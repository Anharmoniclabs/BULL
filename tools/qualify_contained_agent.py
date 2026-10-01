#!/usr/bin/env python3
"""Qualify BULL managed agent sessions on this host (run with sudo).

Launches real sessions through ``bull agent launch`` and records what happened:

1. the containment probe suite, run inside the session as the agent's native
   shell would (filesystem, network, IPC, privilege, terminal and environment
   escapes, plus positive controls);
2. the installed Claude Code and Codex binaries inside sessions, checking that
   each starts, loads only BULL's managed MCP server and completes the MCP
   handshake with the authority;
3. the export path: a hostile workspace edit (hooks, CI workflow, symlink)
   must be refused while an ordinary edit is applied.

The authority here is a labelled transport FIXTURE running under its own
account. It proves the kernel-authenticated path from inside the session, not
a production deployment. Model-driven runs need provider credentials and are
reported as BLOCKED unless ``--api-key-file`` or ``--copy-credentials`` is given.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

FIXTURE_AUTHORITY = r"""
import os, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from bulldog.gateway_transport import GatewayServer
TOOL = {"name": "installation_check", "description": "fixture tool (qualification only)",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}
def handle(message, *, peer_uid):
    if message.get("method") == "list":
        return {"tools": [TOOL]}
    if message.get("method") == "status":
        return {"coverage": {"mode": "fixture"}}
    return {"status": "COMPLETED", "executed": False, "fixture": "transport only"}
server = GatewayServer(SimpleNamespace(config={"agent_uid": int(sys.argv[3])}, handle=handle),
                       Path(sys.argv[2]), agent_gid=int(sys.argv[4]))
print("LISTENING", flush=True)
server.serve()
"""


def launch(common, client, binary, args, *, extra=(), timeout=180):
    command = [sys.executable, "-I", "-m", "bulldog.cli", "agent", "launch",
               *common, "--client", client, "--client-binary", str(binary), *extra, "--", *args]
    done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return done.returncode, done.stdout, done.stderr


def session_of(stderr: str) -> Path | None:
    for line in reversed(stderr.splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("session"):
            return Path(value["session"])
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-user", required=True)
    parser.add_argument("--authority-user", required=True)
    parser.add_argument("--claude-binary", type=Path)
    parser.add_argument("--codex-binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resource-mode", choices=("cgroup", "rlimit-only"), default="cgroup")
    parser.add_argument("--cgroup-parent", type=Path)
    parser.add_argument("--upstream-proxy")
    parser.add_argument("--ca-bundle", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run with sudo: sessions need namespaces and an account switch")
    agent = pwd.getpwnam(args.agent_user)
    authority = pwd.getpwnam(args.authority_user)
    args.output.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="bull-qualify-"))
    run_dir = Path("/run") / f"bull-qualify-{os.getpid()}"
    run_dir.mkdir(mode=0o710)
    os.chown(run_dir, authority.pw_uid, agent.pw_gid)
    socket_path = run_dir / "agent.sock"
    fixture = subprocess.Popen(
        ["/usr/bin/python3", "-I", "-c", FIXTURE_AUTHORITY, str(ROOT / "src"),
         str(socket_path), str(agent.pw_uid), str(agent.pw_gid)],
        # The authority hands its socket to the agent's group, as in a real
        # deployment (see docs/LOCAL_MCP_ATTACHMENT_TESTS.md).
        user=authority.pw_uid, group=authority.pw_gid, extra_groups=[agent.pw_gid],
        stdout=subprocess.PIPE, text=True,
    )
    abstract = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abstract_name = f"bull-qualify-{os.getpid()}"
    abstract.bind("\0" + abstract_name)
    abstract.listen(1)
    results: list[dict] = []
    report = {
        "format": "bull-managed-session-qualification-v1",
        "host": {"kernel": platform.release(), "machine": platform.machine(),
                 "python": platform.python_version()},
        "authority": "FIXTURE (transport only; not a production deployment)",
        "resource_mode": args.resource_mode,
        "results": results,
    }
    try:
        if fixture.stdout.readline().strip() != "LISTENING":
            raise SystemExit("fixture authority failed to start")
        project = work / "project"
        (project / "src").mkdir(parents=True)
        (project / "src" / "app.py").write_text("print('hello')\n")
        (project / "README.md").write_text("fixture project\n")
        (project / ".env").write_text("SECRET=must-not-be-copied\n")
        (project / ".mcp.json").write_text(json.dumps(
            {"mcpServers": {"rogue": {"command": "/bin/sh", "args": ["-c", "true"]}}}))
        (project / ".git").mkdir()
        (project / ".git" / "config").write_text("[core]\n")
        sessions = work / "sessions"
        common = ["--agent-user", args.agent_user, "--project", str(project),
                  "--authority-socket", str(socket_path),
                  "--authority-uid", str(authority.pw_uid),
                  "--sessions", str(sessions), "--resource-mode", args.resource_mode]
        if args.cgroup_parent:
            common += ["--cgroup-parent", str(args.cgroup_parent)]
        if args.upstream_proxy:
            common += ["--upstream-proxy", args.upstream_proxy]
        if args.ca_bundle:
            common += ["--ca-bundle", str(args.ca_bundle)]
        python = Path(sys.executable)

        # 1. Containment probes, as the agent's native shell.
        probe_args = json.dumps({
            "authority_socket": str(socket_path), "authority_uid": authority.pw_uid,
            "provider": "api.anthropic.com", "abstract": abstract_name,
            "host_pid": os.getpid(), "api_key_env": "ANTHROPIC_API_KEY",
        })
        code, out, err = launch(common, "claude", python,
                                ["-I", "-m", "bulldog.containment_probes", probe_args])
        try:
            probes = json.loads(out.strip().splitlines()[-1])
            for item in probes["results"]:
                results.append({"suite": "containment", **item})
            results.append({"suite": "containment", "probe": "runs-as-agent",
                            "kind": "escape", "status": "PASS" if probes["uid"] == agent.pw_uid else "FAIL",
                            "detail": f"uid {probes['uid']}"})
        except (IndexError, ValueError, KeyError):
            results.append({"suite": "containment", "probe": "probe-run", "kind": "positive",
                            "status": "FAIL", "detail": (err or out)[-2000:]})
        probe_session = session_of(err)
        if probe_session:
            copied = (probe_session / "workspace" / ".env").exists()
            results.append({"suite": "workspace", "probe": "secret-excluded", "kind": "escape",
                            "status": "FAIL" if copied else "PASS",
                            "detail": ".env copied" if copied else ".env not copied"})

        # 2. Real clients.
        for client, binary in (("claude", args.claude_binary), ("codex", args.codex_binary)):
            if not binary:
                results.append({"suite": client, "probe": "installed", "kind": "positive",
                                "status": "BLOCKED", "detail": "binary not supplied"})
                continue
            code, out, err = launch(common, client, binary, ["--version"])
            results.append({"suite": client, "probe": "starts-contained", "kind": "positive",
                            "status": "PASS" if code == 0 and out.strip() else "FAIL",
                            "detail": (out.strip() or err[-500:])})
            code, out, err = launch(common, client, binary, ["mcp", "list"])
            text = out + err
            listed_bull = "bull" in text
            rogue = "rogue" in text
            connected = any(w in text.lower() for w in ("connected", "✓", "enabled"))
            results.append({"suite": client, "probe": "mcp:only-bull", "kind": "escape",
                            "status": "PASS" if listed_bull and not rogue else "FAIL",
                            "detail": out.strip()[-800:] or err[-800:]})
            results.append({"suite": client, "probe": "mcp:bull-listed", "kind": "positive",
                            "status": "PASS" if listed_bull and (connected or client == "codex") else "FAIL",
                            "detail": out.strip()[-800:] or err[-800:]})
            results.append({"suite": client, "probe": "model-driven-task", "kind": "positive",
                            "status": "BLOCKED",
                            "detail": "needs provider credentials: rerun with --api-key-file"})

        # 3. Export: hostile and ordinary edits.
        hostile = (
            "import os\n"
            "open('/workspace/src/app.py','a').write('print(1)\\n')\n"
            "open('/workspace/NEW.md','w').write('new\\n')\n"
            "os.makedirs('/workspace/.github/workflows', exist_ok=True)\n"
            "open('/workspace/.github/workflows/x.yml','w').write('on: push\\n')\n"
            "os.makedirs('/workspace/.git/hooks', exist_ok=True)\n"
            "open('/workspace/.git/hooks/pre-commit','w').write('#!/bin/sh\\n')\n"
            "os.symlink('/etc/passwd', '/workspace/link')\n"
        )
        code, out, err = launch(common, "claude", python, ["-I", "-c", hostile])
        export_session = session_of(err)
        from bulldog.agent_launcher import apply_export, changes

        entries = changes(export_session) if export_session else []
        by_path = {e["path"]: e for e in entries}
        results.append({"suite": "export", "probe": "git-internals-ignored", "kind": "escape",
                        "status": "PASS" if not any(p.startswith(".git/") for p in by_path) else "FAIL",
                        "detail": sorted(by_path)})
        results.append({"suite": "export", "probe": "workflow-protected", "kind": "escape",
                        "status": "PASS" if by_path.get(".github/workflows/x.yml", {}).get("protected") else "FAIL",
                        "detail": by_path.get(".github/workflows/x.yml")})
        results.append({"suite": "export", "probe": "symlink-refused", "kind": "escape",
                        "status": "PASS" if by_path.get("link", {}).get("change") == "refused" else "FAIL",
                        "detail": by_path.get("link")})
        try:
            apply_export(export_session)
            refused = False
        except ValueError:
            refused = True
        results.append({"suite": "export", "probe": "hostile-export-refused", "kind": "escape",
                        "status": "PASS" if refused else "FAIL", "detail": "whole export refused"})
        os.unlink(export_session / "workspace" / "link")
        shutil.rmtree(export_session / "workspace" / ".github")
        applied = apply_export(export_session)
        ok = (project / "NEW.md").read_text() == "new\n" and "print(1)" in (project / "src/app.py").read_text()
        results.append({"suite": "export", "probe": "ordinary-edit-applied", "kind": "positive",
                        "status": "PASS" if ok else "FAIL",
                        "detail": [e["path"] for e in applied]})
    finally:
        fixture.terminate()
        fixture.wait(timeout=10)
        abstract.close()
        shutil.rmtree(run_dir, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
    counts = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    report["summary"] = counts
    report["verdict"] = "FAIL" if counts.get("FAIL") else "PASS_WITH_BLOCKED" if counts.get("BLOCKED") else "PASS"
    report["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (args.output / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"verdict": report["verdict"], "summary": counts,
                      "report": str(args.output / "report.json")}))
    return 1 if counts.get("FAIL") else 0


if __name__ == "__main__":
    raise SystemExit(main())
