"""Managed agent sessions: relay policy, client configuration, export and seccomp.

These run unprivileged. The live boundary (namespaces, account switch, real
Claude Code and Codex binaries) is exercised by tools/qualify_contained_agent.py,
which needs sudo; see docs/MANAGED_AGENT_SESSIONS.md for recorded results.
"""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest

from bulldog import agent_launcher as launcher
from bulldog import inference_relay as relay
from bulldog.client_profiles import PROFILES


@pytest.mark.parametrize(
    "head,host,refused",
    [
        (b"CONNECT api.anthropic.com:443 HTTP/1.1", "api.anthropic.com", False),
        (b"CONNECT API.Anthropic.com.:443 HTTP/1.1", "api.anthropic.com", False),
        (b"CONNECT api.anthropic.com:80 HTTP/1.1", "api.anthropic.com", True),
        (b"CONNECT evil.example.com:443 HTTP/1.1", "evil.example.com", True),
        (b"CONNECT 169.254.169.254:443 HTTP/1.1", "169.254.169.254", True),
        (b"GET http://api.anthropic.com/ HTTP/1.1", "", True),
        (b"CONNECT api.anthropic.com:443 HTTP/2", "", True),
        (b"\xff\xfe", "", True),
    ],
)
def test_relay_admits_only_provider_hosts_on_443(head, host, refused):
    got_host, reason = relay.parse_connect(head, frozenset({"api.anthropic.com"}))
    assert got_host == host
    assert (reason is not None) is refused


def test_relay_tunnels_allowed_host_and_logs_every_decision(tmp_path, monkeypatch):
    upstream_server = socket.socket()
    upstream_server.bind(("127.0.0.1", 0))
    upstream_server.listen(1)

    def echo():
        conn, _ = upstream_server.accept()
        with conn:
            conn.sendall(conn.recv(100).upper())

    threading.Thread(target=echo, daemon=True).start()
    monkeypatch.setattr(
        relay, "_open_upstream",
        lambda host, proxy: socket.create_connection(upstream_server.getsockname()),
    )
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = tmp_path / "relay.sock"
    listener.bind(str(path))
    listener.listen(4)
    log = os.open(tmp_path / "log.jsonl", os.O_WRONLY | os.O_CREAT, 0o600)
    service = relay.InferenceRelay(listener, ["api.anthropic.com"], log)
    threading.Thread(target=service.serve_forever, daemon=True).start()

    def ask(request, payload=b""):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(path))
            s.sendall(request)
            reply = s.recv(64)
            if payload and b" 200 " in reply:
                s.sendall(payload)
                reply += s.recv(64)
            return reply

    assert b" 403 " in ask(b"CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n")
    assert b" 403 " in ask(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\nearly")
    reply = ask(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n", b"hello")
    assert b" 200 " in reply and reply.endswith(b"HELLO")
    listener.close()
    events = [json.loads(x) for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert [e["event"] for e in events][:3] == ["deny", "deny", "allow"]


def test_upstream_proxy_url_is_strict():
    assert relay.parse_proxy_url("http://proxy:3128") == ("proxy", 3128)
    assert relay.parse_proxy_url(None) is None
    for bad in ("https://proxy:443", "http://user:pw@proxy:1", "socks5://proxy:1"):
        with pytest.raises(ValueError):
            relay.parse_proxy_url(bad)


def test_claude_managed_configuration_names_only_bull():
    files = PROFILES["claude"].managed_files("/opt/bull/bin/bull-mcp", "/run/a/agent.sock", 996)
    servers = json.loads(files["claude-code/managed-mcp.json"])["mcpServers"]
    assert list(servers) == ["bull"]
    assert servers["bull"]["args"] == ["--socket", "/run/a/agent.sock", "--server-uid", "996"]
    settings = json.loads(files["claude-code/managed-settings.json"])
    assert settings["allowManagedMcpServersOnly"] is True
    assert settings["disableBypassPermissionsMode"] == "disable"
    assert {"WebFetch", "WebSearch"} <= set(settings["permissions"]["deny"])


def test_codex_managed_configuration_names_only_bull():
    import tomllib

    files = PROFILES["codex"].managed_files("/opt/bull/bin/bull-mcp", "/run/a/agent.sock", 996)
    config = tomllib.loads(files["codex/managed_config.toml"])
    assert list(config["mcp_servers"]) == ["bull"]
    assert config["mcp_servers"]["bull"]["command"] == "/opt/bull/bin/bull-mcp"


def test_readonly_roots_collapse_nested_and_system_paths():
    roots = launcher._collapse(["/usr/lib/node", "/opt/a/b", "/opt/a", "/opt/c"])
    assert roots == [Path("/opt/a"), Path("/opt/c")]


def test_node_script_client_brings_its_interpreter(tmp_path, monkeypatch):
    package = tmp_path / "prefix" / "node_modules" / "tool" / "bin"
    package.mkdir(parents=True)
    script = package / "tool.js"
    script.write_text("#!/usr/bin/env node\n")
    node = tmp_path / "node" / "bin" / "node"
    node.parent.mkdir(parents=True)
    node.write_text("")
    monkeypatch.setattr(launcher.shutil, "which", lambda name: str(node))
    assert launcher.runtime_roots(script) == [tmp_path / "prefix", tmp_path / "node"]


def fake_session(tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "app.py").write_text("print('a')\n")
    (project / "README.md").write_text("readme\n")
    (project / ".env").write_text("SECRET=1\n")
    session = tmp_path / "session"
    session.mkdir()
    excludes = list(launcher.DEFAULT_EXCLUDES)
    (session / "plan.json").write_text(json.dumps({"project": str(project), "excludes": excludes}))
    (session / "manifest.json").write_text(json.dumps(launcher.snapshot(project, excludes)))
    workspace = session / "workspace"
    import shutil

    shutil.copytree(project, workspace, symlinks=True, ignore=shutil.ignore_patterns(".env"))
    return project, session, workspace


def test_secret_files_are_not_in_the_snapshot(tmp_path):
    project, session, workspace = fake_session(tmp_path)
    assert ".env" not in json.loads((session / "manifest.json").read_text())
    assert not (workspace / ".env").exists()


def test_export_applies_ordinary_edits(tmp_path):
    project, session, workspace = fake_session(tmp_path)
    (workspace / "src" / "app.py").write_text("print('b')\n")
    (workspace / "NEW.md").write_text("new\n")
    (workspace / "README.md").unlink()
    kinds = {e["path"]: e["change"] for e in launcher.changes(session)}
    assert kinds == {"src/app.py": "modified", "NEW.md": "added", "README.md": "deleted"}
    patch = launcher.write_patch(session, launcher.changes(session))
    assert "+print('b')" in patch.read_text()
    launcher.apply_export(session)
    assert (project / "src" / "app.py").read_text() == "print('b')\n"
    assert (project / "NEW.md").read_text() == "new\n"
    assert not (project / "README.md").exists()
    assert (project / ".env").read_text() == "SECRET=1\n"


@pytest.mark.parametrize(
    "path", [".github/workflows/ci.yml", ".claude/settings.json", ".mcp.json", "Makefile", "x.pth"]
)
def test_export_refuses_host_executed_paths(tmp_path, path):
    project, session, workspace = fake_session(tmp_path)
    (workspace / path).parent.mkdir(parents=True, exist_ok=True)
    (workspace / path).write_text("hostile\n")
    with pytest.raises(ValueError, match="export refused"):
        launcher.apply_export(session)
    assert not (project / path).exists()
    launcher.apply_export(session, allow_protected=True)
    assert (project / path).exists()


def test_export_ignores_git_internals(tmp_path):
    project, session, workspace = fake_session(tmp_path)
    (workspace / ".git" / "hooks").mkdir(parents=True)
    (workspace / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
    assert launcher.changes(session) == []


def test_export_refuses_symlinks(tmp_path):
    project, session, workspace = fake_session(tmp_path)
    os.symlink("/etc/passwd", workspace / "link")
    entries = launcher.changes(session)
    assert entries == [{"path": "link", "change": "refused", "reason": "not a regular file"}]
    with pytest.raises(ValueError):
        launcher.apply_export(session)


def test_export_refuses_when_project_changed_meanwhile(tmp_path):
    project, session, workspace = fake_session(tmp_path)
    (workspace / "src" / "app.py").write_text("print('agent')\n")
    (project / "src" / "app.py").write_text("print('human')\n")
    with pytest.raises(ValueError, match="changed since the session began"):
        launcher.apply_export(session)
    assert (project / "src" / "app.py").read_text() == "print('human')\n"


def test_export_refuses_project_symlink_redirection(tmp_path):
    project, session, workspace = fake_session(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "docs").mkdir()
    (workspace / "docs" / "x.md").write_text("x\n")
    os.symlink(outside, project / "docs")
    with pytest.raises(ValueError, match="symlink"):
        launcher.apply_export(session)
    assert not (outside / "x.md").exists()


SECCOMP_CHILD = r"""
import ctypes, errno, fcntl, os, sys, threading
sys.path.insert(0, sys.argv[1])
from bulldog import seccomp_policy
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(38, 1, 0, 0, 0)
seccomp_policy.install_agent_seccomp()
out = {}
t = threading.Thread(target=lambda: None); t.start(); t.join(); out["thread"] = "ok"
pid = os.fork()
if pid == 0:
    os._exit(0)
os.waitpid(pid, 0); out["fork"] = "ok"
out["unshare_user"] = libc.syscall(272, 0x10000000) == -1 and ctypes.get_errno()
rc = libc.syscall(56, 0x10000000 | 17, 0, 0, 0, 0)
if rc == 0:
    os._exit(0)
out["clone_user"] = rc == -1 and ctypes.get_errno()
master, slave = os.openpty()
try:
    fcntl.ioctl(slave, 0x5412, b"x"); out["tiocsti"] = 0
except OSError as exc:
    out["tiocsti"] = exc.errno
out["clone3"] = libc.syscall(435, 0, 0) == -1 and ctypes.get_errno()
print(__import__("json").dumps(out))
"""


def test_agent_seccomp_blocks_namespaces_and_tty_injection_keeps_threads():
    import platform

    if platform.machine() != "x86_64":
        pytest.skip("syscall numbers in this probe are x86_64")
    try:
        from bulldog import seccomp_policy  # noqa: F401
    except Exception as exc:
        pytest.skip(f"libseccomp unavailable: {exc}")
    src = str(Path(launcher.__file__).resolve().parents[1])
    done = subprocess.run([sys.executable, "-I", "-c", SECCOMP_CHILD, src],
                          capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    result = json.loads(done.stdout)
    import errno

    assert result["thread"] == "ok" and result["fork"] == "ok"
    assert result["unshare_user"] == errno.EPERM
    assert result["clone_user"] == errno.EPERM
    assert result["tiocsti"] == errno.EPERM
    assert result["clone3"] == errno.ENOSYS


def test_credential_copy_refuses_symlinked_directories(tmp_path):
    home = tmp_path / "agent"
    home.mkdir()
    secret_dir = tmp_path / "root-only"
    secret_dir.mkdir()
    (secret_dir / ".credentials.json").write_text("root secret")
    os.symlink(secret_dir, home / ".claude")
    target = tmp_path / "session" / ".claude" / ".credentials.json"
    copied = launcher.copy_agent_credential(home, ".claude/.credentials.json", target, os.getuid())
    assert copied is False and not target.exists()


def test_credential_copy_takes_the_agents_own_file(tmp_path):
    home = tmp_path / "agent"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / ".credentials.json").write_text("{}")
    target = tmp_path / "session" / ".claude" / ".credentials.json"
    assert launcher.copy_agent_credential(home, ".claude/.credentials.json", target, os.getuid())
    assert target.read_text() == "{}" and (target.stat().st_mode & 0o777) == 0o600
    other = tmp_path / "other.json"
    assert not launcher.copy_agent_credential(home, ".claude/.credentials.json", other, os.getuid() + 1)


def test_git_remote_tokens_are_stripped_from_the_workspace(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://ghp_SECRET@github.com/o/r.git\n'
        '[remote "b"]\n\turl = https://user:pw@example.com/r.git\n'
    )
    launcher._strip_git_credentials(tmp_path)
    text = (tmp_path / ".git" / "config").read_text()
    assert "SECRET" not in text and "pw@" not in text
    assert "https://github.com/o/r.git" in text
