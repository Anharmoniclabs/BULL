"""Build BULL's read-only engineering publication from tracked source files.

No browser policy engine, secret input, model connector or VM is started here.
Only repository text/metadata is published; no local untracked files are indexed.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
REPO = "https://github.com/Anharmoniclabs/BULL"
GROUPS = [
    ("Permission and identity", "The request model, canonicalization, deterministic policy and session/domain history. Model identity is not accepted as authority merely because a proposal asserts it.", "models.py canonicalizer.py policy.py engine.py session_guard.py security_domain.py"),
    ("Dispatch and production", "Production profile assembly, trusted-state validation, exact command binding and dispatcher-issued runtime permits. Development entrypoints are a separate, weaker integration path.", "dispatcher.py profiles.py production_gate.py policy_bundle.py integrity.py runtime.py approval.py approval_crypto.py approval_cli.py"),
    ("Hardware approval", "Custom P-256 request binding and durable ApprovalGate consumption, with diagnostic-only USB tooling. Host conformance tests do not establish secure-element provisioning, physical presence or complete hardware integration.", "hardware_approval/__init__.py hardware_approval/protocol.py hardware_approval/provider.py hardware_approval/verifier.py hardware_approval/diagnostic.py hardware_approval/cli.py"),
    ("File admission", "Bounded manifests, secure path opens, private snapshot construction, isolated worker support and required malware scanning before the admitted copy is used.", "filesystem_manifest.py secure_fs.py workspace_limits.py snapshot.py snapshot_worker.py malware_scanner.py"),
    ("Linux enforcement", "The namespace backend and trusted shell bootstrap install the active restrictions. Compatibility and cross-platform helper contracts do not imply an available certified backend on every platform.", "namespace_sandbox.py _namespace_launcher.sh seccomp_policy.py landlock_policy.py resource_limits.py cgroup_scope.py container_hardening.py linux_sandbox.py sandbox_backends.py host_certify.py"),
    ("Broker components", "Secret retrieval and outbound requests have their own authorization and transport controls. Alternate hardening helpers are documented as components, not assumed to be wired into every execution route.", "secret_broker.py egress_proxy.py socket_hardening.py broker_hardening.py pinned_egress.py"),
    ("Audit and state models", "Local hash-chained records, authenticated checkpoint transports, the durable anchor service, and runtime trace abstractions. The guest relay requires a verified acknowledgment; production operators supply their own collector and authority.", "audit.py audit_transport.py anchor_service.py trace_model.py trace_runtime.py"),
    ("Assurance and release evidence", "Machine-readable BULL control definitions, source/deployment/release status evaluation, and release-evidence integrity helpers. These report BULL evidence and never substitute for an external certification or legal assessment.", "assurance.py release_evidence.py data/assurance_controls.json"),
    ("MicroVM host and guest", "Hardware-only QEMU/KVM launch, admitted ext4 images, functional guest preflight, trusted one-shot production supervision and bounded authenticated control. Historical runs used a disposable TLS collector; candidate 603365e has five-case KVM and external host/guest receipt evidence.", "microvm.py microvm_image.py guest_preflight.py guest_engine.py microvm_protocol.py"),
    ("Multi-agent orchestration", "Development orchestration with host callables, structured messages and synthetic canary inspection. It does not automatically route effects through ProductionDispatcher; absence of a canary finding is not proof of safety.", "multiagent/__init__.py multiagent/agents.py multiagent/bus.py multiagent/contracts.py multiagent/honeytoken.py multiagent/system.py"),
    ("Adversary observation components", "Contracts, fingerprints, lure, registry and quarantine components for the adversary-capture subsystem. This source inventory is not evidence of deployment, complete containment or independent certification.", "adversary/__init__.py adversary/contracts.py adversary/fingerprint.py adversary/lure.py adversary/quarantine.py adversary/registry.py adversary/system.py"),
    ("Public API and auxiliaries", "Package exports and verification commands, plus advisory/sentinel interfaces. Heuristic agent detection is not proof of identity or a replacement for the production boundary.", "__init__.py cli.py bootstrap.py verify.py advisory.py agent_sentinel.py control_plane.py console_static/index.html console_static/styles.css console_static/app.js console_static/bull-mark.svg"),
]
REMOVED = (
    "site/app.js", "site/story.js", "site/model-connector.js",
    "site/model-connector.css", "site/control-center.html", "site/runtime",
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def tracked_paths() -> list[str]:
    raw = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"])
    return sorted(p.decode("utf-8") for p in raw.split(b"\0") if p)


def source_link(path: str, commit: str, line: int | None = None) -> str:
    suffix = f"#L{line}" if line is not None else ""
    return f"{REPO}/blob/{commit}/{quote(path, safe='/')}" + suffix


def describe(path: str) -> str:
    if path.startswith("src/bulldog/"):
        relative = path.removeprefix("src/bulldog/")
        for title, _, names in GROUPS:
            if relative in names.split():
                return title
        return "Runtime source"
    if path.startswith("microvm/guest/"):
        return "Guest bootstrap or explicit engine adapter example"
    if path.startswith("microvm/"):
        return "MicroVM launch, image, audit or deployment documentation"
    if path.startswith("tests/"):
        return "Regression fixture or test; not deployment certification"
    if path.startswith("formal/"):
        return "Bounded state-machine model or model-checking configuration"
    if path.startswith(".github/workflows/"):
        return "CI or publishing workflow"
    if path.startswith("docs/") or path.endswith(".md"):
        return "Project documentation"
    if path.startswith("site/"):
        return "Read-only website asset or documentation template"
    if path.startswith("tools/"):
        return "Documentation build tooling"
    if path.startswith("certification/"):
        return "Recorded verification artifact; read its own scope and revision"
    if path.startswith("examples/"):
        return "Example request data"
    return "Repository configuration, licensing or auxiliary file"


def symbols_for(path: Path) -> tuple[list[dict], list[str]]:
    if path.suffix != ".py":
        return [], []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    symbols, imports = [], set()
    def visit(nodes, prefix=""):
        for node in nodes:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + node.name
                symbols.append({"name": name, "line": node.lineno,
                                "kind": "class" if isinstance(node, ast.ClassDef) else "function"})
                if isinstance(node, ast.ClassDef):
                    visit(node.body, name + ".")
    visit(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.add("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return symbols, sorted(imports)


def inventory(commit: str) -> list[dict]:
    rows = []
    for name in tracked_paths():
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        symbols, imports = symbols_for(path)
        rows.append({"path": name, "purpose": describe(name), "bytes": len(data),
                     "sha256": hashlib.sha256(data).hexdigest(),
                     "source_url": source_link(name, commit),
                     "symbols": symbols, "imports": imports})
    return rows


def page(title: str, body: str) -> str:
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">"
            f"<title>{html.escape(title)} — BULL</title>"
            "<link rel=\"icon\" href=\"./assets/brand/bull-favicon.svg\">"
            "<link rel=\"stylesheet\" href=\"./styles.css\"></head><body>"
            "<header class=\"masthead\"><a href=\"./index.html\">"
            "<img class=\"logo\" src=\"./assets/brand/bull-primary.svg\" width=\"215\" height=\"78\" alt=\"BULL\"></a>"
            "<a href=\"./index.html#architecture\">Architecture and evidence</a></header><main>"
            + body + "</main><footer><p>BULL · Blocking Unauthorized Logic Loopholes</p></footer></body></html>\n")


def groups_html(commit: str, rows: list[dict]) -> str:
    # Use package-relative paths, not basenames: nested packages legitimately
    # share names such as __init__.py, contracts.py and system.py.
    actual = {row["path"].removeprefix("src/bulldog/") for row in rows
              if row["path"].startswith("src/bulldog/")}
    entries = [name for _, _, names in GROUPS for name in names.split()]
    documented = set(entries)
    if len(entries) != len(documented):
        raise ValueError("module-map drift: duplicate documented path")
    if actual != documented:
        raise ValueError(f"module-map drift: undocumented={actual-documented}; absent={documented-actual}")
    result = []
    for title, description, names in GROUPS:
        links = " ".join(f'<a href="{source_link("src/bulldog/"+name, commit)}">{html.escape(name)}</a>' for name in names.split())
        result.append(f'<article class="module-group"><h3>{html.escape(title)}</h3><div><p>{html.escape(description)}</p><div class="module-files">{links}</div></div></article>')
    return "\n".join(result)


def inventory_html(commit: str, rows: list[dict]) -> str:
    body = (f'<section class="intro"><p class="eyebrow">Complete tracked-file inventory</p><h1>Source, by file.</h1>'
            f'<p class="lede">{len(rows)} tracked regular files at <code>{commit}</code>. '
            'Generated from Git, Python syntax trees and SHA-256 hashes—not from filenames guessed by the webpage.</p>'
            '<p>Python entries include top-level functions, classes and class methods with source-line links, plus syntactic imports. '
            'An import is not proof that a component is active on a production path. Local untracked files are not published.</p>'
            '<p><a href="./data/repository.json">Complete machine-readable inventory with content hashes</a></p></section>'
            '<div class="table-wrap"><table class="inventory"><caption>Every tracked file</caption>'
            '<thead><tr><th>File and source</th><th>Role</th><th>Symbols and imports</th></tr></thead><tbody>')
    for row in rows:
        symbols = "<br>".join(f'<a href="{source_link(row["path"],commit,s["line"])}">{html.escape(s["name"])}</a> <small>L{s["line"]}</small>' for s in row["symbols"])
        imports = html.escape(", ".join(row["imports"]))
        description = symbols or "No Python API symbols."
        if imports:
            description += '<p class="caption">Imports: <code>' + imports + '</code></p>'
        body += (f'<tr><td><a href="{row["source_url"]}"><code>{html.escape(row["path"])}</code></a>'
                 f'<p class="caption">{row["bytes"]:,} bytes · SHA-256 <code>{row["sha256"][:16]}…</code></p></td>'
                 f'<td>{html.escape(row["purpose"])}</td><td>{description}</td></tr>')
    return page("Repository implementation inventory", body + "</tbody></table></div>")


def build(output: Path, commit: str | None = None) -> Path:
    output = output.resolve()
    if output == ROOT or ROOT.is_relative_to(output) or (output.is_relative_to(ROOT) and output != ROOT / "_site"):
        raise ValueError("output must be _site or an independent directory, never repository source")
    if output.exists() and any(output.iterdir()):
        if not (output / ".bull-docs-build").is_file():
            raise ValueError("refusing to overwrite an unrelated nonempty output directory")
        shutil.rmtree(output)
    commit = commit or git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("a full 40-character source commit is required")
    for name in REMOVED:
        if (ROOT / name).exists():
            raise ValueError("removed browser interface returned: " + name)
    rows = inventory(commit)
    shutil.copytree(ROOT / "site", output, dirs_exist_ok=True)
    text = (output / "index.html").read_text(encoding="utf-8")
    names = {row["path"] for row in rows}
    def resolve(match):
        name = match.group(1)
        if name not in names:
            raise ValueError("source link does not exist in tracked inventory: " + name)
        return f'<a href="{source_link(name,commit)}"'
    text = re.sub(r'<a data-code="([^"]+)"(?: href="[^"]*")?', resolve, text)
    if "<!-- REPOSITORY_GROUPS -->" not in text:
        raise ValueError("repository group insertion point is missing")
    text = text.replace("<!-- REPOSITORY_GROUPS -->", groups_html(commit, rows))
    (output / "index.html").write_text(text, encoding="utf-8")
    (output / "repository.html").write_text(inventory_html(commit, rows), encoding="utf-8")
    (output / "data").mkdir(exist_ok=True)
    (output / "data/repository.json").write_text(json.dumps({"repository": "Anharmoniclabs/BULL", "commit":commit, "files":rows}, indent=2) + "\n")
    (output / ".nojekyll").touch()
    (output / ".bull-docs-build").write_text(commit + "\n")
    print(f"Built {output}: {len(rows)} tracked files indexed; no public testing interface")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "_site")
    parser.add_argument("--commit")
    args = parser.parse_args()
    build(args.output, args.commit)
