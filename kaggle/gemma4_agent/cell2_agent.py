# CELL 2: autonomous coding agent driving the Gemma 4 server started by CELL 1.
# Needs from CELL 1: `comp` (competition folder). Server: 127.0.0.1:8000.
# For each task in tasks.jsonl: copy its snapshot, let the model explore/edit/test
# with tools, then save the resulting `git diff` as that task's patch.
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json
import os
import re
import shutil
import signal
import subprocess
import tarfile
import time
import traceback
import urllib.error
import urllib.request
import zipfile

MODEL_NAME = "gemma-4-31b-it-qat-w4a16-ct"
BASE_URL = "http://127.0.0.1:8000/v1"
COMP = Path(globals().get("comp") or "/kaggle/input/CHANGE_ME")  # set by CELL 1
RUNS = Path("/kaggle/working/agent_runs")
PREDICTIONS = Path("/kaggle/working/predictions.jsonl")

MAX_STEPS = 40            # tool-call rounds per task
WORKERS = 4               # concurrent tasks; vLLM batches them
CMD_TIMEOUT = 300         # seconds per shell command
TOOL_OUTPUT_CHARS = 6000  # truncate each tool result
COMPACT_AT_TOKENS = 22000 # elide old tool results past this prompt size (32k context)
MAX_TOKENS = 4096         # per model reply
LIMIT_TASKS = None        # e.g. 2 for a smoke test

# tasks.jsonl field names are not known here. The first match wins; override if
# the printed keys below show different names.
ID_KEYS = ("instance_id", "task_id", "id")
PROBLEM_KEYS = ("problem_statement", "prompt", "instruction", "issue", "description", "task")
SNAPSHOT_KEYS = ("snapshot", "snapshot_path", "snapshot_dir", "repo_path")
# Output record field names. Check the swegemma grader for the real schema.
OUT_ID_KEY, OUT_PATCH_KEY = "instance_id", "model_patch"

SYSTEM = """You are an autonomous software engineer working in a repository at /repo \
(your working directory). Fix the task described by the user by editing files.

Work method:
1. Explore: list_dir, search, read_file to find the relevant code. Read before editing.
2. Reproduce when practical: write or run a small test with run_command.
3. Edit with replace_in_file (exact, unique snippet) or write_file for new files.
4. Verify: rerun the relevant tests. Keep changes minimal and in the repository's style.
5. Call finish with a one-paragraph summary when done.

Rules: always act through tool calls; do not ask questions, nobody will answer. \
Do not modify tests to make them pass unless the task asks for it. \
Do not delete the .git directory."""

TOOLS = [
    {"type": "function", "function": {
        "name": "list_dir", "description": "List a directory (relative to repo root).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "default": "."}}, "required": []}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "Read lines of a text file (1-indexed, inclusive).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "start": {"type": "integer", "default": 1},
            "end": {"type": "integer", "default": 200}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search", "description": "Regex search file contents (grep -rnE). Optional path/glob.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"},
            "path": {"type": "string", "default": "."},
            "glob": {"type": "string", "description": "e.g. *.py"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "replace_in_file",
        "description": "Replace one exact, unique occurrence of `old` with `new` in a file.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "old": {"type": "string"}, "new": {"type": "string"}},
            "required": ["path", "old", "new"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "Create or overwrite a whole file.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "run_command",
        "description": f"Run a bash command in the repo root (timeout {CMD_TIMEOUT}s). Use for tests.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "Stop working. Give a short summary of the change.",
        "parameters": {"type": "object", "properties": {
            "summary": {"type": "string"}}, "required": ["summary"]}}},
]


# ---------------------------------------------------------------- tasks

def pick(record, keys, label):
    for k in keys:
        if record.get(k) not in (None, ""):
            return record[k]
    raise KeyError(f"No {label} field among {keys}; record keys: {sorted(record)}")


def load_tasks():
    rows = [json.loads(line) for line in (COMP / "tasks.jsonl").read_text().splitlines() if line.strip()]
    print(f"{len(rows)} tasks. First record keys: {sorted(rows[0])}")
    return rows[:LIMIT_TASKS] if LIMIT_TASKS else rows


def find_snapshot(record, task_id):
    snaps = COMP / "snapshots"
    for k in SNAPSHOT_KEYS:
        if record.get(k):
            p = Path(record[k])
            for cand in (p, COMP / p, snaps / p, snaps / p.name):
                if cand.exists():
                    return cand
    matches = sorted(snaps.glob(f"{task_id}*"))
    if not matches:
        raise FileNotFoundError(f"No snapshot for {task_id} under {snaps}")
    return matches[0]


def materialize(snapshot, dest):
    if dest.exists():
        shutil.rmtree(dest)
    if snapshot.is_dir():
        shutil.copytree(snapshot, dest, symlinks=True)
    elif zipfile.is_zipfile(snapshot):
        with zipfile.ZipFile(snapshot) as z:
            z.extractall(dest)
    elif tarfile.is_tarfile(snapshot):
        with tarfile.open(snapshot) as t:
            t.extractall(dest, filter="data")
    else:
        raise ValueError(f"Unsupported snapshot format: {snapshot}")
    # Unwrap a single top-level folder produced by archives.
    kids = [p for p in dest.iterdir()]
    if len(kids) == 1 and kids[0].is_dir() and not (dest / ".git").exists():
        inner = kids[0]
        for p in inner.iterdir():
            shutil.move(str(p), dest / p.name)
        inner.rmdir()
    # Fresh baseline commit so the final diff is exactly the agent's change.
    git = ["git", "-c", "user.name=agent", "-c", "user.email=agent@local", "-c", "commit.gpgsign=false"]
    if not (dest / ".git").exists():
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
    # Keep test/build byproducts out of the patch (applies to new files only).
    with (dest / ".git/info").joinpath("exclude").open("a") as f:
        f.write("\n__pycache__/\n*.pyc\n.pytest_cache/\n.mypy_cache/\n*.egg-info/\n.tox/\n")
    subprocess.run(git + ["add", "-A", "-f"], cwd=dest, check=True)
    subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "baseline"], cwd=dest, check=True)
    return dest


# ---------------------------------------------------------------- tools

def clip(text, limit=TOOL_OUTPUT_CHARS):
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n... [{len(text) - limit} chars truncated] ...\n{text[-half:]}"


def safe_path(repo, rel):
    p = (repo / (rel or ".")).resolve()
    if p != repo and repo not in p.parents:
        raise ValueError(f"Path escapes repository: {rel}")
    return p


def run_shell(repo, command, timeout=CMD_TIMEOUT):
    proc = subprocess.Popen(["bash", "-c", command], cwd=repo, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True, text=True, errors="replace",
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        out, _ = proc.communicate(timeout=timeout)
        return f"exit={proc.returncode}\n{out}"
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        return f"TIMEOUT after {timeout}s\n{out}"


def call_tool(repo, name, args):
    if name == "list_dir":
        p = safe_path(repo, args.get("path", "."))
        items = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        return "\n".join(x.name + ("/" if x.is_dir() else "") for x in items if x.name != ".git") or "(empty)"
    if name == "read_file":
        p = safe_path(repo, args["path"])
        lines = p.read_text(errors="replace").splitlines()
        start = max(1, int(args.get("start", 1)))
        end = min(len(lines), int(args.get("end", start + 199)))
        body = "\n".join(f"{i:>5} {lines[i-1]}" for i in range(start, end + 1))
        return f"{args['path']} lines {start}-{end} of {len(lines)}\n{body}"
    if name == "search":
        p = safe_path(repo, args.get("path", "."))
        cmd = ["grep", "-rnIE", "--exclude-dir=.git", "-m", "20"]
        if args.get("glob"):
            cmd.append(f"--include={args['glob']}")
        r = subprocess.run(cmd + ["--", args["pattern"], str(p)], cwd=repo,
                           capture_output=True, text=True, errors="replace", timeout=60)
        out = r.stdout.replace(str(repo) + "/", "")
        lines = out.splitlines()
        return "\n".join(lines[:150]) + (f"\n... {len(lines)-150} more" if len(lines) > 150 else "") or "no matches"
    if name == "replace_in_file":
        p = safe_path(repo, args["path"])
        text = p.read_text()
        n = text.count(args["old"])
        if n != 1:
            return f"ERROR: `old` found {n} times; it must match exactly once. Read the file and retry."
        p.write_text(text.replace(args["old"], args["new"], 1))
        return "ok"
    if name == "write_file":
        p = safe_path(repo, args["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(args["content"])
        return f"wrote {len(args['content'])} chars"
    if name == "run_command":
        return run_shell(repo, args["command"])
    return f"ERROR: unknown tool {name}"


# ---------------------------------------------------------------- model

def chat(messages):
    body = {"model": MODEL_NAME, "messages": messages, "tools": TOOLS, "tool_choice": "auto",
            "temperature": 0.0, "max_tokens": MAX_TOKENS}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(f"{BASE_URL}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with opener.open(req, timeout=900) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            detail = exc.read(3000).decode(errors="replace")
            if exc.code == 400:  # usually context overflow; caller compacts and retries
                raise ValueError(detail) from exc
            err = RuntimeError(f"HTTP {exc.code}: {detail}")
        except OSError as exc:
            err = exc
        time.sleep(5 * (attempt + 1))
    raise err


def compact(messages, keep_last=6):
    """Replace old tool results with a stub to stay inside the 32k window."""
    tool_idx = [i for i, m in enumerate(messages) if m["role"] == "tool"]
    for i in tool_idx[:-keep_last]:
        if not messages[i]["content"].startswith("[elided"):
            messages[i]["content"] = "[elided old tool output; re-run the tool if needed]"


# ---------------------------------------------------------------- agent loop

def solve(record):
    task_id = str(pick(record, ID_KEYS, "id"))
    problem = pick(record, PROBLEM_KEYS, "problem")
    work = RUNS / re.sub(r"[^\w.-]", "_", task_id)
    work.mkdir(parents=True, exist_ok=True)
    repo = materialize(find_snapshot(record, task_id), work / "repo").resolve()
    log = (work / "transcript.jsonl").open("w")

    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Task {task_id}:\n\n{problem}\n\n"
                 f"Top-level files:\n{call_tool(repo, 'list_dir', {})}"}]
    status, idle = "max_steps", 0
    for step in range(MAX_STEPS):
        try:
            resp = chat(messages)
        except ValueError:
            compact(messages, keep_last=2)
            resp = chat(messages)
        msg = resp["choices"][0]["message"]
        if resp.get("usage", {}).get("prompt_tokens", 0) > COMPACT_AT_TOKENS:
            compact(messages)
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         **({"tool_calls": calls} if calls else {})})
        log.write(json.dumps({"step": step, "assistant": messages[-1],
                              "reasoning": msg.get("reasoning_content")}) + "\n")
        if not calls:
            idle += 1
            if idle >= 3:
                status = "no_tool_calls"
                break
            messages.append({"role": "user", "content":
                             "Continue by calling a tool. Call finish when the fix is done."})
            continue
        idle = 0
        done = False
        for c in calls:
            name = c["function"]["name"]
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
                result = "finished" if name == "finish" else call_tool(repo, name, args)
            except Exception as exc:
                result = f"ERROR: {type(exc).__name__}: {exc}"
            done |= name == "finish"
            messages.append({"role": "tool", "tool_call_id": c.get("id", ""), "name": name,
                             "content": clip(str(result))})
            log.write(json.dumps({"step": step, "tool": name, "result": clip(str(result), 2000)}) + "\n")
        log.flush()
        if done:
            status = "finished"
            break
    log.close()

    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)  # honours info/exclude
    patch = subprocess.run(["git", "diff", "--cached", "HEAD", "--binary"], cwd=repo,
                           capture_output=True, text=True, errors="replace", check=True).stdout
    (work / "patch.diff").write_text(patch)
    return {OUT_ID_KEY: task_id, OUT_PATCH_KEY: patch, "status": status, "steps": step + 1}


def run_all():
    RUNS.mkdir(parents=True, exist_ok=True)
    tasks = load_tasks()
    done = {}
    if PREDICTIONS.exists():  # resume: skip tasks already solved
        for line in PREDICTIONS.read_text().splitlines():
            r = json.loads(line)
            if r.get("status") != "error":  # errored tasks are retried
                done[r[OUT_ID_KEY]] = r
    todo = [t for t in tasks if str(pick(t, ID_KEYS, "id")) not in done]
    print(f"{len(done)} already done, {len(todo)} to run with {WORKERS} workers.")
    started = time.monotonic()
    with PREDICTIONS.open("a") as out, ThreadPoolExecutor(WORKERS) as pool:
        futures = {pool.submit(solve, t): t for t in todo}
        for f in as_completed(futures):
            tid = str(pick(futures[f], ID_KEYS, "id"))
            try:
                row = f.result()
            except Exception:
                print(f"[{tid}] FAILED\n{traceback.format_exc()[-1500:]}")
                row = {OUT_ID_KEY: tid, OUT_PATCH_KEY: "", "status": "error", "steps": 0}
            out.write(json.dumps(row) + "\n")
            out.flush()
            print(f"[{tid}] {row['status']} in {row['steps']} steps, "
                  f"patch {len(row[OUT_PATCH_KEY])} chars | {time.monotonic()-started:.0f}s")
    print("Predictions:", PREDICTIONS)


if __name__ == "__main__":
    run_all()
