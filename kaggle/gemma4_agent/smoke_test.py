# Fake OpenAI server that scripts tool calls, then runs cell2 against a toy task.
import json, sys, threading, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

script = [
    ("search", {"pattern": "def add", "glob": "*.py"}),
    ("read_file", {"path": "calc.py"}),
    ("replace_in_file", {"path": "calc.py", "old": "return a - b", "new": "return a + b"}),
    ("run_command", {"command": "python -c 'import calc; assert calc.add(2,3)==5; print(\"pass\")'"}),
    ("finish", {"summary": "fixed add"}),
]
seen = []

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        seen.append(body["messages"])
        n = sum(1 for m in body["messages"] if m["role"] == "assistant")
        name, args = script[min(n, len(script) - 1)]
        out = {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": f"c{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}}],
            "usage": {"prompt_tokens": 100}}
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)

srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

tmp = Path(tempfile.mkdtemp())
comp = tmp / "comp"; (comp / "snapshots" / "t1").mkdir(parents=True)
(comp / "snapshots" / "t1" / "calc.py").write_text("def add(a, b):\n    return a - b\n")
(comp / "tasks.jsonl").write_text(json.dumps({"instance_id": "t1", "problem_statement": "add() subtracts"}) + "\n")

g = {"__name__": "cell", "comp": str(comp)}
src = Path(sys.argv[1]).read_text()
exec(compile(src, "cell2", "exec"), g)
g["BASE_URL"] = f"http://127.0.0.1:{srv.server_port}/v1"
g["RUNS"] = tmp / "runs"; g["PREDICTIONS"] = tmp / "pred.jsonl"
g["run_all"]()
row = json.loads((tmp / "pred.jsonl").read_text())
print(row["patch" if "patch" in row else "model_patch"])
assert "+    return a + b" in row["model_patch"] and row["status"] == "finished"
print(seen[-1][-2:])
assert "pycache" not in row["model_patch"]; print("SMOKE OK")
