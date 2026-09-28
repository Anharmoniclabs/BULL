# CELL 2: run the agentharness coding agent against the Gemma 4 server from CELL 1.
# Needs from CELL 1: `comp` (competition folder) and a ready server on 127.0.0.1:8000.
# Attach the `agentharness` folder as a Kaggle dataset (or copy it to /kaggle/working).
import sys
from pathlib import Path

MODEL_NAME = "gemma-4-31b-it-qat-w4a16-ct"
LIMIT_TASKS = 2        # smoke test first; set None for the full run
WORKERS = 4            # concurrent tasks; vLLM batches them
ID_KEY, PATCH_KEY = "instance_id", "model_patch"  # confirm against the swegemma grader

found = sorted(p.parent.parent for root in (Path("/kaggle/working"), Path("/kaggle/input"))
               if root.exists() for p in root.rglob("agentharness/__init__.py"))
if not found:
    raise RuntimeError("Attach the agentharness folder as a dataset or copy it to /kaggle/working.")
sys.path.insert(0, str(found[0]))

from agentharness import AgentConfig, ChatClient
from agentharness.batch import run_batch

client = ChatClient("http://127.0.0.1:8000/v1", MODEL_NAME, max_tokens=4096)
config = AgentConfig(
    max_steps=40, plan_steps=8,     # plans are auto-approved in batch mode
    compact_at_tokens=22000,        # server runs with --max-model-len 32768
    command_timeout=300, time_budget=1800,
    baseline_checks=True,           # set False if the snapshots' test suites are slow
)
run_batch(client, Path(comp), Path("/kaggle/working/predictions.jsonl"),
          Path("/kaggle/working/agent_runs"), workers=WORKERS, config=config,
          limit=LIMIT_TASKS, id_key=ID_KEY, patch_key=PATCH_KEY)
