# Gemma 4 coding agent (Kaggle)

- **CELL 1** (yours): starts vLLM with `gemma-4-31b-it-qat-w4a16-ct` on 4×L4, port 8000.
- **CELL 2** (`cell2_agent.py`): paste into the next cell. For each task in
  `tasks.jsonl` it copies the snapshot, runs a tool-calling loop (list/read/search/
  edit/run/finish), and writes the `git diff` to `/kaggle/working/predictions.jsonl`.
  Resumable: rerunning skips finished tasks and retries errored ones.

Before the full run: set `LIMIT_TASKS = 2`, check the printed `tasks.jsonl` keys,
and confirm the output field names (`OUT_ID_KEY`, `OUT_PATCH_KEY`) match what the
`swegemma` grader expects.

Local check without a GPU: `python smoke_test.py cell2_agent.py` (fake model server).
