# Gemma 4 coding agent (Kaggle)

- **CELL 1** (yours): starts vLLM with `gemma-4-31b-it-qat-w4a16-ct` on 4×L4, port 8000.
- **CELL 2** (`cell2_agent.py`): runs the repository's `agentharness` package in batch
  mode over `tasks.jsonl` and writes `/kaggle/working/predictions.jsonl`.

Upload the `agentharness/` folder as a Kaggle dataset and attach it (it has no
dependencies beyond the standard library). Start with `LIMIT_TASKS = 2`, read
`/kaggle/working/agent_runs/<task>/evidence/events.jsonl`, and confirm the output
field names match what the `swegemma` grader expects. See `agentharness/README.md`.
