#!/usr/bin/env python3
"""Fail when the TLA/Python transition traceability map drifts."""

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from bulldog.trace_model import TRANSITIONS


def main() -> int:
    manifest = json.loads((ROOT / "formal/refinement-map.json").read_text())
    if set(manifest) != {"format", "model", "implementation", "mapping", "claim"}:
        raise ValueError("unexpected refinement map fields")
    tla = (ROOT / manifest["model"]).read_text()
    python = (ROOT / manifest["implementation"]).read_text()
    mapped = set(manifest["mapping"])
    if mapped != set(TRANSITIONS):
        raise ValueError(
            f"Python transition coverage drift: mapped={sorted(mapped)} runtime={sorted(TRANSITIONS)}"
        )
    missing_tla = [
        name
        for name in mapped
        if not re.search(rf"(?m)^{re.escape(name)}(?:\([^)]*\))?\s*==", tla)
    ]
    missing_python = [
        name
        for name in mapped
        if f'if name == "{name}"' not in python
        and f'elif name == "{name}"' not in python
    ]
    if missing_tla or missing_python:
        raise ValueError(
            f"refinement traceability drift: tla={missing_tla} python={missing_python}"
        )
    print(
        json.dumps(
            {
                "status": "PASS",
                "mapped_transitions": len(mapped),
                "claim": manifest["claim"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
