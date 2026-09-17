from __future__ import annotations

import argparse
import json
from pathlib import Path

from .snapshot import create_snapshot
from .workspace_limits import WorkspaceBudget


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("scratch")
    args = parser.parse_args()

    budget = WorkspaceBudget.from_environment()
    snapshot = create_snapshot(
        Path(args.source),
        budget=budget,
        scratch_root=Path(args.scratch),
    )
    print(
        json.dumps(
            {
                "source_root": str(snapshot.source_root),
                "snapshot_root": str(snapshot.snapshot_root),
                "source_hash": snapshot.source_hash,
                "snapshot_hash": snapshot.snapshot_hash,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
