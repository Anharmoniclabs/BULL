from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import AuditLedger
from .engine import BulldogEngine
from .models import ActionRequest


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate an AI-agent action through Bulldog policy")
    parser.add_argument("request", help="JSON action request")
    parser.add_argument("--ledger", default=".bulldog/audit.jsonl")
    args = parser.parse_args()

    data = json.loads(Path(args.request).read_text(encoding="utf-8"))
    action = ActionRequest.from_dict(data)
    engine = BulldogEngine(ledger=AuditLedger(args.ledger))
    result = engine.evaluate(action)
    print(json.dumps({
        "decision": result.decision.value,
        "risk": result.risk,
        "hard_block": result.hard_block,
        "reasons": result.reasons,
    }, indent=2))
    return 0 if result.decision.value in {"ALLOW", "SANDBOX"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
