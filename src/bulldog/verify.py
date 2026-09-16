from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLedger


def run_pytest(root: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return {
        "passed": proc.returncode == 0,
        "return_code": proc.returncode,
        "output": proc.stdout.strip(),
    }


def verify_audit(path: Path | None) -> dict:
    if path is None:
        return {
            "checked": False,
            "valid": None,
            "records": None,
            "error": None,
        }

    ledger = AuditLedger(path)
    result = ledger.verify()

    return {
        "checked": True,
        "valid": result.valid,
        "records": result.records,
        "error_index": result.error_index,
        "error": result.error,
        "head_hash": result.head_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify BULL runtime integrity."
    )
    parser.add_argument(
        "--audit",
        type=Path,
        default=None,
        help="Optional audit JSONL ledger to verify.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional path to write JSON certification report.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    timestamp = datetime.now(timezone.utc).isoformat()

    report = {
        "product": "BULL",
        "verification_version": 1,
        "timestamp_utc": timestamp,
        "python": sys.version,
        "platform": platform.platform(),
        "root": str(root),
    }

    print("=" * 80)
    print("BULL — SELF VERIFICATION")
    print("=" * 80)

    try:
        from .engine import BulldogEngine
        from .policy import DeterministicPolicy
        from .session_guard import SessionGuard

        _ = BulldogEngine
        _ = DeterministicPolicy
        _ = SessionGuard
        import_ok = True
        import_error = None
    except Exception as exc:
        import_ok = False
        import_error = repr(exc)

    report["import_check"] = {
        "passed": import_ok,
        "error": import_error,
    }

    print()
    print("IMPORT CHECK:", "PASS" if import_ok else "FAIL")
    if import_error:
        print(import_error)

    print()
    print("RUNNING TEST SUITE...")
    tests = run_pytest(root)
    report["tests"] = tests
    print(tests["output"])

    print()
    print("TEST SUITE:", "PASS" if tests["passed"] else "FAIL")

    audit = verify_audit(args.audit)
    report["audit"] = audit

    if audit["checked"]:
        print()
        print("AUDIT LEDGER:", "PASS" if audit["valid"] else "FAIL")
        print("records:", audit["records"])
        if audit["error"]:
            print("error:", audit["error"])
    else:
        print()
        print("AUDIT LEDGER: NOT REQUESTED")

    overall = (
        import_ok
        and tests["passed"]
        and (not audit["checked"] or audit["valid"])
    )
    report["overall_pass"] = overall

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print()
        print("REPORT:", args.json)

    print()
    print("=" * 80)
    print("BULL VERIFICATION: PASS" if overall else "BULL VERIFICATION: FAIL")
    print("=" * 80)

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
