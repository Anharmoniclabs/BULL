import json
import tempfile
import unittest
from pathlib import Path

from bulldog.audit import AuditLedger
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Provenance


def action(name):
    return ActionRequest(
        actor="audit-integrity-test",
        task="audit integrity",
        operation="read",
        resource=f"/workspace/{name}.txt",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        provenance=(Provenance.HUMAN,),
        metadata={"session_id": f"audit-{name}"},
    )


def build(path):
    ledger = AuditLedger(path)
    engine = BulldogEngine(ledger=ledger)

    for name in ("a", "b", "c"):
        engine.evaluate(action(name))

    return ledger


class AuditIntegrityTests(unittest.TestCase):
    def test_valid_chain_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            result = ledger.verify()
            self.assertTrue(result.valid)
            self.assertEqual(result.records, 3)
            self.assertIsNone(result.error)

    def test_modified_record_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            record = json.loads(lines[1])
            record["resource"] = "/workspace/forged.txt"
            lines[1] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")
            result = ledger.verify()
            self.assertFalse(result.valid)
            self.assertEqual(result.error_index, 1)

    def test_deleted_middle_record_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            del lines[1]
            path.write_text("\n".join(lines) + "\n")
            result = ledger.verify()
            self.assertFalse(result.valid)

    def test_reordered_records_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            lines[1], lines[2] = lines[2], lines[1]
            path.write_text("\n".join(lines) + "\n")
            result = ledger.verify()
            self.assertFalse(result.valid)

    def test_forged_previous_hash_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            record = json.loads(lines[2])
            record["previous_hash"] = "0" * 64
            lines[2] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")
            result = ledger.verify()
            self.assertFalse(result.valid)
            self.assertEqual(result.error_index, 2)

    def test_forged_record_hash_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            record = json.loads(lines[0])
            record["record_hash"] = "f" * 64
            lines[0] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")
            result = ledger.verify()
            self.assertFalse(result.valid)
            self.assertEqual(result.error_index, 0)


if __name__ == "__main__":
    unittest.main()
