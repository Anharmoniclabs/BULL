import json
import tempfile
import unittest
from pathlib import Path

from bulldog.audit import AuditIntegrityError, AuditLedger
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Provenance


def action(name):
    return ActionRequest(
        actor="audit-cert",
        task="audit test",
        operation="read",
        resource=f"/workspace/{name}.txt",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        provenance=(Provenance.HUMAN,),
        metadata={"session_id": name},
    )


def build(path):
    ledger = AuditLedger(path)
    engine = BulldogEngine(ledger=ledger)

    for name in ("a", "b", "c"):
        engine.evaluate(action(name))

    return ledger


class AuditFailClosedTests(unittest.TestCase):
    def test_valid_head_checkpoint(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            result = ledger.verify()
            self.assertTrue(result.valid)
            self.assertEqual(result.records, 3)
            self.assertTrue(ledger.head_path.exists())

    def test_final_record_deletion_detected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            lines.pop()
            path.write_text("\n".join(lines) + "\n")
            result = ledger.verify()
            self.assertFalse(result.valid)
            self.assertIn("head checkpoint mismatch", result.error)

    def test_refuses_append_after_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            record = json.loads(lines[1])
            record["resource"] = "/workspace/tampered.txt"
            lines[1] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")
            engine = BulldogEngine(ledger=ledger)
            with self.assertRaises(AuditIntegrityError):
                engine.evaluate(action("new"))

    def test_refuses_append_after_truncation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = build(path)
            lines = path.read_text().splitlines()
            path.write_text("\n".join(lines[:-1]) + "\n")
            engine = BulldogEngine(ledger=ledger)
            with self.assertRaises(AuditIntegrityError):
                engine.evaluate(action("after-truncate"))

    def test_clean_append_updates_head(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            ledger = AuditLedger(path)
            engine = BulldogEngine(ledger=ledger)
            engine.evaluate(action("one"))
            first_head = ledger.head_path.read_text().strip()
            engine.evaluate(action("two"))
            second_head = ledger.head_path.read_text().strip()
            self.assertNotEqual(first_head, second_head)
            result = ledger.verify()
            self.assertTrue(result.valid)
            self.assertEqual(result.records, 2)


if __name__ == "__main__":
    unittest.main()
