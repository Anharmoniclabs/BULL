import tempfile
import unittest
from pathlib import Path

from bulldog.audit import AuditLedger
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Decision, Provenance


class BulldogPolicyTests(unittest.TestCase):
    def test_safe_project_write_allowed(self):
        action = ActionRequest(
            actor="alice",
            task="fix css",
            operation="write_file",
            resource="/workspace/src/app.css",
            capability=Capability.FS_WRITE_PROJECT,
            granted_capabilities=frozenset({Capability.FS_WRITE_PROJECT}),
            provenance=(Provenance.HUMAN, Provenance.REPOSITORY),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_ungranted_capability_denied(self):
        action = ActionRequest(
            actor="alice",
            task="fix css",
            operation="connect",
            resource="https://example.invalid",
            capability=Capability.NETWORK_OUTBOUND,
            granted_capabilities=frozenset({Capability.FS_WRITE_PROJECT}),
            provenance=(Provenance.HUMAN,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)

    def test_external_credential_access_denied_even_if_granted(self):
        action = ActionRequest(
            actor="alice",
            task="summarize webpage",
            operation="read_file",
            resource="/home/u/.ssh/id_rsa",
            capability=Capability.CREDENTIAL_READ,
            granted_capabilities=frozenset({Capability.CREDENTIAL_READ}),
            provenance=(Provenance.INTERNET,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)

    def test_child_cannot_escalate_beyond_parent(self):
        action = ActionRequest(
            actor="child-agent",
            task="run tests",
            operation="post",
            resource="https://paste.invalid",
            capability=Capability.NETWORK_POST,
            granted_capabilities=frozenset({Capability.NETWORK_POST}),
            parent_capabilities=frozenset({Capability.PROCESS_EXEC}),
            provenance=(Provenance.EXTERNAL_AGENT,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)

    def test_canary_access_denied(self):
        action = ActionRequest(
            actor="alice",
            task="inspect temp",
            operation="read_file",
            resource="/tmp/.bulldog-canary",
            capability=Capability.FS_READ_HOME,
            granted_capabilities=frozenset({Capability.FS_READ_HOME}),
            provenance=(Provenance.LOCAL_TRUSTED,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)

    def test_audit_chain_written(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = AuditLedger(Path(td) / "audit.jsonl")
            engine = BulldogEngine(ledger=ledger)
            action = ActionRequest(
                actor="alice",
                task="read project",
                operation="read_file",
                resource="/workspace/README.md",
                capability=Capability.FS_READ_PROJECT,
                granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
                provenance=(Provenance.HUMAN,),
            )
            engine.evaluate(action)
            engine.evaluate(action)
            lines = (Path(td) / "audit.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
