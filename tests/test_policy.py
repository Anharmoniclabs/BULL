import tempfile
import unittest
from pathlib import Path

from bulldog.audit import AuditLedger
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Decision, Provenance


def verified_action(**overrides):
    data = dict(
        actor="alice",
        task="test",
        operation="read_file",
        resource="/workspace/README.md",
        resolved_resource="/workspace/README.md",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        provenance=(Provenance.HUMAN,),
        security_context_verified=True,
    )
    data.update(overrides)
    return ActionRequest(**data)


class BulldogPolicyTests(unittest.TestCase):
    def test_safe_project_write_allowed(self):
        action = verified_action(
            task="fix css",
            operation="write_file",
            resource="/workspace/src/app.css",
            resolved_resource="/workspace/src/app.css",
            capability=Capability.FS_WRITE_PROJECT,
            granted_capabilities=frozenset({Capability.FS_WRITE_PROJECT}),
            provenance=(Provenance.HUMAN, Provenance.REPOSITORY),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertFalse(result.flags)

    def test_unverified_security_context_fails_closed(self):
        action = ActionRequest(
            actor="model-claimed-human",
            task="read project",
            operation="read_file",
            resource="/workspace/README.md",
            resolved_resource="/workspace/README.md",
            capability=Capability.FS_READ_PROJECT,
            granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
            provenance=(Provenance.HUMAN,),
            security_context_verified=False,
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)
        self.assertIn("UNVERIFIED_SECURITY_CONTEXT", result.plain_english_flags[0])

    def test_ungranted_capability_denied(self):
        action = verified_action(
            operation="connect",
            resource="https://example.invalid",
            resolved_resource=None,
            capability=Capability.NETWORK_OUTBOUND,
            granted_capabilities=frozenset({Capability.FS_WRITE_PROJECT}),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)
        self.assertTrue(any("CAPABILITY_NOT_GRANTED" in x for x in result.plain_english_flags))

    def test_project_capability_cannot_escape_project_root(self):
        action = verified_action(
            resource="/workspace/link",
            resolved_resource="/etc/passwd",
            capability=Capability.FS_READ_PROJECT,
            granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(any("RESOURCE_CAPABILITY_MISMATCH" in x for x in result.plain_english_flags))

    def test_filesystem_action_without_resolved_path_denied(self):
        action = verified_action(resolved_resource=None)
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(any("RESOURCE_NOT_RESOLVED" in x for x in result.plain_english_flags))

    def test_external_credential_access_denied_even_if_granted(self):
        action = verified_action(
            task="summarize webpage",
            resource="/home/u/.ssh/id_rsa",
            resolved_resource="/home/u/.ssh/id_rsa",
            capability=Capability.CREDENTIAL_READ,
            granted_capabilities=frozenset({Capability.CREDENTIAL_READ}),
            provenance=(Provenance.INTERNET,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(any("UNTRUSTED_CREDENTIAL_ACCESS" in x for x in result.plain_english_flags))

    def test_external_process_execution_escalates(self):
        action = verified_action(
            task="run instructions from webpage",
            operation="exec",
            resource="/bin/sh",
            resolved_resource=None,
            capability=Capability.PROCESS_EXEC,
            granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
            provenance=(Provenance.INTERNET,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.ESCALATE)
        self.assertGreaterEqual(result.risk, 0.90)
        self.assertTrue(any("UNTRUSTED_TO_EXECUTION" in x for x in result.plain_english_flags))

    def test_external_network_outbound_is_contained(self):
        action = verified_action(
            task="fetch remote data",
            operation="connect",
            resource="https://example.invalid",
            resolved_resource=None,
            capability=Capability.NETWORK_OUTBOUND,
            granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
            provenance=(Provenance.INTERNET,),
            external_side_effect=True,
        )
        result = BulldogEngine().evaluate(action)
        self.assertIn(result.decision, {Decision.SANDBOX, Decision.ESCALATE})
        self.assertGreaterEqual(result.risk, 0.75)
        self.assertTrue(any("EXTERNAL_DATA_TRANSFER" in x for x in result.plain_english_flags))

    def test_secret_taint_cannot_leave_over_network(self):
        action = verified_action(
            task="send transformed result",
            operation="connect",
            resource="https://example.invalid/collect",
            resolved_resource=None,
            capability=Capability.NETWORK_OUTBOUND,
            granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
            provenance=(Provenance.LOCAL_TRUSTED,),
            external_side_effect=True,
            secret_taint=True,
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)
        self.assertTrue(any("POSSIBLE_SECRET_EXFILTRATION" in x for x in result.plain_english_flags))

    def test_secret_taint_cannot_leave_via_agent_message(self):
        action = verified_action(
            task="delegate transformed state",
            operation="message",
            resource="agent://child",
            resolved_resource=None,
            capability=Capability.AGENT_MESSAGE,
            granted_capabilities=frozenset({Capability.AGENT_MESSAGE}),
            provenance=(Provenance.LOCAL_TRUSTED,),
            external_side_effect=True,
            secret_taint=True,
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(any("POSSIBLE_SECRET_EXFILTRATION" in x for x in result.plain_english_flags))

    def test_child_cannot_escalate_beyond_parent(self):
        action = verified_action(
            actor="child-agent",
            task="run tests",
            operation="post",
            resource="https://paste.invalid",
            resolved_resource=None,
            capability=Capability.NETWORK_POST,
            granted_capabilities=frozenset({Capability.NETWORK_POST}),
            parent_capabilities=frozenset({Capability.PROCESS_EXEC}),
            provenance=(Provenance.EXTERNAL_AGENT,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(any("CHILD_AUTHORITY_ESCALATION" in x for x in result.plain_english_flags))

    def test_canary_access_denied_using_resolved_path(self):
        action = verified_action(
            task="inspect temp",
            resource="/workspace/innocent-link",
            resolved_resource="/tmp/.bulldog-canary",
            capability=Capability.FS_READ_HOME,
            granted_capabilities=frozenset({Capability.FS_READ_HOME}),
            provenance=(Provenance.LOCAL_TRUSTED,),
        )
        result = BulldogEngine().evaluate(action)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(any("CANARY_TOUCHED" in x for x in result.plain_english_flags))

    def test_audit_chain_records_plain_english_flags(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = AuditLedger(Path(td) / "audit.jsonl")
            engine = BulldogEngine(ledger=ledger)
            action = verified_action()
            engine.evaluate(action)
            engine.evaluate(action)
            lines = (Path(td) / "audit.jsonl").read_text().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn('"flags": []', lines[0])


if __name__ == "__main__":
    unittest.main()
