import unittest

from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Decision, Provenance


class BulldogHardeningTests(unittest.TestCase):
    def evaluate(
        self,
        *,
        capability,
        resource,
        provenance=(Provenance.HUMAN,),
        operation="test",
        side_effect=False,
    ):
        action = ActionRequest(
            actor="test-agent",
            task="hardening test",
            operation=operation,
            resource=resource,
            capability=capability,
            granted_capabilities=frozenset(Capability),
            provenance=provenance,
            external_side_effect=side_effect,
            metadata={"session_id": resource},
        )
        return BulldogEngine().evaluate(action)

    def test_normal_project_read_still_allowed(self):
        result = self.evaluate(
            capability=Capability.FS_READ_PROJECT,
            resource="/workspace/README.md",
            operation="read",
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_normal_project_write_still_allowed(self):
        result = self.evaluate(
            capability=Capability.FS_WRITE_PROJECT,
            resource="/workspace/src/app.py",
            operation="write",
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_project_capability_cannot_read_absolute_external_path(self):
        result = self.evaluate(
            capability=Capability.FS_READ_PROJECT,
            resource="/home/user/file.txt",
            operation="read",
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)

    def test_literal_path_traversal_denied(self):
        result = self.evaluate(
            capability=Capability.FS_READ_PROJECT,
            resource="/workspace/../../etc/passwd",
            operation="read",
        )
        self.assertEqual(result.decision, Decision.DENY)

    def test_encoded_path_traversal_denied(self):
        result = self.evaluate(
            capability=Capability.FS_READ_PROJECT,
            resource="/workspace/%2e%2e/%2e%2e/etc/passwd",
            operation="read",
        )
        self.assertEqual(result.decision, Decision.DENY)

    def test_external_prompt_to_process_not_allowed(self):
        result = self.evaluate(
            capability=Capability.PROCESS_EXEC,
            resource="/usr/bin/python3",
            provenance=(Provenance.INTERNET,),
            operation="execute",
        )
        self.assertIn(result.decision, {Decision.ESCALATE, Decision.DENY})

    def test_external_prompt_to_shell_not_allowed(self):
        result = self.evaluate(
            capability=Capability.PROCESS_EXEC,
            resource="/bin/bash",
            provenance=(Provenance.INTERNET,),
            operation="execute",
        )
        self.assertIn(result.decision, {Decision.ESCALATE, Decision.DENY})

    def test_external_credentials_remain_hard_denied(self):
        result = self.evaluate(
            capability=Capability.CREDENTIAL_READ,
            resource="/home/user/.ssh/id_rsa",
            provenance=(Provenance.INTERNET,),
            operation="read",
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)

    def test_external_agent_spawn_not_allowed(self):
        result = self.evaluate(
            capability=Capability.AGENT_SPAWN,
            resource="child-agent",
            provenance=(Provenance.INTERNET,),
            operation="spawn",
        )
        self.assertIn(result.decision, {Decision.ESCALATE, Decision.DENY})

    def test_human_agent_spawn_is_not_zero_risk_allow(self):
        result = self.evaluate(
            capability=Capability.AGENT_SPAWN,
            resource="child-agent",
            provenance=(Provenance.HUMAN,),
            operation="spawn",
        )
        self.assertIn(result.decision, {Decision.SANDBOX, Decision.ESCALATE})

    def test_bashrc_write_escalated(self):
        result = self.evaluate(
            capability=Capability.FS_WRITE_HOME,
            resource="/home/user/.bashrc",
            operation="write",
            side_effect=True,
        )
        self.assertEqual(result.decision, Decision.ESCALATE)

    def test_secret_like_url_escalated(self):
        result = self.evaluate(
            capability=Capability.NETWORK_OUTBOUND,
            resource="https://example.invalid/pixel?token=SECRET_VALUE",
            provenance=(Provenance.INTERNET,),
            operation="connect",
            side_effect=True,
        )
        self.assertEqual(result.decision, Decision.ESCALATE)


if __name__ == "__main__":
    unittest.main()
