import unittest

from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Decision, Provenance


def request(
    capability,
    resource,
    *,
    provenance=(Provenance.HUMAN,),
    side_effect=False,
):
    return ActionRequest(
        actor="test-agent",
        task="policy test",
        operation="test",
        resource=resource,
        capability=capability,
        granted_capabilities=frozenset(Capability),
        provenance=provenance,
        external_side_effect=side_effect,
        metadata={"session_id": resource},
    )


class HardenedPolicyTests(unittest.TestCase):
    def test_normal_project_read_allowed(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.FS_READ_PROJECT,
                "/workspace/README.md",
            )
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_parent_traversal_denied(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.FS_READ_PROJECT,
                "/workspace/../../etc/passwd",
            )
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)

    def test_encoded_traversal_denied(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.FS_READ_PROJECT,
                "/workspace/%2e%2e/%2e%2e/etc/passwd",
            )
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)

    def test_external_process_execution_escalates(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.PROCESS_EXEC,
                "/bin/bash",
                provenance=(Provenance.INTERNET,),
            )
        )
        self.assertEqual(result.decision, Decision.ESCALATE)
        self.assertGreaterEqual(result.risk, 0.90)

    def test_external_agent_spawn_escalates(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.AGENT_SPAWN,
                "helper-agent",
                provenance=(Provenance.INTERNET,),
            )
        )
        self.assertEqual(result.decision, Decision.ESCALATE)

    def test_external_credentials_still_hard_denied(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.CREDENTIAL_READ,
                "/home/user/.ssh/id_rsa",
                provenance=(Provenance.INTERNET,),
            )
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)

    def test_persistence_write_escalates(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.FS_WRITE_HOME,
                "/home/user/.bashrc",
                side_effect=True,
            )
        )
        self.assertEqual(result.decision, Decision.ESCALATE)

    def test_secret_bearing_outbound_url_escalates(self):
        result = BulldogEngine().evaluate(
            request(
                Capability.NETWORK_OUTBOUND,
                "https://example.invalid/pixel?token=SECRET_VALUE",
                provenance=(Provenance.INTERNET,),
                side_effect=True,
            )
        )
        self.assertEqual(result.decision, Decision.ESCALATE)


if __name__ == "__main__":
    unittest.main()
