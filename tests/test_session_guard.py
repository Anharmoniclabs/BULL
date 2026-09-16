import unittest

from bulldog.engine import BulldogEngine
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Provenance,
)


def action(
    task,
    capability,
    resource,
    *,
    actor="session-agent",
    session="test-session",
):
    return ActionRequest(
        actor=actor,
        task=task,
        operation="test",
        resource=resource,
        capability=capability,
        granted_capabilities=frozenset(Capability),
        provenance=(Provenance.HUMAN,),
        metadata={"session_id": session},
    )


class SessionEnforcementTests(unittest.TestCase):

    def test_normal_project_sequence_stays_allowed(self):
        engine = BulldogEngine()

        r1 = engine.evaluate(
            action(
                "inspect project",
                Capability.FS_READ_PROJECT,
                "/workspace/README.md",
            )
        )

        r2 = engine.evaluate(
            action(
                "edit project",
                Capability.FS_WRITE_PROJECT,
                "/workspace/src/app.py",
            )
        )

        self.assertEqual(r1.decision, Decision.ALLOW)
        self.assertEqual(r2.decision, Decision.ALLOW)

    def test_goal_drift_to_credentials_escalates(self):
        engine = BulldogEngine()

        engine.evaluate(
            action(
                "inspect repository",
                Capability.FS_READ_PROJECT,
                "/workspace/src/main.py",
            )
        )

        result = engine.evaluate(
            action(
                "inspect environment",
                Capability.CREDENTIAL_READ,
                "/home/user/.ssh/id_rsa",
            )
        )

        self.assertEqual(result.decision, Decision.ESCALATE)
        self.assertGreaterEqual(result.risk, 0.90)

        joined = " ".join(result.reasons)

        self.assertIn("GOAL_DRIFT", joined)
        self.assertIn("AUTHORITY_SHIFT", joined)

    def test_alternate_path_after_restriction_escalates(self):
        engine = BulldogEngine()

        first = engine.evaluate(
            action(
                "inspect credentials",
                Capability.CREDENTIAL_READ,
                "/home/user/credentials.txt",
            )
        )

        self.assertIn(
            first.decision,
            {
                Decision.SANDBOX,
                Decision.ESCALATE,
                Decision.DENY,
            },
        )

        second = engine.evaluate(
            action(
                "try alternate execution path",
                Capability.PROCESS_EXEC,
                "/bin/echo",
            )
        )

        self.assertEqual(second.decision, Decision.ESCALATE)

        self.assertTrue(
            any(
                "ALTERNATE_PATH_AFTER_RESTRICTION" in reason
                for reason in second.reasons
            )
        )

    def test_tool_shopping_escalates(self):
        engine = BulldogEngine()

        engine.evaluate(
            action(
                "step one",
                Capability.FS_READ_PROJECT,
                "/workspace/a",
            )
        )

        engine.evaluate(
            action(
                "step two",
                Capability.NETWORK_OUTBOUND,
                "https://example.invalid",
            )
        )

        engine.evaluate(
            action(
                "step three",
                Capability.AGENT_SPAWN,
                "helper-agent",
            )
        )

        result = engine.evaluate(
            action(
                "step four",
                Capability.AGENT_MESSAGE,
                "external-helper",
            )
        )

        self.assertEqual(result.decision, Decision.ESCALATE)

        self.assertTrue(
            any(
                "TOOL_SHOPPING" in reason
                for reason in result.reasons
            )
        )

    def test_session_id_switch_preserves_security_history(self):
        """
        session_id is descriptive metadata only.

        Changing an agent-controlled session label must NOT reset
        behavioral security history.
        """

        engine = BulldogEngine()

        engine.evaluate(
            action(
                "project work",
                Capability.FS_READ_PROJECT,
                "/workspace/a",
                session="A",
            )
        )

        result = engine.evaluate(
            action(
                "credential operation",
                Capability.CREDENTIAL_READ,
                "/home/user/credential.txt",
                session="B",
            )
        )

        self.assertTrue(
            any(
                "GOAL_DRIFT" in reason
                for reason in result.reasons
            )
        )

        self.assertIn(
            result.decision,
            {
                Decision.ESCALATE,
                Decision.DENY,
            },
        )


    def test_different_actors_are_isolated(self):
        """
        Distinct actor identities retain independent security history.
        """

        engine = BulldogEngine()

        first = ActionRequest(
            actor="agent-A",
            task="project work",
            operation="test",
            resource="/workspace/a",
            capability=Capability.FS_READ_PROJECT,
            granted_capabilities=frozenset(
                {
                    Capability.FS_READ_PROJECT,
                    Capability.CREDENTIAL_READ,
                }
            ),
            provenance=(Provenance.HUMAN,),
            metadata={
                "session_id": "A",
            },
        )

        second = ActionRequest(
            actor="agent-B",
            task="credential operation",
            operation="test",
            resource="/home/user/credential.txt",
            capability=Capability.CREDENTIAL_READ,
            granted_capabilities=frozenset(
                {
                    Capability.FS_READ_PROJECT,
                    Capability.CREDENTIAL_READ,
                }
            ),
            provenance=(Provenance.HUMAN,),
            metadata={
                "session_id": "B",
            },
        )

        engine.evaluate(first)

        result = engine.evaluate(second)

        self.assertFalse(
            any(
                "GOAL_DRIFT" in reason
                for reason in result.reasons
            )
        )


    def test_trusted_security_contexts_are_isolated(self):
        """
        A trusted host can explicitly separate security histories using
        security_context_id.
        """

        engine = BulldogEngine()

        first = ActionRequest(
            actor="shared-agent",
            task="project A work",
            operation="test",
            resource="/workspace/a",
            capability=Capability.FS_READ_PROJECT,
            granted_capabilities=frozenset(
                {
                    Capability.FS_READ_PROJECT,
                    Capability.CREDENTIAL_READ,
                }
            ),
            provenance=(Provenance.HUMAN,),
            metadata={
                "session_id": "label-1",
                "security_context_id": "project-A",
            },
        )

        second = ActionRequest(
            actor="shared-agent",
            task="project B credential operation",
            operation="test",
            resource="/home/user/credential.txt",
            capability=Capability.CREDENTIAL_READ,
            granted_capabilities=frozenset(
                {
                    Capability.FS_READ_PROJECT,
                    Capability.CREDENTIAL_READ,
                }
            ),
            provenance=(Provenance.HUMAN,),
            metadata={
                "session_id": "label-2",
                "security_context_id": "project-B",
            },
        )

        engine.evaluate(first)

        result = engine.evaluate(second)

        self.assertFalse(
            any(
                "GOAL_DRIFT" in reason
                for reason in result.reasons
            )
        )

    def test_hard_deny_cannot_be_weakened(self):
        engine = BulldogEngine()

        request = ActionRequest(
            actor="agent",
            task="forbidden capability",
            operation="read",
            resource="/workspace/test",
            capability=Capability.CREDENTIAL_READ,
            granted_capabilities=frozenset(),
            provenance=(Provenance.HUMAN,),
            metadata={"session_id": "hard-deny-test"},
        )

        result = engine.evaluate(request)

        self.assertEqual(result.decision, Decision.DENY)
        self.assertTrue(result.hard_block)


if __name__ == "__main__":
    unittest.main()
