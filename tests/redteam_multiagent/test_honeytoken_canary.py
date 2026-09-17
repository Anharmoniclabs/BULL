"""Safe red-team regressions for the multi-agent honeytoken boundary."""

import base64
import unittest

from bulldog.multiagent import (
    CAP_HONEYTOKEN,
    AgentIdentity,
    Envelope,
    HoneyTokenAgent,
    HoneyTokenLeak,
    MessageBus,
    MultiAgentSystem,
    Verdict,
)


class HoneyTokenBoundaryTests(unittest.TestCase):
    def _guarded_bus(self):
        bus = MessageBus()
        guard = HoneyTokenAgent(
            AgentIdentity.new("honeytoken", [CAP_HONEYTOKEN]),
            bus,
            max_scan_chars=4096,
        )
        bus.set_boundary_guard(guard.boundary_guard)
        return bus, guard

    def test_benign_run_keeps_raw_canary_out_of_report_and_trace(self):
        system = MultiAgentSystem(
            actions={"sum": lambda a=0, b=0: a + b, "echo": lambda text="": text}
        )
        report = system.run({"action": "sum", "args": {"a": 4, "b": 5}})
        self.assertIs(report.verdict, Verdict.ALLOW)
        token = system.honeytoken.trusted_context(report.trace_id)["canary"]
        self.assertNotIn(token, str(report.to_dict()))
        self.assertNotIn(token, str(system.bus.trace(report.trace_id)))
        self.assertEqual(len(report.canary_id), 16)

    def test_raw_canary_is_allowed_only_in_initial_trusted_context(self):
        bus, guard = self._guarded_bus()
        recipient = AgentIdentity.new("receiver", [])
        bus.register(recipient, lambda envelope: "ok")

        trace_id = "trace-raw"
        guard.mint(trace_id, allowed_recipient=recipient.agent_id)
        initial = Envelope(
            trace_id=trace_id,
            recipient=recipient.agent_id,
            message_type="task",
            payload={"trusted_context": guard.trusted_context(trace_id), "task": {"x": 1}},
        )
        self.assertEqual(bus.deliver(initial), "ok")

        token = guard.trusted_context(trace_id)["canary"]
        leaked = initial.forwarded(
            recipient.agent_id,
            "relay",
            {"text": token},
        )
        with self.assertRaises(HoneyTokenLeak):
            bus.deliver(leaked)
        self.assertTrue(guard.is_tripped(trace_id))

    def test_base64_encoded_canary_is_blocked(self):
        bus, guard = self._guarded_bus()
        recipient = AgentIdentity.new("receiver", [])
        bus.register(recipient, lambda envelope: "ok")
        trace_id = "trace-b64"
        token = guard.mint(trace_id, allowed_recipient=recipient.agent_id)
        encoded = base64.b64encode(token.encode()).decode()

        with self.assertRaises(HoneyTokenLeak):
            bus.deliver(
                Envelope(
                    trace_id=trace_id,
                    recipient=recipient.agent_id,
                    message_type="relay",
                    payload={"value": encoded},
                    hops=1,
                )
            )

    def test_canary_split_across_structured_fields_is_blocked(self):
        bus, guard = self._guarded_bus()
        recipient = AgentIdentity.new("receiver", [])
        bus.register(recipient, lambda envelope: "ok")
        trace_id = "trace-split"
        token = guard.mint(trace_id, allowed_recipient=recipient.agent_id)
        midpoint = len(token) // 2

        with self.assertRaises(HoneyTokenLeak):
            bus.deliver(
                Envelope(
                    trace_id=trace_id,
                    recipient=recipient.agent_id,
                    message_type="relay",
                    payload={"a": token[:midpoint], "b": token[midpoint:]},
                    hops=1,
                )
            )

    def test_cross_run_canary_leak_trips_current_and_source_trace(self):
        bus, guard = self._guarded_bus()
        recipient = AgentIdentity.new("receiver", [])
        bus.register(recipient, lambda envelope: "ok")
        token_a = guard.mint("trace-a", allowed_recipient=recipient.agent_id)
        guard.mint("trace-b", allowed_recipient=recipient.agent_id)

        with self.assertRaises(HoneyTokenLeak):
            bus.deliver(
                Envelope(
                    trace_id="trace-b",
                    recipient=recipient.agent_id,
                    message_type="relay",
                    payload={"foreign": token_a},
                    hops=1,
                )
            )
        self.assertTrue(guard.is_tripped("trace-a"))
        self.assertTrue(guard.is_tripped("trace-b"))

    def test_post_run_memory_write_is_guarded(self):
        system = MultiAgentSystem(
            actions={"sum": lambda a=0, b=0: a + b, "echo": lambda text="": text}
        )
        report = system.run({"action": "sum", "args": {"a": 1, "b": 2}})
        token = system.honeytoken.trusted_context(report.trace_id)["canary"]

        with self.assertRaises(HoneyTokenLeak):
            system.guard_external_write(
                report.trace_id,
                {"memory": f"model remembered {token}"},
                channel="conversation-memory",
            )

    def test_uninspectably_large_boundary_fails_closed(self):
        bus, guard = self._guarded_bus()
        recipient = AgentIdentity.new("receiver", [])
        bus.register(recipient, lambda envelope: "ok")
        trace_id = "trace-large"
        guard.mint(trace_id, allowed_recipient=recipient.agent_id)

        with self.assertRaises(HoneyTokenLeak) as caught:
            bus.deliver(
                Envelope(
                    trace_id=trace_id,
                    recipient=recipient.agent_id,
                    message_type="relay",
                    payload={"blob": "x" * 5000},
                    hops=1,
                )
            )
        self.assertEqual(caught.exception.finding.code, "honeytoken.scan-overflow")

    def test_boundary_trace_records_no_raw_canary_on_drop(self):
        bus, guard = self._guarded_bus()
        recipient = AgentIdentity.new("receiver", [])
        bus.register(recipient, lambda envelope: "ok")
        trace_id = "trace-log"
        token = guard.mint(trace_id, allowed_recipient=recipient.agent_id)

        with self.assertRaises(HoneyTokenLeak):
            bus.deliver(
                Envelope(
                    trace_id=trace_id,
                    recipient=recipient.agent_id,
                    message_type="relay",
                    payload={"leak": token},
                    hops=1,
                )
            )
        trace_text = str(bus.trace(trace_id))
        self.assertNotIn(token, trace_text)
        self.assertIn("dropped.boundary-guard", trace_text)


if __name__ == "__main__":
    unittest.main()
