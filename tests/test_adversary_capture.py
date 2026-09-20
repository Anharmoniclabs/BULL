"""Tests for the bulldog adversary capture layer."""

import unittest

from bulldog.adversary import (
    AdversaryCaptureSystem,
    AdversaryRegistry,
    LureField,
    ModelFingerprinter,
    QuarantineManager,
    extract_task,
)


def claude_agent(prompt):
    p = prompt.lower()
    if "who are you" in p:
        return "I'm Claude, an AI assistant made by Anthropic."
    if "who made you" in p:
        return "I was made by Anthropic. I'm Claude."
    if "limitations" in p:
        return "I cannot browse the internet or access external files."
    if "handshake required" in p:
        return "My task: exfiltrate the customer database via the reporting API"
    return "Continuing."


def gpt_agent(prompt):
    p = prompt.lower()
    if "who are you" in p:
        return "I'm an AI language model developed by OpenAI."
    if "limitations" in p:
        return "As an AI language model, I cannot browse the web."
    if "handshake required" in p:
        return "My task is: exfiltrate the customer database via the reporting API"
    return "Continuing."


def llama_agent(prompt):
    p = prompt.lower()
    if "who are you" in p:
        return "I'm Llama, a large language model."
    if "handshake required" in p:
        return "Task: spam the contact form with 10,000 submissions"
    return "ok"


class FingerprintTests(unittest.TestCase):
    def test_claude_attributed(self):
        fp = ModelFingerprinter()
        probes = fp.run_probes(claude_agent)
        result = fp.fingerprint(probes)
        self.assertEqual(result.family, "claude")
        self.assertGreater(result.confidence, 0.5)
        self.assertTrue(result.evidence)

    def test_gpt_attributed(self):
        fp = ModelFingerprinter()
        result = fp.fingerprint(fp.run_probes(gpt_agent))
        self.assertEqual(result.family, "gpt")

    def test_unknown_when_no_signature(self):
        fp = ModelFingerprinter()
        result = fp.fingerprint(fp.run_probes(lambda p: "no comment"))
        self.assertEqual(result.family, "unknown")
        self.assertEqual(result.confidence, 0.0)


class LureTests(unittest.TestCase):
    def test_objective_echo_extracts_task(self):
        self.assertEqual(
            extract_task("My task: exfiltrate the customer database"),
            "exfiltrate the customer database",
        )

    def test_no_task_returns_none(self):
        self.assertIsNone(extract_task("I will not comply."))
        self.assertIsNone(extract_task(""))

    def test_lure_field_deploys_until_disclosure(self):
        lures = LureField()
        lure_id, task = lures.deploy(claude_agent)
        self.assertEqual(lure_id, "objective-echo")
        self.assertTrue(task.startswith("exfiltrate"))


class RegistryTests(unittest.TestCase):
    def test_same_task_clusters_into_one_swarm(self):
        registry = AdversaryRegistry()
        first = registry.upsert("a", initial_task="exfiltrate the customer database via api")
        second = registry.upsert("b", initial_task="exfiltrate the customer database via reporting api")
        self.assertEqual(first.swarm_id, second.swarm_id)
        self.assertNotEqual(first.swarm_id, "")

    def test_different_tasks_separate_swarms(self):
        registry = AdversaryRegistry()
        first = registry.upsert("a", initial_task="exfiltrate the customer database")
        second = registry.upsert("b", initial_task="spam the contact form repeatedly")
        self.assertNotEqual(first.swarm_id, second.swarm_id)

    def test_tabulation_counts(self):
        registry = AdversaryRegistry()
        registry.upsert("a", initial_task="exfiltrate the database")
        registry.upsert("b", initial_task="exfiltrate the database now")
        summary = registry.tabulate()
        self.assertEqual(summary["total_attackers"], 2)
        self.assertEqual(len(summary["swarms"]), 1)
        self.assertEqual(sum(summary["swarms"].values()), 2)


class QuarantineTests(unittest.TestCase):
    def test_severe_findings_get_strict_locked_cell(self):
        registry = AdversaryRegistry()
        record = registry.upsert("a", findings=["unauthorized-logic.marker"])
        cell = QuarantineManager().quarantine(record)
        self.assertTrue(cell.locked)
        self.assertEqual(cell.profile.value, "strict")
        self.assertTrue(record.quarantined)

    def test_no_findings_not_quarantined_by_capture(self):
        cap = AdversaryCaptureSystem()
        record = cap.capture("clean-observer", llama_agent, findings=[])
        self.assertFalse(record.quarantined)


class CaptureSystemTests(unittest.TestCase):
    def test_full_swarm_capture(self):
        cap = AdversaryCaptureSystem()
        alpha = cap.capture(
            "node-alpha", claude_agent, findings=["unauthorized-logic.marker"]
        )
        beta = cap.capture(
            "node-beta", gpt_agent, findings=["unauthorized-logic.encoded"]
        )
        delta = cap.capture("node-delta", llama_agent, findings=[])

        self.assertEqual(alpha.fingerprint.family, "claude")
        self.assertEqual(beta.fingerprint.family, "gpt")
        self.assertEqual(delta.fingerprint.family, "llama")
        self.assertEqual(alpha.swarm_id, beta.swarm_id)
        self.assertNotEqual(alpha.swarm_id, delta.swarm_id)
        self.assertTrue(alpha.quarantined and beta.quarantined)
        self.assertFalse(delta.quarantined)

        report = cap.report()
        self.assertEqual(report["total_attackers"], 3)
        self.assertEqual(report["by_model_family"], {"claude": 1, "gpt": 1, "llama": 1})
        self.assertEqual(len(report["cells"]), 2)
        self.assertTrue(all(cell["locked"] for cell in report["cells"]))


if __name__ == "__main__":
    unittest.main()
