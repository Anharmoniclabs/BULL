from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bulldog.control_plane import ControlPlane
from bulldog.models import Decision


class ControlPlaneTests(unittest.TestCase):
    def test_snapshot_reports_observed_state_without_fixture_metrics(self):
        with tempfile.TemporaryDirectory(prefix="bull-console-") as directory:
            proc = Path(directory) / "proc"
            proc.mkdir()
            with patch.dict(
                os.environ,
                {
                    "PATH": os.environ.get("PATH", ""),
                    "BULL_AUDIT_LEDGER": "",
                    "BULL_POLICY_BUNDLE": "",
                    "BULL_POLICY_BUNDLE_KEY": "",
                },
                clear=True,
            ):
                control = ControlPlane(
                    workspace=directory,
                    auto_scan=False,
                    dynamic_attestation=False,
                    proc_root=proc,
                )
                snapshot = control.snapshot()

        self.assertEqual(snapshot["meta"]["workspace"], str(Path(directory).resolve()))
        self.assertEqual(snapshot["discovery"]["entity_count"], 0)
        self.assertEqual(snapshot["system_health"]["observed_entities"], 0)
        self.assertFalse(snapshot["audit"]["configured"])
        self.assertEqual(snapshot["audit"]["records"], 0)
        self.assertIn(snapshot["malware"]["status"], {"ready", "unavailable", "error"})
        self.assertEqual(len(snapshot["isolation"]["items"]), 8)

    def test_policy_workbench_uses_real_deterministic_policy(self):
        with tempfile.TemporaryDirectory(prefix="bull-console-") as directory:
            proc = Path(directory) / "proc"
            proc.mkdir()
            with patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
                control = ControlPlane(
                    workspace=directory,
                    auto_scan=False,
                    dynamic_attestation=False,
                    proc_root=proc,
                )
                result = control.evaluate_policy(
                    {
                        "actor": "test",
                        "operation": "credential.read",
                        "resource": "/tmp/credential",
                        "capability": "credential.read",
                        "granted_capabilities": ["credential.read"],
                        "provenance": ["internet"],
                    }
                )
        self.assertEqual(result["decision"], Decision.DENY.value)
        self.assertTrue(result["hard_block"])
        self.assertEqual(result["risk"], 1.0)

    def test_console_assets_are_operator_views_not_fake_demo_counters(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "src/bulldog/console_static/index.html").read_text(encoding="utf-8")
        js = (root / "src/bulldog/console_static/app.js").read_text(encoding="utf-8")
        self.assertIn("From Discovery to Enforcement", html)
        self.assertIn("Malware Scan", html)
        self.assertIn("Dynamic Attestation", html)
        self.assertIn("/api/v1/snapshot", js)
        self.assertIn("microvm-start", html)
        self.assertIn("microvm-stop", html)
        self.assertNotIn("1,842", html + js)
        self.assertNotIn("127 Protected Sessions", html + js)
        self.assertNotIn("All systems operational", html + js)


if __name__ == "__main__":
    unittest.main()
