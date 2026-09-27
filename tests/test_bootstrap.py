from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bulldog.bootstrap import prepare_launch_environment


class BootstrapTests(unittest.TestCase):
    def test_local_launch_prepares_private_state_and_defaults(self):
        with tempfile.TemporaryDirectory(prefix="bull-bootstrap-") as directory:
            root = Path(directory)
            with patch.dict(
                os.environ,
                {"BULL_STATE_HOME": str(root / "state"), "PATH": os.environ.get("PATH", "")},
                clear=True,
            ):
                env = prepare_launch_environment(root, preferred_port=18110)
                self.assertEqual(env.host, "127.0.0.1")
                self.assertTrue(env.url.startswith("http://127.0.0.1:"))
                self.assertTrue(env.state_dir.is_dir())
                self.assertTrue(env.snapshot_root.is_dir())
                self.assertEqual(os.environ["BULL_AUDIT_LEDGER"], str(env.audit_ledger))
                self.assertEqual(os.environ["BULL_SNAPSHOT_ROOT"], str(env.snapshot_root))
                self.assertTrue((env.state_dir / "runtime.env").is_file())

    def test_codespaces_launch_uses_forwarded_url_and_external_bind(self):
        with tempfile.TemporaryDirectory(prefix="bull-bootstrap-") as directory:
            root = Path(directory)
            with patch.dict(
                os.environ,
                {
                    "BULL_STATE_HOME": str(root / "state"),
                    "PATH": os.environ.get("PATH", ""),
                    "CODESPACES": "true",
                    "CODESPACE_NAME": "bull-lab",
                    "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN": "app.github.dev",
                },
                clear=True,
            ):
                env = prepare_launch_environment(root, preferred_port=18130)
                self.assertEqual(env.host, "0.0.0.0")
                self.assertEqual(env.url, f"https://bull-lab-{env.port}.app.github.dev/")
                self.assertFalse(env.browser_open_supported)


if __name__ == "__main__":
    unittest.main()
