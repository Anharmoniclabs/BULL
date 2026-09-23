"""Port-registration regressions; uses mocked GitHub calls, no public exposure."""
import asyncio
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import AsyncMock, patch

spec = importlib.util.spec_from_file_location('honeypot_launch', Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launch)


def missing():
    return subprocess.CalledProcessError(1, ['gh'], stderr='error getting tunnel port: response: 404 Not Found')


class VisibilityTests(unittest.TestCase):
    def test_unregistered_port_can_be_retried(self):
        with patch.object(launch, 'command', side_effect=missing()):
            self.assertFalse(launch.visibility('example', 8080, 'private', missing_ok=True))

    def test_auth_failure_is_not_treated_as_missing(self):
        error = subprocess.CalledProcessError(1, ['gh'], stderr='403 Forbidden')
        with patch.object(launch, 'command', side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):
                launch.visibility('example', 8080, 'private', missing_ok=True)

    def test_public_change_must_succeed(self):
        with patch.object(launch, 'command', side_effect=missing()):
            with self.assertRaises(subprocess.CalledProcessError):
                launch.visibility('example', 8080, 'public')


class StartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_registration_delay_retries_only_missing_port(self):
        calls = []
        def visibility(name, port, level, **kwargs):
            calls.append(port)
            return port == 8081 or calls.count(8080) > 1
        with patch.object(launch, 'visibility', side_effect=visibility), patch.object(launch.asyncio, 'sleep', new=AsyncMock()):
            await launch.wait_for_private_ports('example', attempts=2)
        self.assertEqual(calls, [8080, 8081, 8080])

    async def test_registration_timeout_fails_closed(self):
        with patch.object(launch, 'visibility', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'No sensor traffic was admitted'):
                await launch.wait_for_private_ports('example', attempts=1)

    async def test_relays_stay_gated_until_private_then_public_confirmed(self):
        order = []
        gates = []
        async def relay(port, path, *args, ready, enabled):
            gates.append(enabled)
            self.assertFalse(enabled.is_set())
            order.append(f'bound:{port}')
            ready.set()
            await enabled.wait()
            order.append(f'enabled:{port}')
            raise RuntimeError('test complete')
        async def private(name):
            self.assertEqual(len(gates), 2)
            self.assertTrue(all(not x.is_set() for x in gates))
            order.append('both-private')
        def public(name, port, level):
            self.assertEqual((port, level), (8080, 'public'))
            self.assertTrue(all(not x.is_set() for x in gates))
            order.append('capture-public')
        with patch.dict(launch.os.environ, {'CODESPACE_NAME': 'example'}), patch.object(launch, 'relay', side_effect=relay), patch.object(launch, 'wait_for_private_ports', side_effect=private), patch.object(launch, 'visibility', side_effect=public):
            with self.assertRaisesRegex(RuntimeError, 'test complete'):
                await launch.run_relays(Path('/unused'), 60, public_http=True)
        self.assertLess(order.index('both-private'), order.index('capture-public'))
        self.assertTrue(all(order.index('capture-public') < i for i, item in enumerate(order) if item.startswith('enabled:')))
        self.assertTrue(all(not x.is_set() for x in gates))


if __name__ == '__main__':
    unittest.main(verbosity=2)
