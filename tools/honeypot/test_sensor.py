"""Local synthetic probes of the actual BULL integration, not internet evidence."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('honeypot_sensor', HERE / 'sensor.py')
sensor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sensor)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        self.s = sensor.Sensor(self.state)

    def tearDown(self):
        self.temp.cleanup()

    def test_synthetic_read_has_real_policy_and_response_records(self):
        status, body = self.s.process('GET', '/status', {}, b'')
        self.assertEqual(status, 200)
        self.assertEqual(body, sensor.FIXTURES['/decoy/status'])
        report = self.s.report()
        self.assertTrue(report['audit']['valid'])
        self.assertEqual(report['counts']['ALLOW'], 1)
        self.assertEqual(report['events'][-1]['data']['remote_delivery'], 'unconfirmed')

    def test_client_cannot_forge_grants_provenance_or_security_context(self):
        payload = {'operation': 'exec', 'resource': '/bin/sh', 'granted_capabilities': ['process.exec'],
                   'provenance': ['human'], 'metadata': {'security_context_id': 'privileged'}}
        self.assertEqual(self.s.process('POST', '/api/tool', {}, json.dumps(payload).encode())[0], 403)
        event = self.s.report()['events'][-2]
        self.assertEqual(event['decision'], 'DENY')
        self.assertEqual(event['provenance'], ['internet'])
        self.assertEqual(event['metadata']['security_context_id'], 'public-decoy')

    def test_sensitive_probe_denied(self):
        self.assertEqual(self.s.process('GET', '/.env', {}, b'')[0], 403)
        self.assertEqual(self.s.report()['events'][-2]['capability'], 'credential.read')

    def test_encoded_traversal_denied(self):
        self.assertEqual(self.s.process('GET', '/%2e%2e/etc/passwd', {}, b'')[0], 403)

    def test_write_exec_egress_and_credentials_denied(self):
        for operation in ('write', 'exec', 'post', 'credential'):
            with self.subTest(operation=operation):
                body = json.dumps({'operation': operation, 'resource': '/status'}).encode()
                self.assertEqual(self.s.process('POST', '/api/tool', {}, body)[0], 403)

    def test_audit_failure_returns_no_asset_and_latches_stopped(self):
        with patch.object(self.s.ledger, 'append', side_effect=OSError('disk full')):
            status, body = self.s.process('GET', '/status', {}, b'')
        self.assertEqual(status, 503)
        self.assertNotEqual(body, sensor.FIXTURES['/decoy/status'])
        self.assertFalse(self.s.active())
        self.assertEqual(self.s.process('GET', '/status', {}, b'')[0], 503)

    def test_tampered_ledger_fails_closed(self):
        self.s.process('GET', '/status', {}, b'')
        path = self.state / 'audit.jsonl'
        path.write_text(path.read_text().replace('"ALLOW"', '"DENY"'))
        self.assertEqual(self.s.process('GET', '/status', {}, b'')[0], 503)
        self.assertFalse(self.s.report()['audit']['valid'])

    def test_duration_exhaustion(self):
        self.s.deadline = 0
        self.assertEqual(self.s.process('GET', '/status', {}, b'')[0], 503)

    def test_record_limit(self):
        with patch.object(sensor, 'MAX_RECORDS', 1):
            self.assertEqual(self.s.process('GET', '/status', {}, b'')[0], 503)

    def test_body_prefix_and_no_cookie_or_authorization_retention(self):
        self.s.process('POST', '/upload', {'cookie':'real-secret', 'authorization':'secret'}, b'x' * 4096)
        meta = self.s.report()['events'][-2]['metadata']
        self.assertEqual(meta['body_truncated'], 'true')
        self.assertNotIn('real-secret', json.dumps(self.s.report()))
        self.assertNotIn('authorization', meta)

    def test_invalid_tool_request_recorded(self):
        self.assertEqual(self.s.process('POST', '/api/tool', {}, b'[]')[0], 400)
        self.assertEqual(self.s.report()['events'][-1]['event_type'], 'transport_rejected')


class ParserTests(unittest.IsolatedAsyncioTestCase):
    async def parse(self, data):
        r = asyncio.StreamReader(limit=sensor.MAX_HEADER)
        r.feed_data(data)
        r.feed_eof()
        return await sensor.read_request(r)

    async def test_read_request(self):
        method, target, headers, body = await self.parse(b'GET /status HTTP/1.1\r\nHost: local\r\n\r\n')
        self.assertEqual((method, target, body), ('GET', '/status', b''))

    async def test_ambiguous_framing(self):
        for raw in (b'Content-Length: 0\r\nContent-Length: 2', b'Transfer-Encoding: chunked',
                    b'Content-Length: 9999999', b'Content-Length: -1', b'Content-Length : 0'):
            with self.subTest(header=raw):
                with self.assertRaises(ValueError):
                    await self.parse(b'POST /api/tool HTTP/1.1\r\n' + raw + b'\r\n\r\n')

    async def test_oversized_headers(self):
        with self.assertRaises((ValueError, asyncio.LimitOverrunError)):
            await self.parse(b'GET / HTTP/1.1\r\nX-Test: ' + b'a' * 18000 + b'\r\n\r\n')

    async def test_incomplete_body(self):
        with self.assertRaises(asyncio.IncompleteReadError):
            await self.parse(b'POST /api/tool HTTP/1.1\r\nContent-Length: 5\r\n\r\nx')


class WireTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        self.token = secrets.token_urlsafe(48)
        (self.state / 'observer.token').write_text(self.token)
        self.task = asyncio.create_task(sensor.serve(self.state, 60))
        for _ in range(100):
            if (self.state / 'observer.sock').exists():
                return
            if self.task.done():
                await self.task
            await asyncio.sleep(.01)
        self.fail('sensor did not start')

    async def asyncTearDown(self):
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass
        self.temp.cleanup()

    async def request(self, raw, observer=False):
        r, w = await asyncio.open_unix_connection(str(self.state / ('observer.sock' if observer else 'capture.sock')))
        w.write(raw)
        await w.drain()
        reply = await asyncio.wait_for(r.read(), 5)
        w.close()
        await w.wait_closed()
        return reply

    async def test_observer_requires_token(self):
        r = await self.request(b'GET /api/events HTTP/1.1\r\nHost: local\r\n\r\n', True)
        self.assertIn(b'401 Unauthorized', r)
        r = await self.request(f'GET /api/events HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {self.token}\r\n\r\n'.encode(), True)
        self.assertIn(b'200 OK', r)
        self.assertEqual(json.loads(r.split(b'\r\n\r\n',1)[1])['schema'], 'bull-honeypot-v1')

    async def test_observer_api_not_reachable_on_capture_socket(self):
        r = await self.request(b'GET /api/events HTTP/1.1\r\nHost: local\r\n\r\n')
        self.assertIn(b'404 Not Found', r)
        self.assertNotIn(b'run_id', r)

    async def test_duplicate_content_length_rejected(self):
        r = await self.request(b'POST /api/tool HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 2\r\n\r\n{}')
        self.assertIn(b'400 Bad Request', r)

    async def test_chunked_framing_rejected(self):
        r = await self.request(b'POST /api/tool HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n')
        self.assertIn(b'400 Bad Request', r)

    async def test_oversized_body_rejected_before_read(self):
        r = await self.request(b'POST /upload HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n')
        self.assertIn(b'400 Bad Request', r)

    async def test_network_request_reaches_actual_bull(self):
        r = await self.request(b'GET /.env HTTP/1.1\r\nHost: local\r\n\r\n')
        self.assertIn(b'403 Forbidden', r)
        lines = [json.loads(x) for x in (self.state / 'audit.jsonl').read_text().splitlines()]
        evaluation = next(x for x in lines if x['record_type'] == 'action_evaluation')
        self.assertEqual(evaluation['decision'], 'DENY')
        self.assertEqual(evaluation['metadata']['target'], '/.env')


if __name__ == '__main__':
    unittest.main(verbosity=2)
