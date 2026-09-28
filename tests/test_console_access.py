"""The console API refuses unauthenticated, cross-origin and rebinding requests.

Loopback binding is not an identity: another local account, an agent, or a web
page in the operator's browser can all reach 127.0.0.1. Runs a real HTTP server.
"""

import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch

import pytest

from bulldog.control_plane import ConsoleHandler, ControlPlane, _ConsoleServer, console_url


@pytest.fixture
def console():
    with tempfile.TemporaryDirectory(prefix="bull-console-") as directory:
        proc = Path(directory) / "proc"
        proc.mkdir()
        with patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
            control = ControlPlane(
                workspace=directory, auto_scan=False, dynamic_attestation=False,
                proc_root=proc,
            )
            try:
                server = _ConsoleServer(("127.0.0.1", 0), ConsoleHandler, control)
            except OSError as exc:
                pytest.skip(f"loopback HTTP unavailable: {exc}")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield server
            finally:
                server.shutdown()
                server.server_close()


def send(server, method, path, *, key=None, host=None, origin=None,
         content_type="application/json", body=b"{}"):
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if key is not None:
        headers["Authorization"] = "Bearer " + key
    if origin is not None:
        headers["Origin"] = origin
    if method == "POST":
        headers["Content-Type"] = content_type
    conn.request(method, path, body=body if method == "POST" else None, headers=headers)
    response = conn.getresponse()
    status, data = response.status, response.read()
    conn.close()
    return status, data


def test_snapshot_requires_the_run_key(console):
    assert send(console, "GET", "/api/v1/snapshot")[0] == 401
    assert send(console, "GET", "/api/v1/snapshot", key="guess")[0] == 401
    status, data = send(console, "GET", "/api/v1/snapshot", key=console.access_key)
    assert status == 200 and "meta" in json.loads(data)


def test_static_page_loads_without_key(console):
    assert send(console, "GET", "/")[0] == 200


@pytest.mark.parametrize("action", ["microvm-stop", "microvm-start", "malware-scan", "rescan"])
def test_actions_refuse_missing_key(console, action):
    assert send(console, "POST", "/api/v1/actions/" + action)[0] == 401


def test_rebinding_host_is_refused_even_with_key(console):
    status, _ = send(console, "GET", "/api/v1/snapshot", key=console.access_key,
                     host="attacker.example:80")
    assert status == 421


def test_cross_site_form_post_is_refused(console):
    port = console.server_address[1]
    status, _ = send(console, "POST", "/api/v1/actions/rescan", key=console.access_key,
                     content_type="text/plain")
    assert status == 415
    status, _ = send(console, "POST", "/api/v1/actions/rescan", key=console.access_key,
                     origin="https://attacker.example")
    assert status == 403
    status, _ = send(console, "POST", "/api/v1/actions/rescan", key=console.access_key,
                     origin=f"http://127.0.0.1:{port}")
    assert status == 200


def test_oversized_body_is_refused_not_split(console):
    status, _ = send(console, "POST", "/api/v1/actions/policy-evaluate",
                     key=console.access_key, body=b" " * (70 * 1024))
    assert status == 400


def test_operator_url_keeps_key_in_fragment():
    url = console_url("http://127.0.0.1:11510/", "abc")
    assert url == "http://127.0.0.1:11510/#token=abc"
