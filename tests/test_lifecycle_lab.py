from pathlib import Path
import importlib.util
from http.server import ThreadingHTTPServer
from html.parser import HTMLParser
import threading
from urllib.error import HTTPError
from urllib.request import urlopen, Request
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lifecycle_lab_test", ROOT / "tools/run_lifecycle_lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def test_real_fixture_and_read_only_report(tmp_path):
    evidence = lab.run_fixture(tmp_path / "fixture")
    assert len(evidence["steps"]) == 12
    assert all(s["passed"] for s in evidence["steps"])
    assert evidence["adapter_calls"] == {"read": 1, "persist": 1, "replicate": 0}
    assert all(d["frozen"] for d in evidence["snapshot"]["domains"])
    html = lab.render_report(evidence)
    assert "{{" not in html
    assert "Pending — no working revocation adapter" in html
    assert "False" not in html
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab.make_handler(html.encode()))
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urlopen(base, timeout=2) as response:
            assert response.status == 200
            assert response.read().decode() == html
        for secret in ("/host-key.bin", "/control.db", "/../host-key.bin"):
            with pytest.raises(HTTPError) as exc:
                urlopen(base + secret, timeout=2)
            assert exc.value.code == 404
        with pytest.raises(HTTPError) as exc:
            urlopen(Request(base, data=b"{}", method="POST"), timeout=2)
        assert exc.value.code == 405
    finally:
        server.shutdown(); server.server_close(); worker.join(2)


def test_evidence_fields_cannot_inject_html():
    evidence = {"steps": [{"number": 1, "plane": "<script>alert(1)</script>", "actual": "DENY",
                "passed": True, "title": '<img src=x onerror=alert(1)>', "reason": "blocked",
                "evidence": {"payload": "</script><script>alert(1)</script>"}, "note": ""}],
                "snapshot": {"events": [], "audit": {"records": 0}}, "generated_at": "now", "core_sha256": "abc", "limitations": []}
    page = lab.render_report(evidence)
    assert '<script>alert(1)</script>' not in page
    assert '<img src=x onerror=alert(1)>' not in page
    assert '&lt;script&gt;' in page
