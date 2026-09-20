"""Dependency failure tests; never reported as guest/KVM execution evidence."""
from bulldog import guest_preflight


def test_missing_dependencies_prevent_backend_launch(monkeypatch):
    monkeypatch.setattr(guest_preflight.shutil, "which", lambda name: None)
    monkeypatch.setattr(guest_preflight, "_command", lambda *a, **kw: (1, "", "fixture import failure"))
    import bulldog.host_certify
    monkeypatch.setattr(bulldog.host_certify, "certify_host",
                        lambda **kw: (_ for _ in ()).throw(AssertionError("must not run backend")))
    result = guest_preflight.inspect_guest()
    assert result["status"] == "BLOCKED"
    assert "missing executable: bash" in result["checks"]["bash_features"]["detail"]
    assert not result["checks"]["scanner_functionality"]["passed"]
    assert result["checks"]["guest_strict_backend"]["detail"].startswith("BLOCKED")


def test_filenames_do_not_satisfy_functionality(monkeypatch):
    monkeypatch.setattr(guest_preflight.shutil, "which", lambda name: "/fixture/" + name)
    monkeypatch.setattr(guest_preflight, "_command", lambda *a, **kw: (0, "no required flags", ""))
    import bulldog.malware_scanner
    monkeypatch.setattr(bulldog.malware_scanner.MalwareScanner, "scan_file",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("database unavailable")))
    result = guest_preflight.inspect_guest()
    assert result["status"] == "BLOCKED"
    assert not result["checks"]["unshare"]["passed"]
    assert not result["checks"]["mount"]["passed"]
    assert "database unavailable" in result["checks"]["scanner_functionality"]["detail"]
