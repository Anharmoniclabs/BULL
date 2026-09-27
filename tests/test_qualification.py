import json

from bulldog.qualification import (CASES, GATEWAY_CHECKS, summarize_kvm,
                                   summarize_offline_egress, summarize_gateway_lab,
                                   summarize_gateway_systemd)


def test_private_kvm_reports_are_bound_and_sanitized(tmp_path):
    revision, digest = "a" * 40, "b" * 64
    assets = {name: digest for name in ("kernel", "rootfs", "firmware")}
    case_dir = tmp_path / "cases"
    case_dir.mkdir()
    (tmp_path / "setup-report.json").write_text(json.dumps({
        "status": "PASS", "source_dirty": False, "source_commit": revision,
        "kvm": {"status": "PASS"}, "asset_sha256": assets,
        "private_token": "DO-NOT-EXPOSE"}))
    (case_dir / "summary.json").write_text(json.dumps({
        "status": "PASS", "source_tree_sha256": [digest],
        "cases": {name: "PASS" for name in CASES}}))
    for name in CASES:
        path = case_dir / name
        path.mkdir()
        (path / "report.json").write_text(json.dumps({
            "status": "PASS", "case": name, "revision": revision,
            "assets": assets, "source_tree_sha256": digest,
            "external_collector": False, "private_token": "DO-NOT-EXPOSE"}))
    result = summarize_kvm(tmp_path, current_commit=revision)
    assert result["status"] == "PASS"
    assert "DO-NOT-EXPOSE" not in str(result)
    assert summarize_kvm(tmp_path, current_commit="c" * 40)["status"] == "STALE"
    denied = case_dir / "denied" / "report.json"
    data = json.loads(denied.read_text())
    data["assets"]["kernel"] = "c" * 64
    denied.write_text(json.dumps(data))
    assert summarize_kvm(tmp_path, current_commit=revision)["status"] == "INVALID"


def test_offline_guest_report_is_source_bound_and_gateway_unclaimed(tmp_path):
    revision, digest = "a" * 40, "b" * 64
    assets = {name: digest for name in ("kernel", "rootfs", "firmware")}
    (tmp_path / "setup-report.json").write_text(json.dumps({
        "status": "PASS", "source_dirty": False, "source_commit": revision,
        "kvm": {"status": "PASS"}, "asset_sha256": assets}))
    case_dir = tmp_path / "offline-egress"
    case_dir.mkdir()
    report = {"status": "PASS", "case": "offline-egress", "revision": revision,
              "assets": assets, "source_tree_sha256": digest,
              "qemu_network": "none (observed child command line)", "external_collector": False,
              "offline_egress": {"denials": {"ipv4": "ENETUNREACH", "ipv6": "EAFNOSUPPORT"}}}
    path = case_dir / "report.json"
    path.write_text(json.dumps(report))
    result = summarize_offline_egress(tmp_path, current_commit=revision)
    assert result["status"] == "OFFLINE PASS"
    assert "gateway deployment not tested" in result["evidence"]
    assert summarize_offline_egress(tmp_path, current_commit="c" * 40)["status"] == "STALE"
    report["qemu_network"] = "slirp"
    path.write_text(json.dumps(report))
    assert summarize_offline_egress(tmp_path, current_commit=revision)["status"] == "INVALID"


def test_networked_gateway_lab_is_source_bound_and_separate_from_production(tmp_path):
    revision, digest = "a" * 40, "b" * 64
    report = {
        "status": "PASS", "source_dirty": False, "source_commit": revision,
        "kvm": {"status": "PASS"},
        "guest_assets": {name: digest for name in ("kernel", "initrd", "rootfs")},
        "guest_result": {
            "status": "PASS", "checks": {name: True for name in GATEWAY_CHECKS},
            "scope": "disposable Debian KVM lab guest, restricted QEMU user networking; "
                     "direct init startup, no systemd or production image",
            "private_token": "DO-NOT-EXPOSE",
        },
    }
    path = tmp_path / "setup-report.json"
    path.write_text(json.dumps(report))
    result = summarize_gateway_lab(tmp_path, current_commit=revision)
    assert result["status"] == "PASS"
    assert "production image or systemd claim" in result["evidence"]
    assert "DO-NOT-EXPOSE" not in str(result)
    assert summarize_gateway_lab(tmp_path, current_commit="c" * 40)["status"] == "STALE"
    report["guest_result"]["checks"]["denied_dns"] = False
    path.write_text(json.dumps(report))
    assert summarize_gateway_lab(tmp_path, current_commit=revision)["status"] == "INVALID"


def test_systemd_candidate_is_source_bound_and_never_promoted_to_production(tmp_path):
    revision, digest = "a" * 40, "b" * 64
    report = {
        "status": "PASS", "source_dirty": False, "source_commit": revision,
        "scope": "disposable Debian networked KVM systemd candidate; not the pinned production image",
        "kvm": {"status": "PASS"},
        "guest_assets": {name: digest for name in ("kernel", "initrd", "rootfs")},
        "guest_result": {"status": "PASS",
                         "checks": {name: True for name in GATEWAY_CHECKS | {"service_units_active"}}},
    }
    (tmp_path / "setup-report.json").write_text(json.dumps(report))
    result = summarize_gateway_systemd(tmp_path, current_commit=revision)
    assert result["status"] == "CANDIDATE PASS"
    assert "pinned production image remains separate" in result["evidence"]
    assert summarize_gateway_systemd(tmp_path, current_commit="c" * 40)["status"] == "STALE"
    report["guest_result"]["checks"]["agent_workload_uid"] = False
    (tmp_path / "setup-report.json").write_text(json.dumps(report))
    assert summarize_gateway_systemd(tmp_path, current_commit=revision)["status"] == "INVALID"
