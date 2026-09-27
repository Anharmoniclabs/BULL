import json

from bulldog.qualification import CASES, summarize_kvm


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
