from bulldog.snapshot import create_snapshot_isolated, destroy_snapshot
from bulldog.workspace_limits import WorkspaceBudget


def test_isolated_snapshot_worker_returns_read_only_bounded_snapshot(tmp_path, monkeypatch):
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "a.txt").write_text("safe", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    # The worker path is still exercised in CI even without a delegated real
    # cgroup. Production requires BULL_CGROUP_PARENT and adds cgroup limits.
    monkeypatch.delenv("BULL_CGROUP_PARENT", raising=False)
    budget = WorkspaceBudget(
        max_files=10,
        max_total_bytes=1024 * 1024,
        max_file_bytes=1024 * 1024,
        max_depth=4,
        max_path_bytes=256,
        manifest_timeout_seconds=5.0,
        snapshot_timeout_seconds=5.0,
        malware_scan_timeout_seconds=5.0,
        snapshot_min_free_bytes=1,
    )
    snapshot = create_snapshot_isolated(
        source,
        budget=budget,
        scratch_root=scratch,
    )
    assert (snapshot.snapshot_root / "a.txt").read_text(encoding="utf-8") == "safe"
    assert snapshot.snapshot_root.stat().st_mode & 0o222 == 0

    destroy_snapshot(snapshot)
    assert list(scratch.iterdir()) == []
