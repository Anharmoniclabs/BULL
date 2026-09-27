"""Read only, source-bound summary of a private five-case KVM run."""
from __future__ import annotations

import json
from pathlib import Path
import re

CASES = ("allowed", "denied", "timeout", "cancel", "missing-protection")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _read(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("missing, linked or oversized qualification report")
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("qualification report is not an object")
    return value


def summarize_kvm(directory: str | Path, *, current_commit: str | None) -> dict[str, str]:
    """Check five private reports; expose no paths, sessions, keys or raw events."""
    try:
        root = Path(directory)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("qualification directory unavailable")
        setup = _read(root / "setup-report.json")
        summary = _read(root / "cases/summary.json")
        revision = setup.get("source_commit")
        assets = setup.get("asset_sha256")
        trees = summary.get("source_tree_sha256")
        if (setup.get("status") != "PASS" or setup.get("source_dirty") is not False
                or type(setup.get("kvm")) is not dict or setup["kvm"].get("status") != "PASS"
                or type(revision) is not str or not HEX40.fullmatch(revision)
                or type(assets) is not dict or set(assets) != {"kernel", "rootfs", "firmware"}
                or any(type(v) is not str or not HEX64.fullmatch(v) for v in assets.values())
                or summary.get("status") != "PASS" or type(trees) is not list or len(trees) != 1
                or type(trees[0]) is not str or not HEX64.fullmatch(trees[0])
                or summary.get("cases") != {name: "PASS" for name in CASES}):
            raise ValueError("incomplete five-case qualification summary")
        for name in CASES:
            case = _read(root / "cases" / name / "report.json")
            if (case.get("status") != "PASS" or case.get("case") != name
                    or case.get("revision") != revision or case.get("assets") != assets
                    or case.get("source_tree_sha256") != trees[0]
                    or case.get("external_collector") is not False):
                raise ValueError("case identity or result mismatch")
        if current_commit != revision:
            return {"status": "STALE", "detail": "Five guest cases passed for a different source revision.",
                    "evidence": f"Operator-selected private reports: {revision[:12]} (one-shot fixture)"}
        return {"status": "PASS", "detail": "Five real-KVM one-shot cases passed for this source revision.",
                "evidence": f"Operator-selected private reports: {revision[:12]}; disposable local TLS collector"}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"status": "INVALID", "detail": "Selected KVM evidence is missing, incomplete or inconsistent.",
                "evidence": "No qualification claim made"}


def summarize_offline_egress(directory: str | Path, *, current_commit: str | None) -> dict[str, str]:
    """Check a separate guest-offline fixture without implying gateway enforcement."""
    try:
        root = Path(directory)
        if root.is_symlink() or not root.is_dir():
            raise ValueError("offline evidence directory unavailable")
        setup = _read(root / "setup-report.json")
        case = _read(root / "offline-egress/report.json")
        revision = setup.get("source_commit")
        assets = setup.get("asset_sha256")
        fixture = case.get("offline_egress")
        if (setup.get("status") != "PASS" or setup.get("source_dirty") is not False
                or type(setup.get("kvm")) is not dict or setup["kvm"].get("status") != "PASS"
                or type(revision) is not str or not HEX40.fullmatch(revision)
                or type(assets) is not dict or set(assets) != {"kernel", "rootfs", "firmware"}
                or any(type(v) is not str or not HEX64.fullmatch(v) for v in assets.values())
                or case.get("status") != "PASS" or case.get("case") != "offline-egress"
                or case.get("revision") != revision or case.get("assets") != assets
                or case.get("qemu_network") != "none (observed child command line)"
                or type(case.get("source_tree_sha256")) is not str
                or not HEX64.fullmatch(case["source_tree_sha256"])
                or type(fixture) is not dict or fixture.get("interfaces") != ["lo"]
                or type(fixture.get("denials")) is not dict
                or set(fixture["denials"]) != {"ipv4", "ipv6"}
                or any(v not in {"EPERM", "EACCES", "ENETUNREACH", "EHOSTUNREACH",
                                 "ENETDOWN", "EAFNOSUPPORT", "EPROTONOSUPPORT", "ENODEV"}
                       for v in fixture["denials"].values())
                or case.get("external_collector") is not False):
            raise ValueError("incomplete offline guest evidence")
        if current_commit != revision:
            return {"status": "STALE", "detail": "Offline guest test belongs to another source revision.",
                    "evidence": f"Private guest report: {revision[:12]}"}
        return {"status": "OFFLINE PASS",
                "detail": "KVM guest workload saw only loopback and denied IPv4/IPv6 outbound connections; QEMU -net none observed.",
                "evidence": f"Private guest report: {revision[:12]}; gateway deployment not tested"}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"status": "INVALID", "detail": "Offline guest evidence is missing or inconsistent.",
                "evidence": "No guest network claim made"}
