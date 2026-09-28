#!/usr/bin/env python3
"""Qualify actual BULL systemd gateway units in a separate networked KVM candidate.

Clones a private signed-package Debian lab rootfs. Never edits the pinned
offline guest, its evidence, host nftables, or the original lab directory.
This is a service candidate, not the released BULL Buildroot production image.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.run_codespace_gateway_kvm import (
    EXPECTED,
    boot,
    build,
    digest,
    run,
    probe_kvm,
    source_identity,
)

SYSTEMD_CHECKS = EXPECTED | {"service_units_active"}


def safe_lab(path: Path) -> Path:
    path = path.absolute()
    info = path.lstat()
    if (
        path.parent != Path("/tmp")
        or not path.name.startswith("bull-gateway-kvm-")
        or path.is_symlink()
        or not path.is_dir()
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError(
            "source must be an owned private gateway lab directory in /tmp"
        )
    report_path = path / "setup-report.json"
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError("source report unavailable")
    report = json.loads(report_path.read_text())
    if (
        report.get("status") != "PASS"
        or report.get("evidence_directory") != str(path)
        or report.get("guest_result", {}).get("status") != "PASS"
    ):
        raise ValueError("source must have a passing disposable gateway lab report")
    if (path / "rootfs").is_symlink() or not (path / "rootfs").is_dir():
        raise ValueError("source guest rootfs must be a real directory")
    run(["sudo", "-n", "test", "-d", str(path / "rootfs/boot")])
    return path


def stage_systemd(directory: Path, *, resume: bool = False) -> tuple[Path, Path, Path]:
    rootfs = directory / "rootfs"
    log = directory / "build.log"
    # Never let apt post-install scripts start guest services on the host.
    if not resume:
        policy = rootfs / "usr/sbin/policy-rc.d"
        run(["sudo", "-n", "tee", str(policy)], input_text="#!/bin/sh\nexit 101\n")
        run(["sudo", "-n", "chmod", "0755", str(policy)])
        try:
            for args in (("update",), ("install", "-y", "systemd-sysv")):
                run(
                    [
                        "sudo",
                        "-n",
                        "chroot",
                        str(rootfs),
                        "/usr/bin/env",
                        "DEBIAN_FRONTEND=noninteractive",
                        "/usr/bin/apt-get",
                        *args,
                    ],
                    log=log,
                )
        finally:
            run(["sudo", "-n", "rm", "-f", "--", str(policy)])
    for directory_name in (
        "etc/systemd/system/multi-user.target.wants",
        "usr/lib/python3/dist-packages",
    ):
        run(["sudo", "-n", "install", "-d", "-m", "0755", str(rootfs / directory_name)])
    # Debian's system Python searches dist-packages. The exact service unit's
    # ExecStart is used; its import is checked inside the guest after boot.
    target = rootfs / "usr/lib/python3/dist-packages/bulldog"
    run(["sudo", "-n", "test", "!", "-L", str(target)])
    run(["sudo", "-n", "install", "-d", "-m", "0755", str(target)])
    run(["sudo", "-n", "cp", "-a", str(ROOT / "src/bulldog") + "/.", str(target)])
    run(["sudo", "-n", "chmod", "-R", "a+rX", str(target)])
    units = rootfs / "etc/systemd/system"
    run(
        [
            "sudo",
            "-n",
            "install",
            "-m",
            "0644",
            str(ROOT / "deploy/bull-egress-gateway.service"),
            str(units / "bull-egress-gateway.service"),
        ]
    )
    redirect = """[Unit]
Description=BULL egress nftables redirect (fail-closed)
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/bull/egress_redirect.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
"""
    network = """[Unit]
Description=Disposable BULL KVM candidate network
Requires=bull-egress-redirect.service
After=bull-egress-redirect.service
Before=bull-egress-gateway.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/bull-lab-network
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
"""
    qualify = """[Unit]
Description=Qualify BULL gateway and redirect systemd units in disposable KVM guest
Requires=bull-lab-network.service
Wants=bull-egress-gateway.service
After=bull-lab-network.service bull-egress-gateway.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -u /opt/bull/gateway_guest_probe.py --systemd
StandardOutput=journal+console
StandardError=journal+console
[Install]
WantedBy=multi-user.target
"""
    for name, body in (
        ("bull-egress-redirect.service", redirect),
        ("bull-lab-network.service", network),
        ("bull-lab-qualify.service", qualify),
    ):
        run(["sudo", "-n", "tee", str(units / name)], input_text=body)
        run(["sudo", "-n", "chmod", "0644", str(units / name)])
    run(
        [
            "sudo",
            "-n",
            "install",
            "-m",
            "0755",
            str(ROOT / "tools/gateway_systemd_network.sh"),
            str(rootfs / "usr/local/sbin/bull-lab-network"),
        ]
    )
    for name in (
        "bull-egress-redirect",
        "bull-lab-network",
        "bull-egress-gateway",
        "bull-lab-qualify",
    ):
        link = units / "multi-user.target.wants" / (name + ".service")
        if not resume:
            run(["sudo", "-n", "ln", "-s", "../" + name + ".service", str(link)])
        else:
            run(["sudo", "-n", "test", "-L", str(link)])
    run(["sudo", "-n", "install", "-d", "-m", "0700", str(rootfs / "var/lib/bull")])
    run(["sudo", "-n", "chown", "23456:23456", str(rootfs / "var/lib/bull")])
    run(
        [
            "sudo",
            "-n",
            "chown",
            "root:23456",
            str(rootfs / "etc/bull/egress_policy.json"),
        ]
    )
    run(["sudo", "-n", "chmod", "0640", str(rootfs / "etc/bull/egress_policy.json")])
    return build(directory, resume=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--from-lab", type=Path)
    selection.add_argument(
        "--resume", type=Path, help="retry owned private blocked systemd candidate"
    )
    args = parser.parse_args()
    os.umask(0o077)
    if args.resume:
        directory = args.resume.absolute()
        info = directory.lstat()
        if (
            directory.parent != Path("/tmp")
            or not directory.name.startswith("bull-gateway-systemd-")
            or directory.is_symlink()
            or not directory.is_dir()
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            parser.error("--resume requires an owned private systemd candidate in /tmp")
        prior_path = directory / "setup-report.json"
        if prior_path.is_symlink() or not prior_path.is_file():
            parser.error("missing private setup report")
        previous = json.loads(prior_path.read_text())
        if previous.get("status") != "BLOCKED" or previous.get(
            "evidence_directory"
        ) != str(directory):
            parser.error("--resume requires a blocked candidate setup report")
    else:
        directory = Path(tempfile.mkdtemp(prefix="bull-gateway-systemd-", dir="/tmp"))
    source = source_identity()
    report = {
        "status": "BLOCKED",
        "source_commit": source["commit"],
        "source_dirty": source["dirty"],
        "evidence_directory": str(directory),
        "scope": "disposable Debian networked KVM systemd candidate; not the pinned production image",
    }
    print("Evidence directory:", directory, flush=True)
    try:
        if source["dirty"]:
            raise ValueError("run from a clean source commit")
        lab = safe_lab(args.from_lab) if args.from_lab else None
        kvm = probe_kvm()
        report["kvm"] = kvm
        if kvm.get("status") != "PASS":
            raise ValueError("KVM device/API unavailable")
        if shutil.disk_usage("/tmp").free < (3 if args.resume else 6) * 1024**3:
            raise ValueError("insufficient free space for separate systemd candidate")
        if lab:
            run(
                [
                    "sudo",
                    "-n",
                    "cp",
                    "-a",
                    "--",
                    str(lab / "rootfs"),
                    str(directory / "rootfs"),
                ],
                log=directory / "build.log",
            )
        else:
            run(["sudo", "-n", "test", "-d", str(directory / "rootfs/boot")])
        print("Staging systemd candidate and actual BULL service unit...", flush=True)
        kernel, initrd, image = stage_systemd(directory, resume=bool(args.resume))
        report["guest_assets"] = {
            name: digest(path)
            for name, path in (
                ("kernel", kernel),
                ("initrd", initrd),
                ("rootfs", image),
            )
        }
        print(
            "Booting KVM systemd candidate with restricted user networking...",
            flush=True,
        )
        guest = boot(directory, kernel, initrd, image, init="/lib/systemd/systemd")
        report["guest_result"] = guest
        if (
            guest.get("status") != "PASS"
            or set(guest.get("checks", {})) != SYSTEMD_CHECKS
            or any(v is not True for v in guest["checks"].values())
        ):
            raise ValueError("systemd candidate guest probe incomplete or failed")
        if source_identity() != source:
            raise ValueError("source changed during qualification")
        report["status"] = "PASS"
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "checks": guest["checks"],
                    "source_commit": source["commit"],
                    "scope": report["scope"],
                }
            ),
            flush=True,
        )
        return 0
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        report["reason"] = str(exc)[:700]
        print("BLOCKED/FAIL:", report["reason"], file=sys.stderr, flush=True)
        return 1
    finally:
        target = directory / "setup-report.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        target.chmod(0o600)
        print("Setup report:", target, flush=True)
        print(
            "Keep guest image and logs private; no host nftables changes.", flush=True
        )


if __name__ == "__main__":
    raise SystemExit(main())
