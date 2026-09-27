#!/usr/bin/env python3
"""Build and boot a disposable networked KVM guest for the actual BULL gateway.

This is a lab image built from Debian's signed package repository. It does not
replace the pinned offline BULL guest or qualify the production systemd unit.
QEMU user networking is restricted; no host nftables rules are changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from tools.deployment_check import probe_kvm, source_identity

NEEDED = ("debootstrap", "mkfs.ext4", "qemu-system-x86_64", "sudo")
EXPECTED = {"gateway_uid", "agent_workload_uid", "direct_gateway_http", "allowed_http", "denied_http", "ipv4_alt_closed",
            "ipv6_alt_closed", "ipv6_web_closed", "filter_drop_counters",
            "denied_dns", "gateway_down_closed", "restart_still_denies"}


def run(args, *, log=None, input_text=None):
    if log is None:
        return subprocess.run(args, check=True, text=True, input=input_text,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900).stdout
    with log.open("a") as output:
        subprocess.run(args, check=True, text=True, stdout=output,
                       stderr=subprocess.STDOUT, timeout=1800)
    return ""


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build(directory, *, resume=False):
    rootfs = directory / "rootfs"
    log = directory / "build.log"
    if resume:
        run(["sudo", "-n", "test", "-d", str(rootfs / "boot")])
        print("Reusing signed-package guest from private lab directory...", flush=True)
    else:
        print("Building disposable signed-package Debian guest (this can take several minutes)...", flush=True)
        run(["sudo", "-n", "debootstrap", "--arch=amd64", "--variant=minbase",
             "--include=linux-image-amd64,python3,nftables,iproute2,util-linux,kmod,passwd",
             "bookworm", str(rootfs), "https://deb.debian.org/debian"], log=log)
    # debootstrap owns /boot as root. Stage the boot assets through sudo into
    # the user's private run directory; QEMU itself remains unprivileged.
    def boot_asset(pattern, name):
        found = run(["sudo", "-n", "find", str(rootfs / "boot"), "-maxdepth", "1",
                     "-type", "f", "-name", pattern, "-print"]).splitlines()
        if len(found) != 1:
            raise RuntimeError("expected one Debian " + name + "; inspect private build.log")
        source = Path(found[0])
        if source.parent != rootfs / "boot":
            raise RuntimeError("boot asset path escaped guest root")
        target = directory / name
        run(["sudo", "-n", "cp", "--", str(source), str(target)])
        run(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), str(target)])
        target.chmod(0o600)
        return target

    kernel = boot_asset("vmlinuz-*", "vmlinuz")
    initrd = boot_asset("initrd.img-*", "initrd.img")
    if resume:
        existing_uid = run(["sudo", "-n", "chroot", str(rootfs), "/usr/bin/id", "-u", "bullgw"]).strip()
        if existing_uid != "23456":
            raise RuntimeError("resumed guest has unexpected bullgw UID")
        if run(["sudo", "-n", "chroot", str(rootfs), "/usr/bin/id", "-u", "bullagent"]).strip() != "23457":
            raise RuntimeError("resumed guest has unexpected bullagent UID")
    else:
        run(["sudo", "-n", "chroot", str(rootfs), "/usr/sbin/groupadd", "--gid", "23456", "bullgw"])
        run(["sudo", "-n", "chroot", str(rootfs), "/usr/sbin/useradd", "--system", "--uid", "23456",
             "--gid", "23456", "--no-create-home", "--shell", "/usr/sbin/nologin", "bullgw"])
        run(["sudo", "-n", "chroot", str(rootfs), "/usr/sbin/groupadd", "--gid", "23457", "bullagent"])
        run(["sudo", "-n", "chroot", str(rootfs), "/usr/sbin/useradd", "--system", "--uid", "23457",
             "--gid", "23457", "--no-create-home", "--shell", "/usr/sbin/nologin", "bullagent"])
    run(["sudo", "-n", "install", "-d", "-m", "0755", str(rootfs / "opt/bull/src"),
         str(rootfs / "etc/bull")])
    run(["sudo", "-n", "cp", "-a", str(ROOT / "src/bulldog"), str(rootfs / "opt/bull/src/")])
    run(["sudo", "-n", "chmod", "0755", str(rootfs / "opt"), str(rootfs / "opt/bull"),
         str(rootfs / "opt/bull/src")])
    run(["sudo", "-n", "chmod", "-R", "a+rX", str(rootfs / "opt/bull/src")])
    for src, dest, mode in (
        (ROOT / "tools/gateway_guest_probe.py", rootfs / "opt/bull/gateway_guest_probe.py", "0644"),
        (ROOT / "tools/gateway_guest_init.sh", rootfs / "sbin/bull-egress-lab-init", "0755"),
        (ROOT / "deploy/egress_redirect.nft", rootfs / "etc/bull/egress_redirect.nft", "0600"),
    ):
        run(["sudo", "-n", "install", "-m", mode, str(src), str(dest)])
    policy = '{"hosts":{"allowed.test":{"methods":["GET"],"paths":["/ok"]}}}\n'
    run(["sudo", "-n", "tee", str(rootfs / "etc/bull/egress_policy.json")], input_text=policy)
    run(["sudo", "-n", "chmod", "0644", str(rootfs / "etc/bull/egress_policy.json")])
    run(["sudo", "-n", "tee", "-a", str(rootfs / "etc/hosts")], input_text="127.0.0.1 allowed.test\n")
    # Keep the evidence private and sparse; mkfs copies files and their modes.
    used = int(run(["sudo", "-n", "du", "-sb", str(rootfs)]).split()[0])
    size = max(3 * 1024**3, used * 2 + 512 * 1024**2)
    image = directory / "gateway-rootfs.ext4"
    if resume and image.exists():
        if image.is_symlink() or image.stat().st_uid != os.getuid():
            raise RuntimeError("refusing to replace unowned or linked lab image")
        image.unlink()
    with image.open("xb") as stream:
        stream.truncate(size)
    run(["sudo", "-n", "mkfs.ext4", "-q", "-F", "-d", str(rootfs), str(image)], log=log)
    image.chmod(0o600)
    return kernel, initrd, image


def boot(directory, kernel, initrd, image, *, init="/sbin/bull-egress-lab-init"):
    command = ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
               "-m", "1536M", "-smp", "2", "-nodefaults", "-no-user-config",
               "-nographic", "-display", "none", "-monitor", "none", "-no-reboot",
               "-kernel", str(kernel), "-initrd", str(initrd),
               "-append", f"console=ttyS0 root=/dev/vda rw init={init}",
               "-drive", f"file={image},format=raw,if=virtio,snapshot=on",
               "-netdev", "user,id=lab,restrict=on", "-device", "virtio-net-pci,netdev=lab",
               "-serial", "stdio", "-sandbox",
               "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
    log = directory / "boot.log"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1, start_new_session=True)
    import selectors
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 240
    result = None
    try:
        with log.open("w") as output:
            while time.monotonic() < deadline:
                if process.poll() is not None and not selector.select(timeout=.2):
                    break
                if not selector.select(timeout=.5):
                    continue
                line = process.stdout.readline()
                if not line:
                    continue
                output.write(line)
                output.flush()
                if "BULL_GATEWAY_KVM_RESULT=" in line:
                    raw = line.split("BULL_GATEWAY_KVM_RESULT=", 1)[1].strip()
                    result = json.loads(raw)
                    break
        if result is None:
            raise RuntimeError("guest produced no result before exit/deadline; inspect private boot.log")
        return result
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-deps", action="store_true")
    parser.add_argument("--resume", type=Path, help="reuse an owned private /tmp/bull-gateway-kvm-* build")
    args = parser.parse_args()
    os.umask(0o077)
    if args.resume:
        directory = args.resume.absolute()
        info = directory.lstat()
        if (directory.parent != Path("/tmp") or not directory.name.startswith("bull-gateway-kvm-")
                or directory.is_symlink() or not directory.is_dir() or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            parser.error("--resume requires an owned private BULL gateway lab directory directly under /tmp")
        previous = json.loads((directory / "setup-report.json").read_text())
        if (previous.get("status") not in {"BLOCKED", "PASS"}
                or previous.get("evidence_directory") != str(directory)):
            parser.error("--resume requires a prior BULL gateway setup report in this private directory")
    else:
        directory = Path(tempfile.mkdtemp(prefix="bull-gateway-kvm-", dir="/tmp"))
    source = source_identity()
    report = {"status": "BLOCKED", "source_commit": source["commit"],
              "source_dirty": source["dirty"], "evidence_directory": str(directory),
              "scope": "disposable Debian KVM gateway lab; not the pinned production guest/systemd unit"}
    print("Evidence directory:", directory, flush=True)
    try:
        if source["dirty"]:
            raise RuntimeError("run from a clean source commit")
        kvm = probe_kvm()
        report["kvm"] = kvm
        if kvm["status"] != "PASS":
            raise RuntimeError("KVM unavailable: " + kvm.get("reason", "unknown"))
        missing = [tool for tool in NEEDED if not shutil.which(tool)]
        if missing and args.install_deps:
            run(["sudo", "-n", "apt-get", "update"], log=directory / "dependencies.log")
            run(["sudo", "-n", "apt-get", "install", "-y", "debootstrap", "qemu-system-x86", "e2fsprogs"],
                log=directory / "dependencies.log")
            missing = [tool for tool in NEEDED if not shutil.which(tool)]
        if missing:
            raise RuntimeError("missing tools: " + ", ".join(missing) + "; retry --install-deps")
        run(["sudo", "-n", "true"])
        if shutil.disk_usage("/tmp").free < 5 * 1024**3:
            raise RuntimeError("at least 5 GiB free in /tmp required for disposable guest build")
        kernel, initrd, image = build(directory, resume=bool(args.resume))
        report["guest_assets"] = {name: digest(path) for name, path in
                                  (("kernel", kernel), ("initrd", initrd), ("rootfs", image))}
        print("Booting networked KVM lab guest (QEMU restrict=on)...", flush=True)
        result = boot(directory, kernel, initrd, image)
        report["guest_result"] = result
        if result.get("status") != "PASS" or set(result.get("checks", {})) != EXPECTED or \
                any(value is not True for value in result["checks"].values()):
            raise RuntimeError("gateway guest probe failed; inspect private boot.log")
        if source_identity() != source:
            raise RuntimeError("source changed during KVM run")
        report["status"] = "PASS"
        print(json.dumps({"status": "PASS", "checks": result["checks"],
                          "scope": report["scope"], "source_commit": source["commit"]}), flush=True)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        report["reason"] = str(exc)[:700]
        print("BLOCKED/FAIL:", report["reason"], file=sys.stderr)
        return 1
    finally:
        path = directory / "setup-report.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        path.chmod(0o600)
        print("Setup report:", path, flush=True)
        print("Keep the disposable image and logs private; no host nftables rules were changed.", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
