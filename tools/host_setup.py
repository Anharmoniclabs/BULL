#!/usr/bin/env python3
"""Administrator provisioning of a BULL cgroup and optional KVM group access.

Run explicitly with sudo on Linux. Only a dedicated subtree is delegated.
Parent controllers require a separate opt-in if not already enabled. No remount,
world-writable device, privileged container, or software-emulation fallback.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess

CGROUP_ROOT = Path("/sys/fs/cgroup")
CONTROLLERS = {"cpu", "memory", "pids"}


def cgroup_parent(uid):
    if type(uid) is not int or uid <= 0:
        raise ValueError("a non-root service UID is required")
    return CGROUP_ROOT / ("bull-" + str(uid))


def provision_cgroup(user, *, enable_parent=False):
    parent = cgroup_parent(user.pw_uid)
    if not (CGROUP_ROOT / "cgroup.controllers").is_file():
        raise ValueError("cgroup v2 is unavailable")
    available = set((CGROUP_ROOT / "cgroup.controllers").read_text().split())
    if not CONTROLLERS <= available:
        raise ValueError("host does not expose cpu, memory and pids controllers")
    enabled = set((CGROUP_ROOT / "cgroup.subtree_control").read_text().split())
    missing = CONTROLLERS - enabled
    if missing:
        if not enable_parent:
            raise ValueError("parent controllers are disabled; an administrator may use --enable-parent-controllers")
        (CGROUP_ROOT / "cgroup.subtree_control").write_text(" ".join("+" + c for c in sorted(missing)))
    if parent.exists():
        if parent.is_symlink() or parent.stat().st_uid != user.pw_uid:
            raise ValueError("existing BULL cgroup belongs to a different UID")
    else:
        parent.mkdir(mode=0o700)
        os.chown(parent, user.pw_uid, user.pw_gid)
    if (parent / "cgroup.procs").read_text().strip():
        raise ValueError("BULL parent contains processes; use its coordinator child")
    (parent / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
        os.chown(parent / name, user.pw_uid, user.pw_gid)
    coordinator = parent / "coordinator"
    coordinator.mkdir(mode=0o700, exist_ok=True)
    os.chown(coordinator, user.pw_uid, user.pw_gid)
    os.chown(coordinator / "cgroup.procs", user.pw_uid, user.pw_gid)
    return parent


def system_command(name, *args):
    command = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not command:
        raise ValueError("required administrator command is missing: " + name)
    subprocess.run([command, *args], check=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def grant_kvm(user):
    info = Path("/dev/kvm").lstat()
    if not stat.S_ISCHR(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (10, 232):
        raise ValueError("expected the actual /dev/kvm character device")
    if info.st_mode & 0o007:
        raise ValueError("KVM device has unexpected public access; administrator review required")
    if info.st_mode & 0o060 != 0o060:
        raise ValueError("KVM device group lacks read/write permission")
    if info.st_gid == 0:
        raise ValueError("KVM requires a dedicated non-root device group; refusing root-group membership")
    try:
        group = grp.getgrgid(info.st_gid).gr_name
    except KeyError:
        group = "bull-kvm-" + str(info.st_gid)
        system_command("groupadd", "--gid", str(info.st_gid), group)
    if info.st_gid not in os.getgrouplist(user.pw_name, user.pw_gid):
        system_command("usermod", "--append", "--groups", group, user.pw_name)
    return group


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", required=True, help="normal operator/service account")
    parser.add_argument("--grant-kvm", action="store_true")
    parser.add_argument("--enable-parent-controllers", action="store_true")
    parser.add_argument("--enter-shell", action="store_true", help="enter an unprivileged Bash with refreshed groups inside the delegated cgroup")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError("administrator provisioning requires sudo")
        user = pwd.getpwnam(args.user)
        cgroup_parent(user.pw_uid)
        group = grant_kvm(user) if args.grant_kvm else None
        parent = provision_cgroup(user, enable_parent=args.enable_parent_controllers)
        print(json.dumps({"status": "PROVISIONED_NOT_TESTED", "cgroup_parent": str(parent),
                          "kvm_group": group, "operator": user.pw_name, "certified": False}), flush=True)
        if args.enter_shell:
            (parent / "coordinator/cgroup.procs").write_text(str(os.getpid()))
            os.initgroups(user.pw_name, user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
            environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": user.pw_dir,
                           "USER": user.pw_name, "LOGNAME": user.pw_name,
                           "TERM": os.environ.get("TERM", "xterm"), "BULL_CGROUP_PARENT": str(parent)}
            print("BULL operator shell: run deployment checks here; exit returns to the previous shell.", flush=True)
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"], environment)
        return 0
    except (OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        print("Host provisioning blocked: " + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
