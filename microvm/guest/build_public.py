#!/usr/bin/env python3
"""Public, pinned guest recipe. No private baseline, service key, or founder path.

prepare configures public sources without building a VM. databases verifies and
copies operator-fetched official databases. build downloads hash-checked sources
and compiles; assets are published only after build/input checks pass. A completed
build is not boot/security evidence or a demonstrated bit-for-bit reproduction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCES = {
    "buildroot": ("https://github.com/buildroot/buildroot.git", "d5180309b1b66ef3b8eaccca70ad69be8e0729a1"),
    "qboot": ("https://gitlab.com/qemu-project/qboot.git", "8ca302e86d685fa05b16e2b208888243da319941"),
}
DATABASES = ("main.cvd", "daily.cvd", "bytecode.cvd")
PACKAGES = ("BR2_PACKAGE_CLAMAV", "BR2_PACKAGE_BASH", "BR2_PACKAGE_PYTHON3_SSL", "BR2_PACKAGE_PYTHON3_SQLITE",
            "BR2_PACKAGE_UTIL_LINUX_MOUNT", "BR2_PACKAGE_UTIL_LINUX_UNSHARE", "BR2_PACKAGE_LIBSECCOMP",
            "BR2_PACKAGE_OPENSSH_KEY_UTILS", "BR2_DOWNLOAD_FORCE_CHECK_HASHES", "BR2_REPRODUCIBLE")
KERNEL = ("USER_NS", "PID_NS", "NET_NS", "IPC_NS", "SECCOMP_FILTER", "SECURITY_LANDLOCK", "VIRTIO_CONSOLE",
          "VIRTIO_MMIO", "VIRTIO_MMIO_CMDLINE_DEVICES", "VIRTIO_BLK", "CGROUP_PIDS", "MEMCG", "CFS_BANDWIDTH", "EXT4_FS")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def command(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def source(path, name):
    path = path.resolve(strict=True)
    head = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(path), "status", "--porcelain"])
    if head != SOURCES[name][1] or dirty:
        raise ValueError(name + " source must be the clean pinned commit")
    return path


def snapshot(path):
    return {str(p.relative_to(path)): {"symlink": os.readlink(p)} if p.is_symlink() else {"sha256": sha(p)}
            for p in sorted(path.rglob("*")) if p.is_symlink() or p.is_file()}


def selected(config, names):
    lines = set(config.read_text().splitlines())
    missing = [name for name in names if name + "=y" not in lines]
    if missing:
        raise ValueError("required configuration was not selected: " + ", ".join(missing))


def prepare(output, buildroot=None, qboot=None, fetch=False):
    output = Path(os.path.abspath(output))
    if (output.resolve() != output or not re.fullmatch(r"[A-Za-z0-9_./-]+", str(output))
            or output == ROOT or ROOT in output.parents):
        raise ValueError("use a canonical new output path outside Git, without spaces or shell metacharacters")
    if fetch and (buildroot or qboot):
        raise ValueError("choose --fetch or provide both source directories")
    if not fetch and not (buildroot and qboot):
        raise ValueError("provide --buildroot and --qboot, or --fetch")
    if not fetch:
        source(buildroot, "buildroot")
        source(qboot, "qboot")
        if any(p.resolve() == output or p.resolve() in output.parents for p in (buildroot, qboot)):
            raise ValueError("output must be outside the pinned source trees")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    paths = {"buildroot": buildroot, "qboot": qboot}
    if fetch:
        (output / "sources").mkdir()
        for name, (url, revision) in SOURCES.items():
            path = output / "sources" / name
            command(["git", "init", "--quiet", path])
            command(["git", "-C", path, "remote", "add", "origin", url])
            command(["git", "-C", path, "fetch", "--depth", "1", "origin", revision], timeout=300)
            command(["git", "-C", path, "checkout", "--detach", "FETCH_HEAD"])
            paths[name] = path
    paths = {name: source(path, name) for name, path in paths.items()}
    inputs = output / "inputs"
    inputs.mkdir()
    shutil.copytree(HERE / "public/patches", inputs / "patches")
    shutil.copyfile(HERE / "public/linux.config", inputs / "linux.config")
    overlay = inputs / "overlay"
    for name in ("dev", "proc", "sys/fs/cgroup", "run", "tmp", "workspace", "bull_runtime", "sbin", "usr/share", "var/lib/clamav"):
        (overlay / name).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / "init", overlay / "sbin/bull-init")
    (overlay / "sbin/bull-init").chmod(0o755)
    (overlay / "usr/share/clamav").symlink_to("/var/lib/clamav")
    config = (HERE / "public/bull_defconfig").read_text().replace("@OUTPUT@", str(output)).replace("@INPUTS@", str(inputs))
    config += "\n" + (HERE / "production.fragment").read_text()
    (inputs / "bull_defconfig").write_text(config)
    command(["make", "-C", paths["buildroot"], "O=" + str(output / "output"),
             "BR2_DEFCONFIG=" + str(inputs / "bull_defconfig"), "defconfig"], timeout=120)
    selected(output / "output/.config", PACKAGES)
    epoch = subprocess.check_output(["git", "-C", str(paths["buildroot"]), "show", "-s", "--format=%ct", "HEAD"], text=True).strip()
    record = {"format": "bull-public-guest-build-v1", "sources": {name: {"path": str(path), "url": SOURCES[name][0],
              "commit": SOURCES[name][1]} for name, path in paths.items()}, "source_date_epoch": epoch,
              "recipe_sha256": sha(__file__), "inputs": snapshot(inputs), "database_verification": "NOT_RUN",
              "resolved_config_sha256": sha(output / "output/.config"),
              "status": "CONFIGURED_NOT_BUILT", "certified": False}
    save(output / "build.json", record)
    return record


def load(output):
    output = output.resolve(strict=True)
    record = json.loads((output / "build.json").read_text())
    if not isinstance(record, dict) or record.get("format") != "bull-public-guest-build-v1" or record.get("recipe_sha256") != sha(__file__):
        raise ValueError("build recipe changed; prepare a new output directory")
    if snapshot(output / "inputs") != record["inputs"]:
        raise ValueError("build input hashes changed")
    if sha(output / "output/.config") != record["resolved_config_sha256"]:
        raise ValueError("resolved Buildroot configuration changed")
    sources = record.get("sources")
    if not isinstance(sources, dict) or set(sources) != set(SOURCES):
        raise ValueError("build source map must contain the pinned public sources")
    for name, item in sources.items():
        if (not isinstance(item, dict) or set(item) != {"path", "url", "commit"}
                or (item["url"], item["commit"]) != SOURCES[name]):
            raise ValueError("build source identity changed: " + name)
        source(Path(item["path"]), name)
    return output, record


def databases(output, directory, sigtool="sigtool"):
    output, record = load(output)
    if record["database_verification"] != "NOT_RUN":
        raise ValueError("databases are already sealed; prepare a new build to update")
    verified = {}
    destination = output / "inputs/overlay/var/lib/clamav"
    for name in DATABASES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing regular official database: " + name)
        # A checksum chosen by the caller alone is not origin verification.
        command([sigtool, "--verify-cvd", path], timeout=120, capture_output=True)
        before = sha(path)
        shutil.copyfile(path, destination / name)
        if sha(destination / name) != before:
            raise ValueError("database changed while copying")
        command([sigtool, "--verify-cvd", destination / name], timeout=120, capture_output=True)
        (destination / name).chmod(0o644)
        verified[name] = before
    record.update(database_verification="VERIFIED_BY_SIGTOOL", databases=verified, inputs=snapshot(output / "inputs"))
    save(output / "build.json", record)
    return record


def build(output, jobs=2):
    output, record = load(output)
    if record["database_verification"] != "VERIFIED_BY_SIGTOOL":
        raise ValueError("official offline databases must be verified before building")
    selected(output / "output/.config", PACKAGES)
    env = dict(os.environ, SOURCE_DATE_EPOCH=record["source_date_epoch"])
    buildroot = Path(record["sources"]["buildroot"]["path"])
    command(["make", "-C", buildroot, "O=" + str(output / "output"), "-j" + str(jobs)], env=env)
    command(["make", "-C", buildroot, "O=" + str(output / "output"), "host-meson", "host-ninja", "-j" + str(jobs)], env=env)
    host = output / "output/host/bin"
    env["PATH"] = str(host) + os.pathsep + os.environ.get("PATH", os.defpath)
    firmware_build = output / "firmware-build"
    if not firmware_build.exists():
        command([host / "meson", "setup", "--buildtype=release", firmware_build,
                 record["sources"]["qboot"]["path"]], env=env)
    command([host / "ninja", "-C", firmware_build], env=env)
    selected(output / "output/build/linux-7.1.13/.config", ["CONFIG_" + name for name in KERNEL])
    # Re-check provenance after compilers/build helpers finish.
    load(output)
    images = output / "output/images"
    # Buildroot names ext4 through an ext2 file plus a symlink. Copy to a canonical
    # regular release artifact so the deployment checker never accepts a symlink.
    artifacts = output / "artifacts"
    artifacts.mkdir(mode=0o700, exist_ok=False)
    inputs = {"kernel": images / "bzImage", "rootfs": images / "rootfs.ext4", "firmware": firmware_build / "bios.bin"}
    assets = {}
    for name, path in inputs.items():
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing real build output: " + name)
        destination = artifacts / {"kernel": "bzImage", "rootfs": "rootfs.ext4", "firmware": "qboot.rom"}[name]
        shutil.copyfile(path, destination)
        assets[name] = {"path": str(destination), "sha256": sha(destination)}
    save(output / "assets.json", assets)
    record.update(status="BUILT_NOT_BOOT_TESTED", assets=assets,
                  resolved_config_sha256=sha(output / "output/.config"),
                  resolved_kernel_config_sha256=sha(output / "output/build/linux-7.1.13/.config"))
    save(output / "build.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--fetch", action="store_true")
    prepare_parser.add_argument("--buildroot", type=Path)
    prepare_parser.add_argument("--qboot", type=Path)
    database_parser = commands.add_parser("databases")
    database_parser.add_argument("--output", type=Path, required=True)
    database_parser.add_argument("--database-dir", type=Path, required=True)
    database_parser.add_argument("--sigtool", default="sigtool")
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--jobs", type=int, choices=range(1, 17), default=2)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "prepare":
            result = prepare(args.output, args.buildroot, args.qboot, args.fetch)
        elif args.command == "databases":
            result = databases(args.output, args.database_dir, args.sigtool)
        else:
            result = build(args.output, args.jobs)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print("Guest recipe failed: " + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
