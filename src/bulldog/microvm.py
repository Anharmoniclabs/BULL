"""Hardware-only MicroVM launcher. Deployment configuration is data, never code."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import uuid

from .secure_fs import open_beneath, trusted_root_fd
from .snapshot import create_snapshot, destroy_snapshot
from .workspace_limits import WorkspaceBudget


class MicroVMError(ValueError):
    pass


DEFAULTS = {
    "MEMORY_MIB": "4096", "CPUS": "2", "ACCEL": "kvm",
    "QEMU": "qemu-system-x86_64", "ENGINE_GUEST": "/bull_runtime/bin/bull-engine",
    "WORKSPACE": "", "RUNTIME_DIR": "", "KERNEL": "", "ROOTFS": "",
    "TIMEOUT_SECONDS": "3600", "DEV_9P": "false", "OUTPUT_DIR": "./project_outputs",
    "OUTPUT_MAX_BYTES": "1048576",
}
ROOT_KEYS = {"APPROVED_WORKSPACE_ROOT", "APPROVED_RUNTIME_ROOT"}
PINNED_KEYS = {"KERNEL", "ROOTFS", "QEMU", "ENGINE_GUEST"}
PREFIX = "BULL_MICROVM_"


def config_file(path: Path) -> dict[str, str]:
    """Only uppercase documented keys and unquoted literal values are accepted."""
    if path.is_symlink():
        raise MicroVMError("deployment configuration may not be a symlink")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
        raise MicroVMError("deployment configuration must be owner-controlled and not group/world writable")
    if info.st_size > 16384:
        raise MicroVMError("deployment configuration is too large")
    result = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"BULL_MICROVM_([A-Z_]+)=([A-Za-z0-9_./:+@%-]*)", line)
        if not match:
            raise MicroVMError(f"invalid literal configuration at line {number}")
        key, value = match.groups()
        if key not in DEFAULTS and key not in ROOT_KEYS:
            raise MicroVMError(f"unknown configuration key: {key}")
        if key in result:
            raise MicroVMError(f"duplicate configuration key: {key}")
        result[key] = value
    return result


def overlap(a: Path, b: Path) -> bool:
    return a.is_relative_to(b) or b.is_relative_to(a)


def restricted_root(raw: str, *, must_exist: bool = True) -> Path:
    if not raw or not Path(raw).is_absolute():
        raise MicroVMError("export and approved roots must be explicit absolute paths")
    path = Path(raw).resolve(strict=must_exist)
    homes = {Path(p.pw_dir).resolve() for p in pwd.getpwall() if p.pw_dir}
    broad = {Path(p) for p in ("/", "/home", "/Users", "/root", "/tmp", "/var", "/var/tmp", "/var/lib", "/var/log", "/var/cache", "/var/spool", "/var/backups", "/var/www", "/srv", "/opt", "/mnt", "/media")}
    forbidden = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/dev", "/proc", "/sys", "/boot", "/run")
    if path in broad or path in homes or path.parent in {Path("/home"), Path("/Users")} or any(path.is_relative_to(Path(p).resolve()) for p in forbidden):
        raise MicroVMError("broad system and home-directory roots are forbidden")
    if must_exist and not path.is_dir():
        raise MicroVMError("export root is not a directory")
    return path


def roots(values: dict[str, str], trusted: dict[str, str]) -> tuple[Path, Path]:
    selected = []
    for key, approval in (("WORKSPACE", "APPROVED_WORKSPACE_ROOT"), ("RUNTIME_DIR", "APPROVED_RUNTIME_ROOT")):
        if not trusted.get(approval):
            raise MicroVMError(f"trusted deployment configuration must specify {approval}")
        allowed = restricted_root(trusted[approval])
        path = restricted_root(values[key])
        if not path.is_relative_to(allowed):
            raise MicroVMError(f"{key} is outside the deployment-approved root")
        selected.append(path)
    if overlap(*selected):
        raise MicroVMError("workspace and runtime must not overlap")
    return selected[0], selected[1]


def engine_path(runtime: Path, guest: str) -> None:
    if not re.fullmatch(r"/bull_runtime/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*", guest):
        raise MicroVMError("engine must be a normalized path beneath /bull_runtime")
    relative = guest.removeprefix("/bull_runtime/")
    with trusted_root_fd(runtime) as fd:
        engine = open_beneath(fd, relative)
        try:
            info = os.fstat(engine)
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise MicroVMError("engine must be an executable regular file")
        finally:
            os.close(engine)
    if not (runtime / relative).resolve(strict=True).is_relative_to(runtime):
        raise MicroVMError("engine escaped runtime")


def bounded(raw: str, name: str, minimum: int, maximum: int) -> int:
    if not re.fullmatch(r"[0-9]{1,8}", raw) or not minimum <= int(raw) <= maximum:
        raise MicroVMError(f"{name} must be between {minimum} and {maximum}")
    return int(raw)


def safe_qemu_path(path: Path) -> str:
    value = str(path)
    if any(c.isspace() or c in ",\x00" for c in value):
        raise MicroVMError("QEMU paths may not contain whitespace, NUL or commas")
    return value


def _directory_size(fd: int) -> int:
    total = 0
    for _root, dirs, files, directory in os.fwalk(".", dir_fd=fd, follow_symlinks=False):
        for name in (*dirs, *files):
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise MicroVMError("output directory may not contain symlinks")
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


@contextmanager
def output_directory(path: Path, protected: list[Path], *, create: bool = False,
                     max_bytes: int | None = None):
    """Pin an empty private export. Diagnostics never create or lock it."""
    path = path.absolute()
    restricted_root(str(path), must_exist=False)
    if any(overlap(path.resolve(), item.resolve()) for item in protected):
        raise MicroVMError("output directory must not overlap workspace, runtime or deployment assets")
    with trusted_root_fd(Path("/")) as root_fd:
        parent = open_beneath(root_fd, str(path.parent).lstrip("/") or ".", directory=True)
    fd = None
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise MicroVMError("output parent must be owner-controlled and not group/world writable")
        if create:
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            if create:
                raise
        else:
            fd = open_beneath(parent, path.name, directory=True)
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise MicroVMError("output directory must be owned by launcher user with mode 0700")
            restricted_root(str(path))
            if create:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if os.listdir(fd):
                raise MicroVMError("output directory must be empty; existing artifacts are never overwritten")
            if create:
                attribute = "user.bull_probe_" + uuid.uuid4().hex
                os.setxattr(fd, attribute, b"1", flags=os.XATTR_CREATE)
                os.removexattr(fd, attribute)
        yield fd
        if create and fd is not None and max_bytes is not None and _directory_size(fd) > max_bytes:
            raise MicroVMError("output directory exceeded its configured byte budget")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def build_image(source: Path, output: Path, *, init: Path | None = None, workspace_outputs: bool = False) -> None:
    """Admit to private scratch; publish a complete image without overwriting."""
    source = source.resolve(strict=True)
    output = output.absolute()
    # Pin every output parent component. Never traverse a caller's symlink.
    with trusted_root_fd(Path("/")) as root_fd:
        parent_fd = open_beneath(root_fd, str(output.parent).lstrip("/"), directory=True)
    try:
        info = os.fstat(parent_fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise MicroVMError("image output parent must be private and owned by the builder")
        if overlap(source, output.parent.resolve(strict=True)):
            raise MicroVMError("image output directory must be outside source tree")
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MicroVMError("image output already exists; replacement is forbidden")
        with tempfile.TemporaryDirectory(prefix=".bull-image-", dir=output.parent) as work:
            scratch = Path(work)
            snapshot = create_snapshot(source, budget=WorkspaceBudget(), scratch_root=scratch)
            try:
                stage = snapshot.snapshot_root
                if workspace_outputs:
                    os.chmod(stage, 0o700)
                    target = stage / "outputs"
                    if target.exists() and (not target.is_dir() or any(target.iterdir())):
                        raise MicroVMError("workspace outputs mountpoint must be an empty directory")
                    target.mkdir(exist_ok=True)
                if init is not None:
                    os.chmod(stage, 0o700)
                    for name in ("sbin", "dev", "proc", "sys", "run", "tmp", "workspace", "bull_runtime"):
                        (stage / name).mkdir(exist_ok=True)
                    os.chmod(stage / "sbin", 0o700)
                    target = stage / "sbin/bull-init"
                    if target.exists():
                        target.unlink()
                    shutil.copyfile(init, target)
                    target.chmod(0o555)
                size = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file())
                image = scratch / "image.ext4"
                with image.open("xb") as stream:
                    stream.truncate(max(128 * 1024**2, size * 2 + 64 * 1024**2))
                command = ["mkfs.ext4", "-q", "-F", "-d", str(stage), str(image)]
                if supervise(command, 120) != 0:
                    raise MicroVMError("ext4 image construction failed")
                image.chmod(0o444)
                with image.open("rb") as stream:
                    os.fsync(stream.fileno())
                # link() is atomic and fails if anything appeared at the destination.
                os.link(image, output.name, dst_dir_fd=parent_fd, follow_symlinks=False)
                os.fsync(parent_fd)
            finally:
                destroy_snapshot(snapshot)
    finally:
        os.close(parent_fd)


def qemu_command(values: dict[str, str], workspace: Path, runtime: Path, run: Path, *, output_fd: int | None = None) -> list[str]:
    cmd = [values["QEMU"], "-M", "microvm,x-option-roms=off", "-accel", "kvm", "-cpu", "host",
           "-m", values["MEMORY_MIB"] + "M", "-smp", values["CPUS"],
           "-nodefaults", "-no-user-config", "-nographic", "-display", "none", "-monitor", "none", "-no-reboot",
           "-kernel", values["KERNEL"], "-append",
           "console=ttyS0 reboot=t panic=1 root=/dev/vda ro init=/sbin/bull-init bull.engine=" + values["ENGINE_GUEST"] + " bull.dev9p=" + values["DEV_9P"]]
    rootfs = Path(values["ROOTFS"])
    disks = [("rootfs", run / "rootfs.ext4" if rootfs.is_dir() else rootfs)]
    if values["DEV_9P"] == "true":
        for name, path in (("workspace", workspace), ("runtime", runtime)):
            cmd += ["-fsdev", f"local,id=bull_{name},path={safe_qemu_path(path)},security_model=none,readonly=on",
                    "-device", f"virtio-9p-device,fsdev=bull_{name},mount_tag=bull_{name}"]
    else:
        disks += [("workspace", run / "workspace.ext4"), ("runtime", run / "runtime.ext4")]
    for name, path in disks:
        cmd += ["-drive", f"id={name},file={safe_qemu_path(path)},format=raw,if=none,readonly=on",
                "-device", f"virtio-blk-device,drive={name}"]
    output = Path(values["OUTPUT_DIR"]).absolute() if output_fd is None else Path(f"/proc/self/fd/{output_fd}")
    cmd += ["-fsdev", f"local,id=bull_outputs,path={safe_qemu_path(output)},security_model=mapped-xattr,readonly=off,fmode=0600,dmode=0700,multidevs=forbid",
            "-device", "virtio-9p-device,fsdev=bull_outputs,mount_tag=bull_outputs"]
    return cmd + ["-net", "none", "-serial", "stdio", "-sandbox",
                  "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]


def supervise(command: list[str], timeout: int, *, pass_fds: tuple[int, ...] = (),
              file_size_limit: int | None = None) -> int:
    """Signal only our exact child, never a process name or the caller's group."""
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    child = None
    previous = {}
    def forward(signum, frame):
        if child is not None and child.poll() is None:
            child.send_signal(signum)
        raise MicroVMError(f"VM interrupted by signal {signum}")
    try:
        # The launcher is single-threaded. Block signals across spawn/handler
        # installation so a signal cannot leave an untracked child behind.
        def prepare_child():
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            if file_size_limit is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_limit, file_size_limit))
        child = subprocess.Popen(command, start_new_session=True, pass_fds=pass_fds,
                                 preexec_fn=prepare_child)
        for signum in signals:
            previous[signum] = signal.signal(signum, forward)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise MicroVMError("VM lifetime limit exceeded")
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=os.environ.get(PREFIX + "CONFIG_FILE"))
    flags = {"workspace": "WORKSPACE", "bull-runtime": "RUNTIME_DIR", "kernel": "KERNEL", "rootfs": "ROOTFS",
             "engine": "ENGINE_GUEST", "memory-mib": "MEMORY_MIB", "cpus": "CPUS", "qemu": "QEMU",
             "accel": "ACCEL", "timeout-seconds": "TIMEOUT_SECONDS", "output-dir": "OUTPUT_DIR",
             "output-max-bytes": "OUTPUT_MAX_BYTES"}
    for flag, key in flags.items():
        parser.add_argument("--" + flag, dest=key)
    parser.add_argument("--dev-9p", action="store_true", default=None)
    parser.add_argument("--print-command", action="store_true")
    args = parser.parse_args(argv)
    def interrupted(signum, frame):
        raise MicroVMError(f"launcher interrupted by signal {signum}")
    old_handlers = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        trusted = config_file(Path(args.config)) if args.config else {}
        if not args.config:
            raise MicroVMError("a trusted deployment configuration is required")
        missing_pins = sorted(PINNED_KEYS.difference(trusted))
        if missing_pins:
            raise MicroVMError("trusted deployment configuration must pin: " + ", ".join(missing_pins))
        overridden = [key for key in PINNED_KEYS
                      if os.environ.get(PREFIX + key) is not None or getattr(args, key) is not None]
        if overridden:
            raise MicroVMError("deployment-pinned settings cannot be overridden: " + ", ".join(sorted(overridden)))
        values = {key: (trusted[key] if key in PINNED_KEYS else os.environ.get(PREFIX + key, trusted.get(key, default)))
                  for key, default in DEFAULTS.items()}
        values.update({key: getattr(args, key) for key in flags.values() if getattr(args, key) is not None})
        if args.dev_9p:
            values["DEV_9P"] = "true"
        if values["DEV_9P"] not in {"true", "false"}:
            raise MicroVMError("DEV_9P must be true or false")
        bounded(values["MEMORY_MIB"], "memory MiB", 4096, 65536)
        bounded(values["CPUS"], "CPUs", 1, 64)
        timeout = bounded(values["TIMEOUT_SECONDS"], "timeout seconds", 1, 86400)
        output_max_bytes = bounded(values["OUTPUT_MAX_BYTES"], "output bytes", 4096, 64 * 1024 * 1024)
        if values["ACCEL"] not in {"auto", "kvm"} or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise MicroVMError("only Linux x86-64/KVM is supported; HVF and ARM are experimental and disabled")
        workspace, runtime = roots(values, trusted)
        if args.config and Path(args.config).resolve(strict=True).is_relative_to(workspace):
            raise MicroVMError("trusted deployment configuration may not be inside the workspace")
        engine_path(runtime, values["ENGINE_GUEST"])
        for key in ("KERNEL", "ROOTFS"):
            if not values[key]:
                raise MicroVMError(key + " is required")
            path = Path(values[key]).resolve(strict=True)
            if not path.is_file() and not (key == "ROOTFS" and path.is_dir()):
                raise MicroVMError(key + " must be a regular image or rootfs directory")
            values[key] = safe_qemu_path(path)
        output = Path(values["OUTPUT_DIR"]).absolute()
        protected = [workspace, runtime, Path(values["KERNEL"]), Path(values["ROOTFS"])]
        if args.config:
            protected.append(Path(args.config))
        with output_directory(output, protected):
            pass
        if values["DEV_9P"] == "true":
            target = workspace / "outputs"
            if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
                raise MicroVMError("development workspace requires an existing empty outputs directory")
        if args.print_command:
            print(json.dumps({"hardware_checked": False, "command": shlex.join(qemu_command(values, workspace, runtime, Path("/PRIVATE_RUN_DIRECTORY")))}, indent=2))
            return 0
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise MicroVMError("KVM unavailable: require read/write /dev/kvm; software fallback is forbidden")
        if not shutil.which(values["QEMU"]):
            raise MicroVMError("QEMU is unavailable")
        with output_directory(output, protected, create=True, max_bytes=output_max_bytes) as output_fd, tempfile.TemporaryDirectory(prefix="bull-microvm-") as directory:
            run = Path(directory)
            if Path(values["ROOTFS"]).is_dir():
                init = Path(__file__).resolve().parents[2] / "microvm/guest/init"
                build_image(Path(values["ROOTFS"]), run / "rootfs.ext4", init=init)
            if values["DEV_9P"] != "true":
                build_image(workspace, run / "workspace.ext4", workspace_outputs=True)
                build_image(runtime, run / "runtime.ext4")
            return supervise(qemu_command(values, workspace, runtime, run, output_fd=output_fd), timeout,
                             pass_fds=(output_fd,), file_size_limit=output_max_bytes)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"bull microvm: {exc}\n")
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
