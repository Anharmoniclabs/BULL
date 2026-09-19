"""Build a no-clobber root filesystem from a bounded admitted tree."""
import argparse
from pathlib import Path
import signal
import subprocess

from .microvm import build_image, MicroVMError


def interrupted(signum, frame):
    raise MicroVMError(f"image build interrupted by signal {signum}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        build_image(args.source, args.output, init=Path(__file__).resolve().parents[2] / "microvm/guest/init")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"build-ext4: {exc}\n")
    print(args.output)
    return 0
