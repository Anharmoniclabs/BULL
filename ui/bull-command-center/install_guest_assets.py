#!/usr/bin/env python3
"""Download and verify the published BULL guest assets for Codespaces/KVM use."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

TAG = "guest-2026-09-22"
BASE = f"https://github.com/Anharmoniclabs/BULL/releases/download/{TAG}"
ASSETS = {
    "kernel": {
        "name": "bzImage",
        "sha256": "66bcc80464908d0bbdb5e854eba369d1fa509f71656d9f8baa32073349315daa",
    },
    "rootfs": {
        "name": "rootfs.ext4",
        "sha256": "5a99e8eb82d3acba04efaf23c94c2fad2e01a14b09e9c3b2fe6e07326ccc665b",
    },
    "firmware": {
        "name": "qboot.rom",
        "sha256": "14a5f6679d16477c44ed947a50dae3c772dc77107715c09ab3ac3f5ef2763c98",
    },
}
EXTRA = {
    "SHA256SUMS": "64e013356622668e64868633b705f249cd31a9cf05164793fe197619996e950d",
    "assets.json": "b23d2fe94194f441a7252b6ba2792c2264a5595d213c678ee88376031e06b3af",
    "RELEASE_SCOPE.txt": "656a1ec56144ebb3d7589f91e3f90e78910c8057cf1eccab234c34f4e2bc7f48",
}

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def fetch(name: str, expected: str, destination: Path) -> None:
    if destination.exists():
        actual = digest(destination)
        if actual == expected:
            print(f"{name}: already present and verified", flush=True)
            return
        raise SystemExit(f"{name}: existing file hash mismatch: {actual}")
    tmp = destination.with_suffix(destination.suffix + ".part")
    tmp.unlink(missing_ok=True)
    request = Request(f"{BASE}/{name}", headers={"User-Agent": "BULL-CommandCenter/1"})
    print(f"{name}: downloading from published BULL guest release", flush=True)
    h = hashlib.sha256()
    total = 0
    with urlopen(request, timeout=60) as response, tmp.open("xb") as out:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            out.write(block)
            h.update(block)
            total += len(block)
            if total // (64 * 1024 * 1024) != (total - len(block)) // (64 * 1024 * 1024):
                print(f"{name}: {total / (1024*1024):.0f} MiB", flush=True)
        out.flush()
        os.fsync(out.fileno())
    actual = h.hexdigest()
    if actual != expected:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"{name}: SHA-256 mismatch: {actual}")
    os.replace(tmp, destination)
    destination.chmod(0o600)
    print(f"{name}: VERIFIED sha256={actual}", flush=True)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    os.umask(0o077)
    out = args.output.expanduser().resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.chmod(0o700)

    for item in ASSETS.values():
        fetch(item["name"], item["sha256"], out / item["name"])
    for name, expected in EXTRA.items():
        fetch(name, expected, out / name)

    manifest = {
        key: {"path": str(out / item["name"]), "sha256": item["sha256"]}
        for key, item in ASSETS.items()
    }
    manifest_path = out / "assets-local.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)
    print(f"BULL guest assets ready: {manifest_path}", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
