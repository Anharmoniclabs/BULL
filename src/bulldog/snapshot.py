from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import shutil
import tempfile


class SnapshotViolation(
    RuntimeError
):
    pass


@dataclass(frozen=True)
class ProjectSnapshot:
    source_root: Path
    snapshot_root: Path
    source_hash: str
    snapshot_hash: str


def _validate_tree(
    root: Path,
) -> None:

    for path in root.rglob("*"):

        if ".git" in path.parts:
            continue

        try:
            stat = path.lstat()
        except FileNotFoundError:
            raise SnapshotViolation(
                f"tree changed during validation: {path}"
            )

        if path.is_symlink():
            raise SnapshotViolation(
                f"symlink rejected: {path}"
            )

        if path.is_file():

            if stat.st_nlink > 1:
                raise SnapshotViolation(
                    f"hardlinked file rejected: {path}"
                )


def hash_tree(
    root: str | Path,
) -> str:

    root = Path(
        root
    ).resolve(
        strict=True
    )

    digest = hashlib.sha256()

    for path in sorted(
        root.rglob("*")
    ):

        if ".git" in path.parts:
            continue

        if path.is_symlink():
            raise SnapshotViolation(
                f"symlink rejected: {path}"
            )

        relative = (
            path.relative_to(
                root
            )
            .as_posix()
            .encode("utf-8")
        )

        digest.update(
            b"P:"
            + relative
            + b"\0"
        )

        if path.is_file():

            stat = path.stat()

            if stat.st_nlink > 1:
                raise SnapshotViolation(
                    f"hardlinked file rejected: {path}"
                )

            digest.update(
                b"F:"
            )

            with path.open(
                "rb"
            ) as fh:

                while True:
                    block = fh.read(
                        1024 * 1024
                    )

                    if not block:
                        break

                    digest.update(
                        block
                    )

        elif path.is_dir():

            digest.update(
                b"D:"
            )

    return digest.hexdigest()


def create_snapshot(
    source_root: str | Path,
) -> ProjectSnapshot:

    source_root = Path(
        source_root
    ).resolve(
        strict=True
    )

    _validate_tree(
        source_root
    )

    source_hash_before = (
        hash_tree(
            source_root
        )
    )

    snapshot_parent = Path(
        tempfile.mkdtemp(
            prefix="bull_snapshot_",
            dir="/tmp",
        )
    )

    snapshot_root = (
        snapshot_parent
        / "project"
    )

    shutil.copytree(
        source_root,
        snapshot_root,
        symlinks=False,
        ignore=shutil.ignore_patterns(
            ".git"
        ),
    )

    source_hash_after = (
        hash_tree(
            source_root
        )
    )

    if (
        source_hash_after
        != source_hash_before
    ):
        shutil.rmtree(
            snapshot_parent,
            ignore_errors=True,
        )

        raise SnapshotViolation(
            "source tree changed while snapshot was created"
        )

    snapshot_hash = (
        hash_tree(
            snapshot_root
        )
    )

    if snapshot_hash != source_hash_before:

        shutil.rmtree(
            snapshot_parent,
            ignore_errors=True,
        )

        raise SnapshotViolation(
            "snapshot hash does not match source hash"
        )

    return ProjectSnapshot(
        source_root=source_root,
        snapshot_root=snapshot_root,
        source_hash=source_hash_before,
        snapshot_hash=snapshot_hash,
    )


def destroy_snapshot(
    snapshot: ProjectSnapshot,
) -> None:

    shutil.rmtree(
        snapshot.snapshot_root.parent,
        ignore_errors=True,
    )
