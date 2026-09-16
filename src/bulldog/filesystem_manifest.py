from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import stat


class FilesystemManifestViolation(
    RuntimeError
):
    pass


@dataclass(frozen=True)
class ManifestEntry:

    path: str
    kind: str

    device: int
    inode: int

    mode: int

    uid: int
    gid: int

    size: int

    sha256: str | None


@dataclass(frozen=True)
class FilesystemManifest:

    root: str

    device: int

    entries: tuple[
        ManifestEntry,
        ...
    ]


def _hash_file(
    path: Path,
) -> str:

    digest = hashlib.sha256()

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

    return digest.hexdigest()


def build_manifest(
    root: str | Path,
    *,
    require_same_device: bool = True,
    reject_setid: bool = True,
) -> FilesystemManifest:

    root = Path(
        root
    ).resolve(
        strict=True
    )

    root_stat = root.stat()

    root_device = (
        root_stat.st_dev
    )

    entries = []

    for path in sorted(
        root.rglob("*")
    ):

        if ".git" in path.parts:
            continue

        st = path.lstat()

        relative = (
            path
            .relative_to(root)
            .as_posix()
        )

        if stat.S_ISLNK(
            st.st_mode
        ):
            raise FilesystemManifestViolation(
                f"symlink rejected: {relative}"
            )

        if require_same_device and (
            st.st_dev != root_device
        ):
            raise FilesystemManifestViolation(
                "filesystem boundary/mount point rejected: "
                + relative
            )

        if reject_setid and (
            st.st_mode
            & (
                stat.S_ISUID
                | stat.S_ISGID
            )
        ):
            raise FilesystemManifestViolation(
                "setuid/setgid entry rejected: "
                + relative
            )

        if stat.S_ISREG(
            st.st_mode
        ):

            if st.st_nlink > 1:
                raise FilesystemManifestViolation(
                    "hardlink rejected: "
                    + relative
                )

            kind = "file"

            digest = _hash_file(
                path
            )

        elif stat.S_ISDIR(
            st.st_mode
        ):

            kind = "directory"

            digest = None

        else:

            raise FilesystemManifestViolation(
                "special filesystem object rejected: "
                + relative
            )

        entries.append(
            ManifestEntry(
                path=relative,
                kind=kind,
                device=int(
                    st.st_dev
                ),
                inode=int(
                    st.st_ino
                ),
                mode=int(
                    st.st_mode
                ),
                uid=int(
                    st.st_uid
                ),
                gid=int(
                    st.st_gid
                ),
                size=int(
                    st.st_size
                ),
                sha256=digest,
            )
        )

    return FilesystemManifest(
        root=str(root),
        device=int(
            root_device
        ),
        entries=tuple(
            entries
        ),
    )
