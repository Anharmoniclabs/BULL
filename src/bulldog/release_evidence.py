from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseEvidenceError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_checksums(
    directory: str | Path,
    output_name: str,
    *,
    exclude: Iterable[str] = (),
) -> Path:
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise ReleaseEvidenceError("release evidence root is not a directory")
    output = root / output_name
    patterns = tuple(exclude)
    names: list[str] = []
    for path in root.iterdir():
        if not path.is_file() or path.is_symlink() or path.name == output_name:
            continue
        if any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
            continue
        names.append(path.name)
    if not names:
        raise ReleaseEvidenceError("no release subjects selected for checksums")
    lines = [f"{sha256_file(root / name)}  {name}" for name in sorted(names)]
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def read_checksums(path: str | Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        if len(raw) < 67 or raw[64:66] != "  ":
            raise ReleaseEvidenceError("invalid checksum line")
        digest, name = raw[:64], raw[66:]
        if not _HEX64.fullmatch(digest):
            raise ReleaseEvidenceError("invalid checksum digest")
        if not name or name in result or "/" in name or "\\" in name or name in {".", ".."}:
            raise ReleaseEvidenceError("invalid checksum filename")
        result[name] = digest
    if not result:
        raise ReleaseEvidenceError("checksum file is empty")
    return result


def verify_checksums(
    directory: str | Path,
    checksum_name: str = "SHA256SUMS",
    *,
    complete: bool = True,
) -> dict[str, str]:
    root = Path(directory).resolve(strict=True)
    expected = read_checksums(root / checksum_name)
    for name, digest in expected.items():
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ReleaseEvidenceError(f"checksum subject missing or invalid: {name}")
        if sha256_file(path) != digest:
            raise ReleaseEvidenceError(f"checksum mismatch: {name}")
    if complete:
        actual = {
            path.name
            for path in root.iterdir()
            if path.is_file() and not path.is_symlink() and path.name != checksum_name
        }
        if actual != set(expected):
            missing = sorted(actual - set(expected))
            extra = sorted(set(expected) - actual)
            raise ReleaseEvidenceError(
                f"checksum inventory mismatch: unlisted={missing} missing={extra}"
            )
    return expected


def inspect_cyclonedx(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise ReleaseEvidenceError(f"invalid SBOM JSON: {exc}") from exc
    if value.get("bomFormat") != "CycloneDX":
        raise ReleaseEvidenceError("SBOM is not CycloneDX JSON")
    spec = str(value.get("specVersion", ""))
    if spec not in {"1.5", "1.6", "1.7"}:
        raise ReleaseEvidenceError("unsupported CycloneDX specification version")
    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise ReleaseEvidenceError("CycloneDX SBOM has no components")
    return {
        "valid": True,
        "detail": f"CycloneDX {spec} with {len(components)} components",
        "spec_version": spec,
        "components": len(components),
        "sha256": sha256_file(Path(path)),
    }


def inspect_sigstore_bundle(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise ReleaseEvidenceError(f"invalid Sigstore bundle JSON: {exc}") from exc
    media_type = str(value.get("mediaType", ""))
    if "sigstore" not in media_type:
        raise ReleaseEvidenceError("attestation is not a Sigstore bundle")
    if not isinstance(value.get("verificationMaterial"), dict):
        raise ReleaseEvidenceError("Sigstore bundle lacks verification material")
    envelope = value.get("dsseEnvelope")
    if not isinstance(envelope, dict) or not envelope.get("payload"):
        raise ReleaseEvidenceError("Sigstore bundle lacks DSSE payload")
    return {
        "valid": True,
        "detail": media_type,
        "media_type": media_type,
        "sha256": sha256_file(Path(path)),
    }


def predicate_type_from_bundle(path: str | Path) -> str:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    payload = value["dsseEnvelope"]["payload"]
    statement = json.loads(base64.b64decode(payload))
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type.startswith("https://"):
        raise ReleaseEvidenceError("attestation predicate type is invalid")
    return predicate_type


def inspect_release_evidence(directory: str | Path) -> dict:
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise ReleaseEvidenceError("release evidence directory is unavailable")
    inventory = verify_checksums(root, "SHA256SUMS", complete=True)
    sbom = inspect_cyclonedx(root / "bull-guest.cdx.json")
    provenance = inspect_sigstore_bundle(root / "provenance.sigstore.json")
    sbom_bundle = inspect_sigstore_bundle(root / "guest-sbom.sigstore.json")
    verification_path = root / "attestation-verification.json"
    try:
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        verification_valid = (
            verification.get("format") == "bull-attestation-verification-v1"
            and verification.get("provenance_verified") is True
            and verification.get("sbom_verified") is True
        )
    except Exception:
        verification = {}
        verification_valid = False
    return {
        "format": "bull-release-evidence-v1",
        "inventory": {"valid": True, "files": len(inventory)},
        "sbom": sbom,
        "provenance_bundle": provenance,
        "sigstore_bundle": sbom_bundle,
        "verification_record": {
            "valid": verification_valid,
            "detail": (
                "workflow recorded successful cryptographic verification"
                if verification_valid
                else "missing or unsuccessful attestation verification record"
            ),
            "record": verification,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m bulldog.release_evidence",
        description="Create and inspect BULL release-evidence artifacts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    checksums = subparsers.add_parser("checksums")
    checksums.add_argument("--directory", type=Path, required=True)
    checksums.add_argument("--output", required=True)
    checksums.add_argument("--exclude", action="append", default=[])

    verify = subparsers.add_parser("verify")
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--checksum", default="SHA256SUMS")
    verify.add_argument("--partial", action="store_true")

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("--directory", type=Path, required=True)
    inspect.add_argument("--json", type=Path)

    predicate = subparsers.add_parser("predicate-type")
    predicate.add_argument("--bundle", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "checksums":
            path = write_checksums(
                args.directory,
                args.output,
                exclude=args.exclude,
            )
            print(path)
            return 0
        if args.command == "verify":
            verify_checksums(
                args.directory,
                args.checksum,
                complete=not args.partial,
            )
            return 0
        if args.command == "inspect":
            report = inspect_release_evidence(args.directory)
            encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
            if args.json is not None:
                args.json.write_text(encoded, encoding="utf-8")
            else:
                print(encoded, end="")
            return 0
        if args.command == "predicate-type":
            print(predicate_type_from_bundle(args.bundle))
            return 0
    except (OSError, ValueError, KeyError, ReleaseEvidenceError) as exc:
        parser.error(str(exc))
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
