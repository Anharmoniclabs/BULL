from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Iterable

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseEvidenceError(RuntimeError):
    pass


def _filename(name: str) -> str:
    if (not isinstance(name, str) or not name or name in {".", ".."}
            or "/" in name or "\\" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise ReleaseEvidenceError("invalid checksum filename")
    return name


def _json_object(path: str | Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseEvidenceError(f"invalid evidence JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseEvidenceError("evidence JSON must be an object")
    return value


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
    output = root / _filename(output_name)
    if output.is_symlink():
        raise ReleaseEvidenceError("checksum output must not be a symlink")
    patterns = tuple(exclude)
    names: list[str] = []
    for path in root.iterdir():
        if not path.is_file() or path.is_symlink() or path.name == output_name:
            continue
        if any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
            continue
        names.append(_filename(path.name))
    if not names:
        raise ReleaseEvidenceError("no release subjects selected for checksums")
    lines = [f"{sha256_file(root / name)}  {name}" for name in sorted(names)]
    # Replace the directory entry, never follow an output symlink or truncate
    # another file through a hard link. The staging directory must be trusted.
    descriptor, temporary = tempfile.mkstemp(prefix=".bull-checksums-", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
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
        if _filename(name) in result:
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
    checksum_path = root / _filename(checksum_name)
    if checksum_path.is_symlink() or not checksum_path.is_file():
        raise ReleaseEvidenceError("checksum inventory must be a regular file")
    expected = read_checksums(checksum_path)
    for name, digest in expected.items():
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ReleaseEvidenceError(f"checksum subject missing or invalid: {name}")
        if sha256_file(path) != digest:
            raise ReleaseEvidenceError(f"checksum mismatch: {name}")
    if complete:
        entries = list(root.iterdir())
        if any(path.is_symlink() or not path.is_file() for path in entries):
            raise ReleaseEvidenceError("release inventory contains a non-regular entry")
        actual = {path.name for path in entries if path.name != checksum_name}
        if actual != set(expected):
            missing = sorted(actual - set(expected))
            extra = sorted(set(expected) - actual)
            raise ReleaseEvidenceError(
                f"checksum inventory mismatch: unlisted={missing} missing={extra}"
            )
    return expected


def inspect_cyclonedx(path: str | Path) -> dict:
    value = _json_object(path)
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
    value = _json_object(path)
    media_type = str(value.get("mediaType", ""))
    if media_type not in {"application/vnd.dev.sigstore.bundle.v0.3+json",
                           "application/vnd.dev.sigstore.bundle+json;version=0.3",
                           "application/vnd.dev.sigstore.bundle+json;version=0.2",
                           "application/vnd.dev.sigstore.bundle+json;version=0.1"}:
        raise ReleaseEvidenceError("attestation is not a Sigstore bundle")
    if not isinstance(value.get("verificationMaterial"), dict):
        raise ReleaseEvidenceError("Sigstore bundle lacks verification material")
    envelope = value.get("dsseEnvelope")
    if not isinstance(envelope, dict) or not envelope.get("payload"):
        raise ReleaseEvidenceError("Sigstore bundle lacks DSSE payload")
    _statement_from_bundle(path)
    signatures = envelope.get("signatures")
    if (not isinstance(signatures, list) or not signatures
            or any(not isinstance(item, dict) or not item.get("sig") for item in signatures)):
        raise ReleaseEvidenceError("Sigstore bundle lacks signatures")
    return {
        "valid": True,
        "cryptographically_verified": False,
        "detail": "structural inspection only: " + media_type,
        "media_type": media_type,
        "sha256": sha256_file(Path(path)),
    }


def _statement_from_bundle(path: str | Path) -> dict:
    value = _json_object(path)
    try:
        envelope = value["dsseEnvelope"]
        if envelope["payloadType"] != "application/vnd.in-toto+json":
            raise ReleaseEvidenceError("invalid DSSE payload type")
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseEvidenceError("invalid DSSE statement") from exc
    if not isinstance(statement, dict) or statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ReleaseEvidenceError("invalid in-toto statement")
    return statement


def predicate_type_from_bundle(path: str | Path) -> str:
    predicate_type = _statement_from_bundle(path).get("predicateType")
    if not isinstance(predicate_type, str) or not predicate_type.startswith("https://"):
        raise ReleaseEvidenceError("attestation predicate type is invalid")
    return predicate_type


def _subjects(statement: dict) -> dict[str, str]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ReleaseEvidenceError("attestation subjects are missing")
    result = {}
    for item in subjects:
        if not isinstance(item, dict) or not isinstance(item.get("digest"), dict):
            raise ReleaseEvidenceError("invalid attestation subject")
        name = _filename(item.get("name"))
        digest = item["digest"].get("sha256")
        if name in result or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise ReleaseEvidenceError("invalid or duplicate attestation subject")
        result[name] = digest
    return result


def _verify_attestations(root: Path, expected_source: str) -> dict:
    # Trust policy comes from the operator/code, never the downloaded record.
    if not re.fullmatch(r"[0-9a-f]{40}", expected_source):
        raise ReleaseEvidenceError("expected source must be a full lowercase commit SHA")
    subjects = verify_checksums(root, "SUBJECT_SHA256SUMS", complete=False)
    required = {"bzImage", "rootfs.ext4", "qboot.rom", "bull-guest.cdx.json", "assets.json", "build.json"}
    if not required.issubset(subjects):
        raise ReleaseEvidenceError("release subjects omit required guest assets")
    provenance = _statement_from_bundle(root / "provenance.sigstore.json")
    sbom = _statement_from_bundle(root / "guest-sbom.sigstore.json")
    if provenance.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ReleaseEvidenceError("unexpected provenance predicate")
    if sbom.get("predicateType") != "https://cyclonedx.org/bom":
        raise ReleaseEvidenceError("unexpected SBOM predicate")
    if _subjects(provenance) != subjects:
        raise ReleaseEvidenceError("provenance subjects do not match release inventory")
    if _subjects(sbom) != {"rootfs.ext4": subjects["rootfs.ext4"]}:
        raise ReleaseEvidenceError("SBOM subject does not match guest rootfs")
    if sbom.get("predicate") != _json_object(root / "bull-guest.cdx.json"):
        raise ReleaseEvidenceError("attested SBOM does not match supplied SBOM")
    for bundle, names, predicate in (
        ("provenance.sigstore.json", sorted(subjects), "https://slsa.dev/provenance/v1"),
        ("guest-sbom.sigstore.json", ["rootfs.ext4"], "https://cyclonedx.org/bom"),
    ):
        for name in names:
            try:
                result = subprocess.run([
                    "gh", "attestation", "verify", str(root / name),
                    "--bundle", str(root / bundle),
                    "--repo", "Anharmoniclabs/BULL",
                    "--signer-workflow", "Anharmoniclabs/BULL/.github/workflows/guest-release.yml",
                    "--source-digest", expected_source,
                    "--predicate-type", predicate, "--deny-self-hosted-runners",
                    "--format", "json",
                ], capture_output=True, text=True, timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ReleaseEvidenceError("attestation verifier unavailable or timed out") from exc
            if result.returncode != 0:
                raise ReleaseEvidenceError(f"cryptographic attestation verification failed: {name}")
            try:
                verified = json.loads(result.stdout)
            except ValueError as exc:
                raise ReleaseEvidenceError("invalid attestation verifier output") from exc
            if not isinstance(verified, list) or not verified:
                raise ReleaseEvidenceError("empty attestation verifier result")
    return {"valid": True, "status": "PASS", "source_commit": expected_source,
            "detail": "fresh GitHub CLI verification of supplied bundles and all release subjects"}


def inspect_release_evidence(directory: str | Path, *, expected_source: str | None = None) -> dict:
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
    cryptographic = {"valid": False, "status": "BLOCKED",
                     "detail": "fresh verification not requested; supply a trusted expected source commit"}
    if expected_source is not None:
        cryptographic = _verify_attestations(root, expected_source)
        # Detect changes while an external verifier was running. Trusted private
        # staging is still required; this is not an atomic installation API.
        if verify_checksums(root, "SHA256SUMS", complete=True) != inventory:
            raise ReleaseEvidenceError("release inventory changed during verification")
    return {
        "format": "bull-release-evidence-v1",
        "cryptographic_verification": cryptographic,
        "inventory": {"valid": True, "files": len(inventory)},
        "sbom": sbom,
        "provenance_bundle": provenance,
        "sigstore_bundle": sbom_bundle,
        "verification_record": {
            "valid": verification_valid,
            "detail": (
                "untrusted workflow record claims successful verification; not cryptographic proof"
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
    inspect.add_argument("--expected-source", help="Trusted source commit; runs fresh gh verification")

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
            report = inspect_release_evidence(args.directory, expected_source=args.expected_source)
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
