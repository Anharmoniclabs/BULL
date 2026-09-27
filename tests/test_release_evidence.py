from __future__ import annotations

import base64
import json

import pytest

from bulldog.release_evidence import (
    ReleaseEvidenceError,
    inspect_release_evidence,
    predicate_type_from_bundle,
    verify_checksums,
    write_checksums,
)


def _bundle(predicate_type: str) -> dict:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.bin", "digest": {"sha256": "0" * 64}}],
        "predicateType": predicate_type,
        "predicate": {},
    }
    payload = base64.b64encode(
        json.dumps(statement, sort_keys=True).encode("utf-8")
    ).decode("ascii")
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"certificate": {"rawBytes": "AA=="}},
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload,
            "signatures": [{"sig": "AA=="}],
        },
    }


def _release_fixture(tmp_path):
    (tmp_path / "artifact.bin").write_bytes(b"artifact")
    (tmp_path / "bull-guest.cdx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "type": "operating-system",
                        "name": "bull-guest",
                        "version": "test",
                    }
                ],
            }
        )
    )
    write_checksums(
        tmp_path,
        "SUBJECT_SHA256SUMS",
        exclude=("*.sigstore.json", "attestation-verification.json", "SHA256SUMS"),
    )
    (tmp_path / "provenance.sigstore.json").write_text(
        json.dumps(_bundle("https://slsa.dev/provenance/v1"))
    )
    (tmp_path / "guest-sbom.sigstore.json").write_text(
        json.dumps(_bundle("https://cyclonedx.org/bom"))
    )
    (tmp_path / "attestation-verification.json").write_text(
        json.dumps(
            {
                "format": "bull-attestation-verification-v1",
                "provenance_verified": True,
                "sbom_verified": True,
            }
        )
    )
    write_checksums(tmp_path, "SHA256SUMS")


def test_release_evidence_inventory_and_attestation_structure(tmp_path):
    _release_fixture(tmp_path)
    report = inspect_release_evidence(tmp_path)
    assert report["inventory"]["valid"] is True
    assert report["sbom"]["valid"] is True
    assert report["provenance_bundle"]["valid"] is True
    assert report["sigstore_bundle"]["valid"] is True
    assert report["verification_record"]["valid"] is True
    assert (
        predicate_type_from_bundle(tmp_path / "provenance.sigstore.json")
        == "https://slsa.dev/provenance/v1"
    )


def test_release_checksum_tamper_is_detected(tmp_path):
    _release_fixture(tmp_path)
    (tmp_path / "artifact.bin").write_bytes(b"changed")
    with pytest.raises(ReleaseEvidenceError, match="checksum mismatch"):
        verify_checksums(tmp_path, "SHA256SUMS", complete=True)


def test_release_inventory_requires_every_file(tmp_path):
    _release_fixture(tmp_path)
    (tmp_path / "unlisted.txt").write_text("late mutation")
    with pytest.raises(ReleaseEvidenceError, match="inventory mismatch"):
        verify_checksums(tmp_path, "SHA256SUMS", complete=True)


def test_self_asserted_verification_is_not_cryptographic_proof(tmp_path):
    _release_fixture(tmp_path)
    report = inspect_release_evidence(tmp_path)
    assert report["verification_record"]["valid"] is True  # historical claim only
    assert report["cryptographic_verification"]["valid"] is False
    assert report["cryptographic_verification"]["status"] == "BLOCKED"
    from bulldog.assurance import _release_results

    assert _release_results(tmp_path)["SUPPLY.ATTESTATION_VERIFIED"][0] == "BLOCKED"


@pytest.mark.parametrize(
    "name", ["../outside", "/tmp/outside", "bad\nname", "bad\x00name"]
)
def test_checksum_output_rejects_unsafe_names(tmp_path, name):
    (tmp_path / "artifact").write_bytes(b"content")
    with pytest.raises(ReleaseEvidenceError, match="filename"):
        write_checksums(tmp_path, name)


def test_checksum_output_does_not_follow_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("preserve")
    (tmp_path / "SHA256SUMS").symlink_to(outside)
    with pytest.raises(ReleaseEvidenceError, match="symlink"):
        write_checksums(tmp_path, "SHA256SUMS")
    assert outside.read_text() == "preserve"


@pytest.mark.parametrize("entry", ["symlink", "directory"])
def test_complete_inventory_rejects_unlisted_nonregular_entries(tmp_path, entry):
    _release_fixture(tmp_path)
    if entry == "symlink":
        (tmp_path / "hidden").symlink_to(tmp_path / "artifact.bin")
    else:
        (tmp_path / "hidden").mkdir()
    with pytest.raises(ReleaseEvidenceError, match="non-regular"):
        inspect_release_evidence(tmp_path)


def _verifiable_fixture(root):
    from bulldog.release_evidence import read_checksums

    _release_fixture(root)
    for name in ("bzImage", "rootfs.ext4", "qboot.rom", "assets.json", "build.json"):
        (root / name).write_bytes(b"fixture only")
    write_checksums(
        root,
        "SUBJECT_SHA256SUMS",
        exclude=("*.sigstore.json", "attestation-verification.json", "SHA256SUMS"),
    )
    subjects = read_checksums(root / "SUBJECT_SHA256SUMS")
    for filename, predicate, bound in (
        ("provenance.sigstore.json", "https://slsa.dev/provenance/v1", subjects),
        (
            "guest-sbom.sigstore.json",
            "https://cyclonedx.org/bom",
            {"rootfs.ext4": subjects["rootfs.ext4"]},
        ),
    ):
        bundle = _bundle(predicate)
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        statement["subject"] = [
            {"name": n, "digest": {"sha256": d}} for n, d in bound.items()
        ]
        if filename.startswith("guest-sbom"):
            statement["predicate"] = json.loads(
                (root / "bull-guest.cdx.json").read_text()
            )
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement).encode()
        ).decode()
        (root / filename).write_text(json.dumps(bundle))
    write_checksums(root, "SHA256SUMS")
    return subjects


def test_fresh_verification_checks_all_subjects_and_pins_trust_policy(
    tmp_path, monkeypatch
):
    from bulldog import release_evidence
    from types import SimpleNamespace

    subjects = _verifiable_fixture(tmp_path)
    calls = []

    def verify(argv, **kwargs):
        calls.append(argv)
        assert kwargs["timeout"] == 120
        assert argv[argv.index("--repo") + 1] == "Anharmoniclabs/BULL"
        assert argv[argv.index("--source-digest") + 1] == "a" * 40
        assert argv[argv.index("--signer-workflow") + 1].endswith(
            "/.github/workflows/guest-release.yml"
        )
        assert "--bundle" in argv and "--deny-self-hosted-runners" in argv
        return SimpleNamespace(returncode=0, stdout='[{"verificationResult": {}}]')

    monkeypatch.setattr(release_evidence.subprocess, "run", verify)
    report = inspect_release_evidence(tmp_path, expected_source="a" * 40)
    assert report["cryptographic_verification"]["valid"] is True
    assert len(calls) == len(subjects) + 1
    assert {__import__("pathlib").Path(call[3]).name for call in calls} == set(subjects)


@pytest.mark.parametrize(
    "result", ["rejected", "missing", "empty", "malformed", "timeout"]
)
def test_verifier_failure_never_passes(tmp_path, monkeypatch, result):
    from bulldog import release_evidence
    from types import SimpleNamespace

    _verifiable_fixture(tmp_path)

    def verify(*args, **kwargs):
        if result == "missing":
            raise FileNotFoundError("gh")
        if result == "timeout":
            raise release_evidence.subprocess.TimeoutExpired("gh", 120)
        return SimpleNamespace(
            returncode=1 if result == "rejected" else 0,
            stdout="invalid" if result == "malformed" else "[]",
        )

    monkeypatch.setattr(release_evidence.subprocess, "run", verify)
    with pytest.raises(ReleaseEvidenceError):
        inspect_release_evidence(tmp_path, expected_source="a" * 40)


@pytest.mark.parametrize("change", ["predicate", "subject", "sbom"])
def test_mismatched_attestation_rejected_before_verifier(tmp_path, monkeypatch, change):
    from bulldog import release_evidence

    _verifiable_fixture(tmp_path)
    path = tmp_path / "guest-sbom.sigstore.json"
    bundle = json.loads(path.read_text())
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    if change == "predicate":
        statement["predicateType"] = "https://attacker.invalid/predicate"
    elif change == "subject":
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
    else:
        statement["predicate"]["components"] = []
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(statement).encode()
    ).decode()
    path.write_text(json.dumps(bundle))
    write_checksums(tmp_path, "SHA256SUMS")

    def unexpected(*args, **kwargs):
        pytest.fail("malformed evidence reached cryptographic verifier")

    monkeypatch.setattr(release_evidence.subprocess, "run", unexpected)
    with pytest.raises(ReleaseEvidenceError):
        inspect_release_evidence(tmp_path, expected_source="a" * 40)


def test_checksum_replacement_does_not_truncate_hard_link_target(tmp_path):
    import os

    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"preserve original")
    os.link(artifact, tmp_path / "SHA256SUMS")
    write_checksums(tmp_path, "SHA256SUMS")
    assert artifact.read_bytes() == b"preserve original"
    verify_checksums(tmp_path)
