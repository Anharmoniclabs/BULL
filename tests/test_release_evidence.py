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
    assert predicate_type_from_bundle(
        tmp_path / "provenance.sigstore.json"
    ) == "https://slsa.dev/provenance/v1"


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
