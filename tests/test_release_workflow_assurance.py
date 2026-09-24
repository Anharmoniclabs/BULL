from pathlib import Path


ATTEST_SHA = "508db95dd578ae2727ebd6217d5ba78e4fbda05d"


def test_guest_release_requires_sbom_provenance_and_verification():
    workflow = Path(".github/workflows/guest-release.yml").read_text(encoding="utf-8")

    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "artifact-metadata: write" in workflow
    assert 'CycloneDX-Buildroot==2.0.0' in workflow
    assert workflow.count(f"uses: actions/attest@{ATTEST_SHA}") == 2
    assert "subject-checksums:" in workflow
    assert "sbom-path:" in workflow
    assert workflow.count("gh attestation verify") >= 2
    assert "bull-guest.cdx.json" in workflow
    assert "provenance.sigstore.json" in workflow
    assert "guest-sbom.sigstore.json" in workflow
    assert "attestation-verification.json" in workflow

    verify_index = workflow.index("- name: Verify signed attestations before release")
    release_index = workflow.index("- name: Create the draft versioned GitHub release")
    assert verify_index < release_index


def test_guest_release_final_inventory_is_verified_before_release():
    workflow = Path(".github/workflows/guest-release.yml").read_text(encoding="utf-8")
    create_index = workflow.index(
        "python3 -m bulldog.release_evidence checksums \\\n"
        '            --directory "$release" --output SHA256SUMS'
    )
    verify_index = workflow.index(
        "python3 -m bulldog.release_evidence verify \\\n"
        '            --directory "$release" --checksum SHA256SUMS'
    )
    release_index = workflow.index("- name: Create the draft versioned GitHub release")
    assert create_index < verify_index < release_index
