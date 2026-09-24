from __future__ import annotations

from pathlib import Path

import pytest

from bulldog import assurance
from bulldog.assurance import (
    BLOCKED,
    EXTERNAL,
    IMPLEMENTED,
    PASS,
    evaluate_assurance,
    load_control_registry,
)
from bulldog.production_gate import (
    ProductionRequirements,
    evaluate_production_environment,
)


def test_registry_is_unique_and_profile_references_are_valid():
    registry = load_control_registry()
    controls = registry["controls"]
    ids = [item["id"] for item in controls]
    assert len(ids) == len(set(ids))
    assert registry["profile"]["id"] == "bull-assurance-v1"
    by_id = {item["id"]: item for item in controls}
    for section in (
        "source_required",
        "deployment_required",
        "conditional",
        "release_required",
        "external",
    ):
        assert all(control_id in by_id for control_id in registry["profile"][section])
    assert all(by_id[control_id]["phase"] == "external"
               for control_id in registry["profile"]["external"])


def test_missing_deployment_evidence_never_becomes_pass(monkeypatch):
    for key in tuple(__import__("os").environ):
        if key.startswith("BULL_"):
            monkeypatch.delenv(key, raising=False)

    report = evaluate_assurance(dynamic=False)
    assert report.source_complete is True
    assert report.deployment_complete is False
    assert report.certified is False

    by_id = {item.control_id: item for item in report.controls}
    assert by_id["AUTH.EXACT_COMMAND"].status == IMPLEMENTED
    assert by_id["INTEGRITY.SIGNED_POLICY"].status == BLOCKED
    assert by_id["SANDBOX.SECCOMP_STRICT"].status == BLOCKED
    assert by_id["EXT.ISO27001_ISMS"].status == EXTERNAL


def test_dynamic_attestation_maps_to_required_sandbox_controls(monkeypatch):
    fake_checks = [
        {
            "control_id": control_id,
            "status": PASS,
            "detail": "",
            "evidence": evidence,
        }
        for control_id, evidence in (
            ("INTEGRITY.SIGNED_POLICY", {"human_approval": True}),
            ("INTEGRITY.SIGNED_RUNTIME", {}),
            ("AUDIT.REMOTE_ANCHOR_CONFIG", {}),
            ("AUDIT.LEDGER_CONFIG", {}),
            ("SANDBOX.CGROUP_DELEGATION", {}),
            ("SANDBOX.SECCOMP_PROFILE", {"configured": "strict"}),
            ("STORAGE.SNAPSHOT_SCRATCH", {}),
            ("SANDBOX.BACKEND_CERTIFICATION", {}),
        )
    ]
    fake_host = {
        "dynamic_certified": True,
        "dynamic_error": None,
        "attestation": {
            "pid": 1,
            "no_new_privs": True,
            "seccomp": True,
            "seccomp_profile": "strict",
            "seccomp_rules": 70,
            "landlock": True,
            "landlock_abi": 6,
            "network_interfaces": ["lo"],
            "network_isolated": True,
            "runtime_root": "/bull_runtime",
        },
    }

    monkeypatch.setattr(
        assurance,
        "evaluate_production_environment",
        lambda **kwargs: {
            "format": "bull-production-gate-evidence-v1",
            "passed": True,
            "checks": fake_checks,
            "failures": [],
            "host": fake_host,
        },
    )

    report = evaluate_assurance(dynamic=True)
    assert report.deployment_complete is True
    by_id = {item.control_id: item for item in report.controls}
    for control_id in (
        "SANDBOX.SECCOMP_STRICT",
        "SANDBOX.LANDLOCK",
        "SANDBOX.NO_NEW_PRIVS",
        "SANDBOX.NETWORK_ISOLATION",
        "SANDBOX.PID_NAMESPACE",
        "APPROVAL.CONSEQUENTIAL_GATE",
    ):
        assert by_id[control_id].status == PASS


def test_production_gate_emits_structured_seccomp_evidence(monkeypatch):
    monkeypatch.setenv("BULL_SECCOMP_PROFILE", "strict")
    requirements = ProductionRequirements(
        require_remote_audit_anchor=False,
        require_backend_certification=False,
        require_integrity_manifest=False,
        require_signed_integrity_manifest=False,
        require_signed_policy_bundle=False,
        require_snapshot_scratch=False,
        require_audit_ledger_path=False,
        require_delegated_cgroup=False,
        require_strict_seccomp=True,
    )
    report = evaluate_production_environment(requirements, package_root=Path("."))
    assert report["passed"] is True
    assert report["checks"] == [
        {
            "control_id": "SANDBOX.SECCOMP_PROFILE",
            "status": PASS,
            "detail": "",
            "evidence": {"configured": "strict"},
        }
    ]


def test_cli_parser_exposes_assurance_status():
    from bulldog.cli import build_parser

    args = build_parser().parse_args(["assurance", "status", "--dynamic"])
    assert args.command == "assurance"
    assert args.assurance_command == "status"
    assert args.dynamic is True
    assert callable(args.handler)
