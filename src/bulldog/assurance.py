from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import json
import os
from pathlib import Path
from typing import Any

from .production_gate import (
    ProductionRequirements,
    evaluate_production_environment,
)

IMPLEMENTED = "IMPLEMENTED"
PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"
EXTERNAL = "EXTERNAL"

_ALLOWED_PHASES = {"source", "deployment", "release", "external"}


class AssuranceError(RuntimeError):
    pass


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    title: str
    phase: str
    status: str
    detail: str = ""
    evidence: dict[str, Any] | None = None
    frameworks: dict[str, list[str]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.control_id,
            "title": self.title,
            "phase": self.phase,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence or {},
            "frameworks": self.frameworks or {},
        }


@dataclass(frozen=True)
class AssuranceReport:
    profile_id: str
    profile_digest: str
    dynamic: bool
    source_complete: bool
    deployment_complete: bool
    release_complete: bool | None
    certified: bool
    controls: tuple[ControlResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "bull-assurance-report-v1",
            "profile": self.profile_id,
            "profile_digest": self.profile_digest,
            "dynamic": self.dynamic,
            "source_complete": self.source_complete,
            "deployment_complete": self.deployment_complete,
            "release_complete": self.release_complete,
            "certified": self.certified,
            "controls": [item.to_dict() for item in self.controls],
            "scope": (
                "Project-authored control evidence. This report is not an external "
                "certification, legal conformity assessment, SOC report, RMF "
                "authorization, or FIPS validation."
            ),
        }


def _registry_bytes() -> bytes:
    return (
        resources.files("bulldog")
        .joinpath("data/assurance_controls.json")
        .read_bytes()
    )


def load_control_registry() -> dict[str, Any]:
    try:
        raw = json.loads(_registry_bytes())
    except Exception as exc:
        raise AssuranceError(f"unable to load assurance control registry: {exc}") from exc
    if raw.get("schema") != "bull-assurance-control-registry-v1":
        raise AssuranceError("unsupported assurance registry schema")
    profile = raw.get("profile")
    controls = raw.get("controls")
    if not isinstance(profile, dict) or not isinstance(controls, list) or not controls:
        raise AssuranceError("invalid assurance registry structure")
    by_id: dict[str, dict[str, Any]] = {}
    for item in controls:
        if not isinstance(item, dict):
            raise AssuranceError("invalid assurance control")
        control_id = item.get("id")
        phase = item.get("phase")
        if not isinstance(control_id, str) or not control_id or control_id in by_id:
            raise AssuranceError("duplicate or invalid assurance control id")
        if phase not in _ALLOWED_PHASES:
            raise AssuranceError(f"invalid assurance phase for {control_id}")
        by_id[control_id] = item
    for section in (
        "source_required",
        "deployment_required",
        "conditional",
        "release_required",
        "external",
    ):
        values = profile.get(section)
        if not isinstance(values, list) or any(value not in by_id for value in values):
            raise AssuranceError(f"invalid profile section: {section}")
    if set(profile["deployment_required"]) & set(profile["external"]):
        raise AssuranceError("external controls cannot be deployment requirements")
    return raw


def registry_digest(registry: dict[str, Any] | None = None) -> str:
    registry = load_control_registry() if registry is None else registry
    encoded = json.dumps(
        registry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _gate_status(check: dict[str, Any] | None) -> tuple[str, str, dict[str, Any]]:
    if check is None:
        return FAIL, "production gate did not emit expected control evidence", {}
    return str(check["status"]), str(check.get("detail", "")), dict(check.get("evidence") or {})


def _release_results(release_dir: Path | None) -> dict[str, tuple[str, str, dict[str, Any]]]:
    ids = (
        "SUPPLY.CYCLONEDX_GUEST_SBOM",
        "SUPPLY.SLSA_PROVENANCE",
        "SUPPLY.SIGSTORE_ATTESTATION",
        "SUPPLY.ATTESTATION_VERIFIED",
    )
    if release_dir is None:
        return {
            control_id: (
                BLOCKED,
                "release evidence directory not supplied",
                {},
            )
            for control_id in ids
        }
    from .release_evidence import inspect_release_evidence

    try:
        report = inspect_release_evidence(release_dir)
    except Exception as exc:
        return {
            control_id: (FAIL, f"release evidence inspection failed: {exc}", {})
            for control_id in ids
        }
    mapping = {
        "SUPPLY.CYCLONEDX_GUEST_SBOM": "sbom",
        "SUPPLY.SLSA_PROVENANCE": "provenance_bundle",
        "SUPPLY.SIGSTORE_ATTESTATION": "sigstore_bundle",
        "SUPPLY.ATTESTATION_VERIFIED": "verification_record",
    }
    results: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for control_id, key in mapping.items():
        value = report[key]
        results[control_id] = (
            PASS if value["valid"] else FAIL,
            str(value.get("detail", "")),
            dict(value),
        )
    return results


def evaluate_assurance(
    *,
    dynamic: bool = False,
    package_root: str | Path | None = None,
    release_dir: str | Path | None = None,
) -> AssuranceReport:
    registry = load_control_registry()
    profile = registry["profile"]
    by_id = {item["id"]: item for item in registry["controls"]}

    if package_root is None:
        package_root = Path(__file__).resolve().parent

    requirements = ProductionRequirements(
        require_dynamic_backend_attestation=dynamic,
    )
    gate = evaluate_production_environment(
        requirements=requirements,
        package_root=package_root,
    )
    gate_checks = {item["control_id"]: item for item in gate["checks"]}
    host = gate.get("host") or {}
    attestation = host.get("attestation") or {}

    deployment: dict[str, tuple[str, str, dict[str, Any]]] = {}
    direct = {
        "INTEGRITY.SIGNED_POLICY": "INTEGRITY.SIGNED_POLICY",
        "INTEGRITY.SIGNED_RUNTIME": "INTEGRITY.SIGNED_RUNTIME",
        "AUDIT.REMOTE_ANCHOR_CONFIG": "AUDIT.REMOTE_ANCHOR_CONFIG",
        "AUDIT.LEDGER_CONFIG": "AUDIT.LEDGER_CONFIG",
        "SANDBOX.CGROUP_DELEGATION": "SANDBOX.CGROUP_DELEGATION",
    }
    for control_id, gate_id in direct.items():
        deployment[control_id] = _gate_status(gate_checks.get(gate_id))

    seccomp_config = _gate_status(gate_checks.get("SANDBOX.SECCOMP_PROFILE"))
    if seccomp_config[0] != PASS:
        deployment["SANDBOX.SECCOMP_STRICT"] = seccomp_config
    elif not dynamic:
        deployment["SANDBOX.SECCOMP_STRICT"] = (
            BLOCKED,
            "strict profile is configured; run with --dynamic to attest installation",
            seccomp_config[2],
        )
    else:
        ok = bool(attestation.get("seccomp")) and attestation.get("seccomp_profile") == "strict"
        deployment["SANDBOX.SECCOMP_STRICT"] = (
            PASS if ok else FAIL,
            "" if ok else "dynamic attestation did not prove strict seccomp",
            {"attestation": attestation},
        )

    dynamic_fields = {
        "SANDBOX.LANDLOCK": lambda a: bool(a.get("landlock")) and int(a.get("landlock_abi", 0)) >= 1,
        "SANDBOX.NO_NEW_PRIVS": lambda a: a.get("no_new_privs") is True,
        "SANDBOX.NETWORK_ISOLATION": lambda a: a.get("network_isolated") is True,
        "SANDBOX.PID_NAMESPACE": lambda a: a.get("pid") == 1,
    }
    for control_id, predicate in dynamic_fields.items():
        if not dynamic:
            deployment[control_id] = (
                BLOCKED,
                "run with --dynamic to collect live backend attestation",
                {},
            )
        else:
            ok = bool(host.get("dynamic_certified")) and predicate(attestation)
            deployment[control_id] = (
                PASS if ok else FAIL,
                "" if ok else "live backend attestation did not satisfy this control",
                {"attestation": attestation, "dynamic_error": host.get("dynamic_error")},
            )

    policy_check = gate_checks.get("INTEGRITY.SIGNED_POLICY")
    if policy_check is None:
        deployment["APPROVAL.CONSEQUENTIAL_GATE"] = (
            FAIL,
            "policy evidence unavailable",
            {},
        )
    elif policy_check["status"] != PASS:
        deployment["APPROVAL.CONSEQUENTIAL_GATE"] = _gate_status(policy_check)
    elif (policy_check.get("evidence") or {}).get("human_approval") is True:
        deployment["APPROVAL.CONSEQUENTIAL_GATE"] = (
            PASS,
            "",
            {"policy": "signed human_approval configuration present"},
        )
    else:
        deployment["APPROVAL.CONSEQUENTIAL_GATE"] = (
            BLOCKED,
            "signed policy has no human_approval configuration; protected broker effects remain unavailable",
            {},
        )

    release_path = Path(release_dir).resolve() if release_dir is not None else None
    release = _release_results(release_path)

    results: list[ControlResult] = []
    for control in registry["controls"]:
        control_id = control["id"]
        phase = control["phase"]
        if phase == "source":
            status, detail, evidence = (
                IMPLEMENTED,
                "source/test evidence is registered; this is not live deployment proof",
                control.get("evidence") or {},
            )
        elif phase == "deployment":
            status, detail, evidence = deployment.get(
                control_id,
                (FAIL, "no deployment evaluator is registered for this control", {}),
            )
        elif phase == "release":
            status, detail, evidence = release[control_id]
        else:
            status, detail, evidence = (
                EXTERNAL,
                "requires organizational, legal, assessor, or validated-module evidence outside BULL",
                {},
            )
        results.append(
            ControlResult(
                control_id=control_id,
                title=str(control["title"]),
                phase=phase,
                status=status,
                detail=detail,
                evidence=evidence,
                frameworks=control.get("frameworks") or {},
            )
        )

    result_map = {item.control_id: item for item in results}
    source_complete = all(
        result_map[control_id].status in {IMPLEMENTED, PASS}
        for control_id in profile["source_required"]
    )
    deployment_complete = all(
        result_map[control_id].status == PASS
        for control_id in profile["deployment_required"]
    )
    release_complete = (
        None
        if release_dir is None
        else all(
            result_map[control_id].status == PASS
            for control_id in profile["release_required"]
        )
    )
    return AssuranceReport(
        profile_id=str(profile["id"]),
        profile_digest=registry_digest(registry),
        dynamic=dynamic,
        source_complete=source_complete,
        deployment_complete=deployment_complete,
        release_complete=release_complete,
        certified=False,
        controls=tuple(results),
    )
