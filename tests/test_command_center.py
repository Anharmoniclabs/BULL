from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "ui" / "bull-command-center" / "dashboard_server.py"


def load_dashboard():
    spec = importlib.util.spec_from_file_location("bull_command_center", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_command_center_reports_bull_product():
    ui = load_dashboard()
    state = ui.system_state()
    assert state["product"] == "BULL"


def test_command_center_brand_uses_approved_repo_pack():
    ui = load_dashboard()
    manifest = ui.brand_manifest()
    assert manifest["revision"].startswith("approved-")
    assert "bull-primary-dark.svg" in manifest["files"]
    assert "bull-stacked.svg" in manifest["files"]
    assert "bull-mark.svg" in manifest["files"]
    assert "bull-favicon.svg" in manifest["files"]


def test_command_center_repo_path_is_contained():
    ui = load_dashboard()
    assert ui.resolve_repo_path(".") == ROOT
    with pytest.raises(ValueError):
        ui.resolve_repo_path("../../")


def test_command_center_policy_lab_uses_bull_policy():
    ui = load_dashboard()
    result = ui.policy_evaluate(
        {
            "actor": "ui-test",
            "task": "test missing authority",
            "operation": "file.read",
            "resource": "/workspace/BULL/README.md",
            "capability": "fs.read.project",
            "granted_capabilities": [],
            "provenance": ["human"],
        }
    )
    assert result["decision"] == "DENY"
    assert result["hard_block"] is True


def test_command_center_trace_lab_uses_runtime_trace_model():
    ui = load_dashboard()
    result = ui.trace_simulate(
        {
            "events": [
                {"transition": "Evaluate", "data": {"decision": "DENY"}},
                {"transition": "ResolveDeny", "data": {}},
            ]
        }
    )
    assert result["states"][-1]["decision"] == "DENY"
    assert result["states"][-1]["executed"] is False


def test_command_center_agent_scan_is_evidence_not_attribution():
    ui = load_dashboard()
    result = ui.agent_scan(
        {
            "text": (
                "A multi-agent orchestrator delegates to worker agents. "
                "The documentation mentions a botnet C2 only as a threat example."
            )
        }
    )
    assert result["counts"]["agent"] >= 1
    assert result["counts"]["swarm"] >= 1
    assert result["counts"]["botnet"] >= 1
    assert "not attribution" in result["note"].lower()
