"""Top-level orchestrator for the BULL multi-agent system.

Every task follows the same path: plan -> policy gate -> execution ->
audit -> verification. A step that fails any gate never executes, and a
run whose outputs trip the auditor or verifier is reported as DENY.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .agents import (
    AuditorAgent,
    CoordinatorAgent,
    ExecutorAgent,
    PolicyAgent,
    VerifierAgent,
)
from .bus import MessageBus
from .contracts import (
    CAP_AUDIT,
    CAP_COORDINATE,
    CAP_EXECUTE,
    CAP_POLICY,
    CAP_VERIFY,
    AgentIdentity,
    AgentResult,
    Envelope,
    Finding,
    Verdict,
)


def _findings_as_dicts(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [
        {"severity": finding.severity.value, "code": finding.code, "summary": finding.summary}
        for finding in findings
    ]


@dataclass
class StepReport:
    """Per-step record of policy verdict, execution and findings."""

    action: str
    policy_verdict: Verdict
    executed: bool = False
    output: Any = None
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "policy_verdict": self.policy_verdict.value,
            "executed": self.executed,
            "output": self.output,
            "findings": _findings_as_dicts(self.findings),
        }


@dataclass
class RunReport:
    """Final result of one multi-agent run."""

    trace_id: str
    verdict: Verdict
    steps: List[StepReport] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.verdict is not Verdict.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "verdict": self.verdict.value,
            "steps": [step.to_dict() for step in self.steps],
            "findings": _findings_as_dicts(self.findings),
            "duration_s": self.duration_s,
        }


class MultiAgentSystem:
    """Coordinator-first pipeline with policy, restricted execution and audit."""

    def __init__(
        self,
        actions: Optional[Dict[str, Callable[..., Any]]] = None,
        policy_rules: Optional[list] = None,
    ) -> None:
        self.bus = MessageBus()
        self.coordinator = CoordinatorAgent(
            AgentIdentity.new("coordinator", [CAP_COORDINATE]), self.bus
        )
        self.policy = PolicyAgent(
            AgentIdentity.new("policy", [CAP_POLICY]), self.bus, rules=policy_rules
        )
        self.executor = ExecutorAgent(
            AgentIdentity.new("executor", [CAP_EXECUTE]), self.bus, actions=actions
        )
        self.auditor = AuditorAgent(AgentIdentity.new("auditor", [CAP_AUDIT]), self.bus)
        self.verifier = VerifierAgent(AgentIdentity.new("verifier", [CAP_VERIFY]), self.bus)

    def register_action(self, name: str, func: Callable[..., Any]) -> None:
        """Register an allow-listed callable with the executor."""
        self.executor.register_action(name, func)

    def run(self, task: Dict[str, Any]) -> RunReport:
        """Execute one task through the full agent pipeline."""
        started = time.perf_counter()
        envelope = Envelope(
            recipient=self.coordinator.agent_id,
            message_type="task",
            payload={"task": task},
        )
        report = RunReport(trace_id=envelope.trace_id, verdict=Verdict.ALLOW)

        planned: AgentResult = self.bus.deliver(envelope)
        report.findings.extend(planned.findings)
        if planned.verdict is not Verdict.ALLOW:
            report.verdict = Verdict.DENY
            report.duration_s = round(time.perf_counter() - started, 6)
            return report

        for step_spec in planned.output["plan"]:
            step_report = self._run_step(envelope, step_spec)
            report.steps.append(step_report)
            report.findings.extend(step_report.findings)
            if step_report.policy_verdict is not Verdict.ALLOW or not step_report.executed:
                report.verdict = Verdict.DENY

        report.duration_s = round(time.perf_counter() - started, 6)
        return report

    def _run_step(self, envelope: Envelope, step_spec: Dict[str, Any]) -> StepReport:
        action = step_spec["action"]
        args = step_spec.get("args", {})

        policy_result: AgentResult = self.bus.deliver(
            envelope.forwarded(
                self.policy.agent_id, "policy.check", {"action": action, "args": args}
            )
        )
        report = StepReport(
            action=action,
            policy_verdict=policy_result.verdict,
            findings=list(policy_result.findings),
        )
        if policy_result.verdict is not Verdict.ALLOW:
            return report

        execution_result: AgentResult = self.bus.deliver(
            envelope.forwarded(
                self.executor.agent_id,
                "action.execute",
                {
                    "action": action,
                    "args": args,
                    "policy_verdict": policy_result.verdict.value,
                },
            )
        )
        report.executed = execution_result.success
        report.output = execution_result.output
        report.findings.extend(execution_result.findings)

        audit_results = self.bus.broadcast(
            envelope.forwarded(
                self.auditor.agent_id,
                "result.audit",
                {"action": action, "output": str(execution_result.output)},
            )
        )
        for result in audit_results:
            report.findings.extend(result.findings)

        verification: AgentResult = self.bus.deliver(
            envelope.forwarded(
                self.verifier.agent_id,
                "result.verify",
                {
                    "action": action,
                    "executed": execution_result.success,
                    "output": execution_result.output,
                },
            )
        )
        report.findings.extend(verification.findings)
        if verification.verdict is not Verdict.ALLOW:
            report.executed = False
            report.output = None
        return report
