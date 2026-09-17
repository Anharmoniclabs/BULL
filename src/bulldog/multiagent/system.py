"""Top-level orchestrator for the BULL multi-agent system.

Every task follows the same path: trusted canary exposure -> plan -> policy gate
-> execution -> audit -> verification. A step that fails any gate never
executes, and a canary crossing any unapproved bus/result boundary hard-stops
the trace independently of heuristic attack recognition.
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
    CAP_HONEYTOKEN,
    CAP_POLICY,
    CAP_VERIFY,
    AgentIdentity,
    AgentResult,
    Envelope,
    Finding,
    Verdict,
)
from .honeytoken import HoneyTokenAgent, HoneyTokenLeak


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
    canary_id: str = ""

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
            "canary_id": self.canary_id,
        }


class MultiAgentSystem:
    """Coordinator-first pipeline with policy, restricted execution and audit.

    ``HoneyTokenAgent`` is host-owned and does not make semantic policy
    decisions. It provides a second kind of evidence: a high-entropy marker may
    appear only in the coordinator's initial trusted-context field. If the exact
    marker or a common encoding reaches any other bus payload or agent result,
    the trace is permanently tripped and denied.
    """

    def __init__(
        self,
        actions: Optional[Dict[str, Callable[..., Any]]] = None,
        policy_rules: Optional[list] = None,
    ) -> None:
        self.bus = MessageBus()
        self.honeytoken = HoneyTokenAgent(
            AgentIdentity.new("honeytoken", [CAP_HONEYTOKEN]),
            self.bus,
        )
        self.coordinator = CoordinatorAgent(
            AgentIdentity.new("coordinator", [CAP_COORDINATE]), self.bus
        )
        self.policy = PolicyAgent(
            AgentIdentity.new("policy", [CAP_POLICY]), self.bus, rules=policy_rules
        )
        self.executor = ExecutorAgent(
            AgentIdentity.new("executor", [CAP_EXECUTE]),
            self.bus,
            actions=actions,
            approver=self.policy,
        )
        self.auditor = AuditorAgent(AgentIdentity.new("auditor", [CAP_AUDIT]), self.bus)
        self.verifier = VerifierAgent(AgentIdentity.new("verifier", [CAP_VERIFY]), self.bus)
        self.bus.set_boundary_guard(self.honeytoken.boundary_guard)

    def register_action(self, name: str, func: Callable[..., Any]) -> None:
        """Register an allow-listed callable with the executor."""
        self.executor.register_action(name, func)

    def guard_external_write(
        self,
        trace_id: str,
        value: Any,
        *,
        channel: str = "memory-write",
    ) -> None:
        """Guard adapter-owned writes that happen after/beside bus delivery.

        Model adapters should call this before committing conversation memory,
        external output, cache entries, or other downstream persistence.
        """
        self.honeytoken.inspect_external_write(trace_id, value, channel=channel)

    def run(self, task: Dict[str, Any]) -> RunReport:
        """Execute one task through the full agent pipeline."""
        started = time.perf_counter()
        envelope = Envelope(
            recipient=self.coordinator.agent_id,
            message_type="task",
            payload={},
        )
        self.honeytoken.mint(
            envelope.trace_id,
            allowed_recipient=self.coordinator.agent_id,
        )
        envelope.payload = {
            "task": task,
            "trusted_context": self.honeytoken.trusted_context(envelope.trace_id),
        }
        report = RunReport(
            trace_id=envelope.trace_id,
            verdict=Verdict.ALLOW,
            canary_id=self.honeytoken.fingerprint(envelope.trace_id)[:16],
        )

        try:
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
        except HoneyTokenLeak as exc:
            report.verdict = Verdict.DENY
            if not any(
                finding.code == exc.finding.code and finding.detail == exc.finding.detail
                for finding in report.findings
            ):
                report.findings.append(exc.finding)
            # Suppress any potentially contaminated step output from the caller.
            for step in report.steps:
                step.executed = False
                step.output = None
            report.duration_s = round(time.perf_counter() - started, 6)
            return report
        finally:
            self.honeytoken.complete(envelope.trace_id)

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
                    "approval_token": policy_result.output.get("token"),
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
            ),
            capability=CAP_AUDIT.name,
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
