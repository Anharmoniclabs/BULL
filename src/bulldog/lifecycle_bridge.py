"""Host-owned, single-command bridge from lifecycle admission to production dispatch.

The host must keep the governor/key/dispatcher outside the workload process and
route this command only through this bridge. This covers one explicit EXECUTE
adapter; it does not mediate every BULL effect or authorize arbitrary commands.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .dispatcher import DispatchRequest
from .lifecycle_governance import (
    Effect, EffectRequest, LifecycleGovernor, Outcome, Rejected, ResourceClass,
)
from .profiles import ProductionDispatcher


class GovernedProductionExecution:
    def __init__(self, *, governor: LifecycleGovernor, host_key: object,
                 dispatcher: ProductionDispatcher, actor: str, target: str,
                 dispatch_request: DispatchRequest, command: Sequence[str],
                 project_root: str | Path, timeout: float = 30.0):
        if not isinstance(governor, LifecycleGovernor) or not isinstance(dispatcher, ProductionDispatcher):
            raise TypeError("real lifecycle governor and production dispatcher required")
        if not isinstance(dispatch_request, DispatchRequest) or not command:
            raise ValueError("trusted dispatch request and exact command required")
        self.governor, self.actor, self.target = governor, actor, target
        self.command = tuple(str(part) for part in command)
        self.dispatch_request = dispatch_request
        self.dispatcher = dispatcher
        self.project_root = Path(project_root).resolve(strict=True)
        self.timeout = timeout
        if dispatch_request.authorized_command != self.command:
            raise ValueError("host command and production authorization differ")
        governor.register_resource(actor, target, ResourceClass.PROJECT,
                                   self.command[0], host_key=host_key)
        governor.register_adapter(Effect.EXECUTE, {"argv": list},
                                  {ResourceClass.PROJECT}, self._dispatch, host_key=host_key)

    def _dispatch(self, reference: str, parameters: dict) -> dict:
        if reference != self.command[0] or parameters != {"argv": list(self.command)}:
            raise Rejected("execution adapter binding changed")
        result = self.dispatcher.execute(self.dispatch_request, self.command,
                                         project_root=self.project_root, timeout=self.timeout)
        return {"executed": result.executed,
                "decision": result.evaluation.decision.value,
                "returncode": result.returncode}

    def request(self, *, request_id: str | None = None) -> EffectRequest:
        return EffectRequest.make(self.actor, Effect.EXECUTE, self.target,
                                  {"argv": list(self.command)}, request_id=request_id)

    def submit(self, request: EffectRequest, token: str) -> Outcome:
        if (request.actor != self.actor or request.target != self.target
                or request.kind != Effect.EXECUTE.value
                or request.document()["parameters"] != {"argv": list(self.command)}):
            raise Rejected("request does not match the host-bound execution adapter")
        return self.governor.submit(request, token)
