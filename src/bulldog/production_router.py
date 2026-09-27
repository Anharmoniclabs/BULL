"""Single fail-closed entrypoint for agent-facing production effects.

Only explicitly implemented operations are routable. Adding an enum or callable
elsewhere does not make it reachable from this boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .approval import ApprovalProof
from .dispatcher import DispatchDenied, DispatchRequest
from .profiles import ProductionDispatcher


@dataclass(frozen=True)
class ProductionEffect:
    operation: str
    request: DispatchRequest
    parameters: dict


class ProductionEffectRouter:
    OPERATIONS = frozenset({"process.execute", "network.request", "secret.read"})

    def __init__(self, dispatcher: ProductionDispatcher):
        if not isinstance(dispatcher, ProductionDispatcher):
            raise TypeError("ProductionEffectRouter requires ProductionDispatcher")
        self.dispatcher = dispatcher

    def dispatch(self, effect: ProductionEffect, *, approval: ApprovalProof | None = None):
        if not isinstance(effect, ProductionEffect) or effect.operation not in self.OPERATIONS:
            raise DispatchDenied("effect has no production adapter; deny by default")
        params = effect.parameters
        if not isinstance(params, dict):
            raise DispatchDenied("effect parameters must be a host-validated object")
        if effect.operation == "process.execute":
            if approval is not None:
                raise DispatchDenied("process approval must be represented by signed policy and dispatch authority")
            if set(params) != {"argv", "project_root", "timeout"}:
                raise DispatchDenied("execute adapter requires exact argv, project_root and timeout")
            argv = params["argv"]
            timeout = params["timeout"]
            if (not isinstance(argv, (tuple, list)) or not argv
                    or any(not isinstance(x, str) or not x for x in argv)
                    or type(timeout) not in {int, float} or not 0 < timeout <= 300):
                raise DispatchDenied("invalid bounded execute parameters")
            root = Path(params["project_root"]).resolve(strict=True)
            return self.dispatcher.execute(effect.request, tuple(argv), project_root=root,
                                           timeout=float(timeout))
        if effect.operation == "network.request":
            if set(params) != {"url", "method", "headers", "body"}:
                raise DispatchDenied("network adapter requires exact URL, method, headers and body")
            return self.dispatcher.fetch_egress(
                url=params["url"], method=params["method"], headers=params["headers"],
                body=params["body"], request=effect.request, approval=approval)
        if set(params) != {"token", "name", "sandbox_id"}:
            raise DispatchDenied("secret adapter requires exact token, name and sandbox identity")
        return self.dispatcher.get_secret(
            token=params["token"], name=params["name"], sandbox_id=params["sandbox_id"],
            request=effect.request, approval=approval)

    @classmethod
    def coverage(cls) -> dict:
        return {
            "routable": sorted(cls.OPERATIONS),
            "default": "DENY",
            "human_approval": ["network.request", "secret.read"],
            "unsupported": ["message.send", "publish", "persist", "replicate",
                            "access.change", "security.change"],
        }
