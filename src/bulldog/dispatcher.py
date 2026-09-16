from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .canonicalizer import (
    TrustedExecutionContext,
    canonicalize_action,
)
from .models import Capability
from .runtime import BulldogRuntime


class DispatchDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class DispatchRequest:
    """
    Trusted wrapper around an untrusted model proposal.

    Security-critical identity and provenance live in
    TrustedExecutionContext, not in model-controlled proposal fields.
    """

    proposal: dict
    trusted: TrustedExecutionContext
    granted_capabilities: frozenset[Capability]
    parent_capabilities: frozenset[Capability] | None = None


class CapabilityDispatcher:
    """
    Central BULL reference-monitor entry point.

    Intended flow:

        model proposal
             ↓
        trusted canonicalization
             ↓
        BulldogRuntime
             ↓
        malware gate
             ↓
        sandbox + seccomp
             ↓
        workload

    Model-provided actor/provenance/security-context metadata is ignored
    by the trusted canonicalizer.
    """

    def __init__(
        self,
        *,
        runtime: BulldogRuntime | None = None,
    ):
        self.runtime = (
            runtime
            if runtime is not None
            else BulldogRuntime()
        )

    def canonicalize(
        self,
        request: DispatchRequest,
    ):
        return canonicalize_action(
            request.proposal,
            trusted=request.trusted,
            granted_capabilities=request.granted_capabilities,
            parent_capabilities=request.parent_capabilities,
        )

    def execute(
        self,
        request: DispatchRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float = 30.0,
    ):
        action = self.canonicalize(
            request
        )

        return self.runtime.execute(
            action,
            command,
            project_root=project_root,
            timeout=timeout,
        )
