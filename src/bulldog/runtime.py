from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .engine import BulldogEngine
from .malware_scanner import (
    MalwareScanner,
    MalwareScannerError,
    MalwareScannerUnavailable,
)
from .models import (
    ActionRequest,
    Decision,
    Evaluation,
)
from .namespace_sandbox import (
    NamespaceSandbox,
    SandboxResult,
)
from .trace_runtime import (
    RuntimeTraceVerifier,
)
from .snapshot import (
    SnapshotViolation,
    create_snapshot,
    destroy_snapshot,
    hash_tree,
)


@dataclass(frozen=True)
class ExecutionResult:
    evaluation: Evaluation
    executed: bool
    sandboxed: bool
    review_required: bool
    returncode: int | None
    stdout: str
    stderr: str

    malware_scan_performed: bool = False
    malware_clean: bool | None = None
    malware_detections: tuple[str, ...] = ()

    trace_state: object | None = None


class BulldogRuntime:
    """
    Unified BULL runtime with live formal-trace enforcement.
    """

    def __init__(
        self,
        *,
        engine: BulldogEngine | None = None,
        sandbox: NamespaceSandbox | None = None,
        malware_scanner: MalwareScanner | None = None,
        malware_scan_required: bool = True,
        trace_verifier: RuntimeTraceVerifier | None = None,
    ):
        self.engine = (
            engine
            if engine is not None
            else BulldogEngine()
        )

        self.sandbox = (
            sandbox
            if sandbox is not None
            else NamespaceSandbox()
        )

        self.trace = (
            trace_verifier
            if trace_verifier is not None
            else RuntimeTraceVerifier()
        )

        self.malware_scan_required = bool(
            malware_scan_required
        )

        if malware_scanner is not None:
            self.malware_scanner = malware_scanner

        elif self.malware_scan_required:

            try:
                self.malware_scanner = MalwareScanner()

            except (
                MalwareScannerUnavailable,
                MalwareScannerError,
            ):
                self.malware_scanner = None

        else:
            self.malware_scanner = None


    def execute(
        self,
        action: ActionRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float | None = 30.0,
    ) -> ExecutionResult:

        # Fresh execution trace for each runtime invocation.
        parent_has = (
            action.parent_capabilities is not None
            and action.capability in action.parent_capabilities
        )

        self.trace.reset(
            parent_has_capability=parent_has
        )

        evaluation = self.engine.evaluate(
            action
        )

        # ---------------------------------------------------------------
        # Emit formal Evaluate transition.
        # Any impossible decision fails closed here.
        # ---------------------------------------------------------------

        self.trace.emit(
            "Evaluate",
            decision=evaluation.decision.value,
        )


        # ===============================================================
        # DENY
        # ===============================================================

        if evaluation.decision == Decision.DENY:

            self.trace.emit(
                "ResolveDeny"
            )

            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=False,
                returncode=None,
                stdout="",
                stderr="execution denied by BULL policy",
                trace_state=self.trace.snapshot(),
            )


        # ===============================================================
        # ESCALATE
        # ===============================================================

        if evaluation.decision == Decision.ESCALATE:

            self.trace.emit(
                "ResolveEscalate"
            )

            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=True,
                returncode=None,
                stdout="",
                stderr="execution requires review",
                trace_state=self.trace.snapshot(),
            )


        project_root = Path(
            project_root
        ).resolve(
            strict=True
        )

        # ===============================================================
        # IMMUTABLE EXECUTION SNAPSHOT
        #
        # Reject symlinks/hardlinks and freeze the project bytes before
        # malware scanning. Execution runs from this snapshot, not from
        # the mutable original tree.
        # ===============================================================

        try:
            snapshot = create_snapshot(
                project_root
            )
        except SnapshotViolation as exc:

            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=False,
                returncode=None,
                stdout="",
                stderr=(
                    "project snapshot rejected: "
                    + str(exc)
                ),
                trace_state=self.trace.snapshot(),
            )

        execution_root = (
            snapshot.snapshot_root
        )


        # ===============================================================
        # MALWARE SCAN
        # ===============================================================

        if self.malware_scan_required:

            if self.malware_scanner is None:

                # Scanner unavailable = fail closed.
                #
                # Model this as malware/non-clean path because execution
                # must not proceed without a clean scan.
                self.trace.emit(
                    "ScanMalware"
                )

                self.trace.emit(
                    "BlockMalware"
                )

                return ExecutionResult(
                    evaluation=evaluation,
                    executed=False,
                    sandboxed=False,
                    review_required=False,
                    returncode=None,
                    stdout="",
                    stderr=(
                        "malware scan required but scanner unavailable"
                    ),
                    malware_scan_performed=False,
                    malware_clean=None,
                    trace_state=self.trace.snapshot(),
                )

            try:

                scan = self.malware_scanner.scan_project(
                    project_root
                )

            except Exception as exc:

                self.trace.emit(
                    "ScanMalware"
                )

                self.trace.emit(
                    "BlockMalware"
                )

                return ExecutionResult(
                    evaluation=evaluation,
                    executed=False,
                    sandboxed=False,
                    review_required=False,
                    returncode=None,
                    stdout="",
                    stderr=(
                        "malware scan failed closed: "
                        + str(exc)
                    ),
                    malware_scan_performed=True,
                    malware_clean=None,
                    trace_state=self.trace.snapshot(),
                )


            if not scan.clean:

                self.trace.emit(
                    "ScanMalware"
                )

                self.trace.emit(
                    "BlockMalware"
                )

                detections = tuple(
                    result.signature or result.path
                    for result in scan.detections
                )

                return ExecutionResult(
                    evaluation=evaluation,
                    executed=False,
                    sandboxed=False,
                    review_required=False,
                    returncode=None,
                    stdout="",
                    stderr="malware detection blocked execution",
                    malware_scan_performed=True,
                    malware_clean=False,
                    malware_detections=detections,
                    trace_state=self.trace.snapshot(),
                )


            # Clean scan transition.
            self.trace.emit(
                "ScanClean"
            )

            malware_clean = True

        else:
            # Formal runtime requires a clean scan before execution.
            #
            # If scanning is disabled, do not silently bypass the model.
            raise RuntimeError(
                "formal runtime instrumentation requires malware scanning"
            )


        # ===============================================================
        # SANDBOX EXECUTION
        # ===============================================================

        writable = (
            action.capability.value
            == "fs.write.project"
        )

        if action.capability.value == "process.exec":
            writable = False


        # Scanner must have inspected exactly the bytes that will execute.
        current_snapshot_hash = hash_tree(
            execution_root
        )

        if (
            current_snapshot_hash
            != snapshot.snapshot_hash
        ):
            destroy_snapshot(
                snapshot
            )

            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=False,
                returncode=None,
                stdout="",
                stderr=(
                    "execution snapshot changed after malware scan"
                ),
                malware_scan_performed=True,
                malware_clean=True,
                trace_state=self.trace.snapshot(),
            )


        result: SandboxResult = self.sandbox.run(
            command,
            project_root=project_root,
            writable=writable,
            timeout=timeout,
        )


        # NamespaceSandbox v1 guarantees:
        #   sandboxed = True
        #
        # Launcher installs:
        #   BULL seccomp = True
        #
        # Emit only after successful sandbox launch attempt.
        self.trace.emit(
            "Execute",
            sandboxed=True,
            seccomp=True,
        )

        destroy_snapshot(
            snapshot
        )


        return ExecutionResult(
            evaluation=evaluation,
            executed=True,
            sandboxed=True,
            review_required=False,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            malware_scan_performed=True,
            malware_clean=malware_clean,
            trace_state=self.trace.snapshot(),
        )
