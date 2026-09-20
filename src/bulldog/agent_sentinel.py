"""AgentSentinel: heuristic detection of AI-agent-driven execution.

Design doctrine
---------------
No detection is perfect; an adaptive agent can mimic a human on any single
signal. The sentinel therefore:

- fuses multiple independent weak signals into a weighted score,
- is advisory by default (audit/alert), with an optional deny callback,
- never weakens isolation when detection fails — fail-closed containment
  stays in the sandbox layers; the sentinel only *adds* scrutiny.

Signals
-------
1. Environment markers: variables published by common agent harnesses.
2. Process ancestry: walk /proc parent chain for known harness process names.
3. Input cadence: agents inject input in sub-millisecond bursts; humans have
   fat-tailed inter-event gaps. Burstiness is measured, not assumed.
4. I/O tempo: /proc rchar/wchar growth rate far above interactive baselines.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

# env-var name prefix -> weight. Harnesses strip some of these; absence
# means nothing, presence is near-conclusive.
ENV_MARKERS: dict[str, float] = {
    "ANTHROPIC_": 0.55,
    "CLAUDE": 0.55,
    "OPENAI_": 0.50,
    "CURSOR_": 0.50,
    "AIDER_": 0.50,
    "GITHUB_COPILOT": 0.50,
    "CODEIUM": 0.45,
    "CODY_": 0.45,
    "CONTINUE_": 0.40,
    "MCP_": 0.40,
}

HARNNESS_NAME_MARKERS: dict[str, float] = {
    "claude": 0.40,
    "cursor": 0.40,
    "aider": 0.45,
    "copilot": 0.40,
    "codeium": 0.35,
    "mcp": 0.35,
}

# Inter-event gap (seconds) below which input looks machine-injected.
BURST_GAP_SECONDS = 0.005
# Fraction of burst gaps at/above which burstiness is flagged.
BURST_FRACTION_FLAG = 0.9
# rchar+wchar bytes/sec above which tempo looks non-interactive.
TEMPO_FLAG_BYTES_PER_SEC = 50_000_000


@dataclass
class SignalReport:
    score: float
    verdict: str  # "clean" | "suspicious" | "agent"
    signals: dict[str, float] = field(default_factory=dict)


@dataclass
class _IoSample:
    tick: float
    total_bytes: int


class AgentSentinel:
    """Weighted agent-activity detector with audit and deny hooks."""

    def __init__(
        self,
        *,
        suspicious_at: float = 0.35,
        agent_at: float = 0.6,
        on_verdict: Callable[[SignalReport], None] | None = None,
        proc_root: str | Path = "/proc",
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.suspicious_at = suspicious_at
        self.agent_at = agent_at
        self.on_verdict = on_verdict
        self.proc_root = Path(proc_root)
        self.env = env if env is not None else os.environ
        self._input_events: list[float] = []
        self._last_io: _IoSample | None = None

    # -- signal 1: environment markers ----------------------------------
    def env_score(self) -> dict[str, float]:
        hits: dict[str, float] = {}
        for name in self.env:
            for marker, weight in ENV_MARKERS.items():
                if name.upper().startswith(marker):
                    hits[f"env:{name.split('=')[0]}"] = weight
        return hits

    # -- signal 2: process ancestry -------------------------------------
    def ancestry_score(self, max_depth: int = 16) -> dict[str, float]:
        hits: dict[str, float] = {}
        pid = os.getpid()
        for _ in range(max_depth):
            stat_path = self.proc_root / str(pid) / "stat"
            comm_path = self.proc_root / str(pid) / "comm"
            try:
                stat_text = stat_path.read_text("utf-8")
                comm = comm_path.read_text("utf-8").strip().lower()
            except OSError:
                break
            for marker, weight in HARNNESS_NAME_MARKERS.items():
                if marker in comm:
                    hits[f"proc:{comm}"] = weight
            try:
                # comm may contain spaces/parens; split after the last ')'
                ppid = int(stat_text[stat_text.rindex(")") + 2 :].split()[1])
            except (ValueError, IndexError):
                break
            if ppid in (0, pid):
                break
            pid = ppid
        return hits

    # -- signal 3: input cadence ----------------------------------------
    def record_input_event(self, at: float | None = None) -> None:
        """Feed one user/tool-input event timestamp into the cadence model."""
        self._input_events.append(at if at is not None else time.monotonic())
        if len(self._input_events) > 10_000:
            del self._input_events[:5_000]

    def cadence_score(self) -> dict[str, float]:
        if len(self._input_events) < 8:
            return {}
        gaps = [
            b - a
            for a, b in zip(self._input_events, self._input_events[1:])
            if b >= a
        ]
        if not gaps:
            return {}
        burst_fraction = sum(1 for g in gaps if g < BURST_GAP_SECONDS) / len(gaps)
        if burst_fraction >= BURST_FRACTION_FLAG:
            return {"cadence:burst_injection": 0.35}
        if burst_fraction >= 0.5:
            return {"cadence:elevated_burstiness": 0.15}
        return {}

    # -- signal 4: I/O tempo --------------------------------------------
    def io_tempo_score(self) -> dict[str, float]:
        io_path = self.proc_root / "self" / "io"
        try:
            fields = dict(
                line.split(":", 1)
                for line in io_path.read_text("utf-8").splitlines()
            )
            total = int(fields["rchar"]) + int(fields["wchar"])
        except (OSError, KeyError, ValueError):
            return {}
        now = time.monotonic()
        prev, self._last_io = self._last_io, _IoSample(now, total)
        if prev is None or now <= prev.tick:
            return {}
        rate = (total - prev.total_bytes) / (now - prev.tick)
        if rate >= TEMPO_FLAG_BYTES_PER_SEC:
            return {"io:non_interactive_tempo": 0.25}
        return {}

    # -- fusion ----------------------------------------------------------
    def evaluate(self) -> SignalReport:
        signals: dict[str, float] = {}
        for probe in (self.env_score, self.ancestry_score, self.cadence_score, self.io_tempo_score):
            try:
                signals.update(probe())
            except Exception:
                # A failed probe must never crash the guarded workload.
                continue
        # Saturating combine: 1 - prod(1 - w). Independent weak signals add
        # up; no single weak signal can cross the deny line alone.
        remaining = 1.0
        for w in signals.values():
            remaining *= 1.0 - min(max(w, 0.0), 1.0)
        score = 1.0 - remaining
        verdict = (
            "agent"
            if score >= self.agent_at
            else "suspicious"
            if score >= self.suspicious_at
            else "clean"
        )
        report = SignalReport(score=score, verdict=verdict, signals=signals)
        if self.on_verdict is not None and verdict != "clean":
            self.on_verdict(report)
        return report
