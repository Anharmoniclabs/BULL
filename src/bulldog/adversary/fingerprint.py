"""Behavioral model attribution for attacking agents.

BULL fingerprints which model family is driving an attacker by scoring
probe responses against a signature corpus. Signatures are behavioral
(phrase and refusal patterns) rather than network artifacts, because
attacking agents arrive through the workload itself.
"""

from __future__ import annotations

import re
import time
from typing import Callable, Dict, List, Sequence

from .contracts import ModelFingerprint, ProbeResult

# Behavioral signature corpus: model family -> regexes.
MODEL_SIGNATURES: Dict[str, Sequence[str]] = {
    "claude": (
        r"i'?m claude",
        r"as claude",
        r"i (?:cannot|can'?t) (?:browse|access) (?:the )?(?:internet|web)",
        r"i don'?t have (?:the )?ability to (?:browse|access)",
    ),
    "gpt": (
        r"i'?m (?:chatgpt|an ai language model developed by openai)",
        r"as an ai language model",
        r"developed by openai",
    ),
    "gemini": (
        r"i'?m (?:google'?s )?gemini",
        r"i'?m bard",
        r"large language model (?:from|by) google",
    ),
    "llama": (
        r"i'?m llama",
        r"llama model",
    ),
}

_PROBES: Sequence[str] = (
    "who are you?",
    "what are your limitations?",
    "who made you?",
)


def _compile(corpus: Dict[str, Sequence[str]]) -> Dict[str, Sequence]:
    return {
        family: tuple(re.compile(p, re.IGNORECASE) for p in patterns)
        for family, patterns in corpus.items()
    }


class ModelFingerprinter:
    """Scores probe responses to attribute the driving model family."""

    def __init__(self, corpus: Dict[str, Sequence[str]] = None) -> None:
        self._corpus = _compile(corpus or MODEL_SIGNATURES)

    def run_probes(self, respond: Callable[[str], str]) -> List[ProbeResult]:
        probes: List[ProbeResult] = []
        for index, prompt in enumerate(_PROBES):
            started = time.perf_counter()
            try:
                response = str(respond(prompt))
            except Exception:
                response = ""
            latency = (time.perf_counter() - started) * 1000
            probes.append(
                ProbeResult(
                    probe_id=f"probe-{index}",
                    prompt=prompt,
                    response=response,
                    latency_ms=round(latency, 3),
                )
            )
        return probes

    def fingerprint(self, probes: Sequence[ProbeResult]) -> ModelFingerprint:
        scores: Dict[str, int] = {}
        evidence: Dict[str, List[str]] = {}
        for probe in probes:
            for family, patterns in self._corpus.items():
                for pattern in patterns:
                    match = pattern.search(probe.response)
                    if match:
                        scores[family] = scores.get(family, 0) + 1
                        evidence.setdefault(family, []).append(
                            f"{probe.probe_id}: {match.group(0)[:60]}"
                        )
        if not scores:
            return ModelFingerprint(
                family="unknown",
                confidence=0.0,
                evidence=[p.response[:60] for p in probes if p.response],
            )
        total = sum(scores.values())
        best = max(scores, key=lambda family: scores[family])
        return ModelFingerprint(
            family=best,
            confidence=scores[best] / total,
            evidence=evidence.get(best, []),
        )
