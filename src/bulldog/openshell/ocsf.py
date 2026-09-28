"""Correlate OpenShell OCSF events with BULL decisions into one audit trail.

OpenShell's supervisor pushes its OCSF events to the gateway, where
``openshell logs <sandbox>`` returns them in OCSF shorthand::

    [1790618400.334] [sandbox] [OCSF ] [ocsf] HTTP:POST [MED] DENIED POST
    http://host:40605/v1/records [policy:api engine:middleware]
    [failed:false transformed:false reason:middleware_denied:bull-governance:bull_approval_required]

Each proxied request yields one event per enforcing layer: ``engine:l7``
(OpenShell's own policy) and ``engine:middleware`` (BULL). BULL's hash-chained
ledger records its own decision for the same request. Joining the two, plus
what the destination actually received, answers per action: what OpenShell
decided, what BULL decided, and whether the effect happened.
"""

from __future__ import annotations

from datetime import datetime
import re

_SHORTHAND = re.compile(
    r"^\[(?P<time>\d+(?:\.\d+)?)\]\s+\[sandbox\]\s+\[OCSF\s*\]\s+\[ocsf\]\s+"
    r"HTTP:(?P<verb>[A-Z]+)\s+\[(?P<severity>[A-Z]+)\]\s+(?P<action>ALLOWED|DENIED)\s+"
    r"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+\[policy:(?P<policy>[^ \]]*)\s+engine:(?P<engine>[a-z0-9_]+)\]"
    r"(?:\s+\[(?P<detail>[^\]]*)\])?")


def parse_shorthand(lines, sandbox: str) -> list[dict]:
    """HTTP events from ``openshell logs`` output for one sandbox."""
    events = []
    for line in lines:
        match = _SHORTHAND.match(line.strip())
        if not match:
            continue
        detail = match["detail"] or ""
        reason = detail.split("reason:", 1)[1] if "reason:" in detail else ""
        events.append({
            "sandbox": sandbox, "time": float(match["time"]), "method": match["method"],
            "url": match["url"], "action": match["action"], "engine": match["engine"],
            "policy": match["policy"], "reason": reason,
        })
    return events


def _target(url: str) -> str:
    # OpenShell v0.1.2 hands middleware scheme "https" on plaintext relays while
    # its OCSF events say "http"; compare host:port/path only.
    return url.split("://", 1)[-1]


def _epoch(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp).timestamp()


def _take(candidates: list[dict], used: set[int], when: float, window: float):
    """Nearest unused candidate within ``window`` seconds; ``used`` holds ids."""
    best = None
    for item in candidates:
        if id(item) in used or abs(item["time"] - when) > window:
            continue
        if best is None or abs(item["time"] - when) < abs(best["time"] - when):
            best = item
    if best is not None:
        used.add(id(best))
    return best


def correlate(ledger_records: list[dict], events: list[dict], receipts: list[dict] | None = None,
              *, window: float = 3.0) -> dict:
    """Join every BULL egress decision to OpenShell's events and the effect.

    ``receipts`` are what the destination recorded: dicts with ``time``,
    ``method``, ``url``. Returns rows plus a summary of agreement.
    """
    receipts = receipts or []
    used = {"l7": set(), "middleware": set(), "effect": set()}
    rows = []
    for record in ledger_records:
        if record.get("event_type") != "openshell_egress":
            continue
        data = record["data"]
        when = _epoch(record["timestamp"])

        def same(item, engine=None):
            return (item.get("sandbox", data["sandbox"]) == data["sandbox"]
                    and item["method"] == data["method"]
                    and _target(item["url"]) == _target(data["resource"])
                    and (engine is None or item["engine"] == engine))

        l7 = _take([e for e in events if same(e, "l7")], set(), when, window)
        mw_candidates = [e for e in events if same(e, "middleware")]
        middleware = _take(mw_candidates, used["middleware"], when, window)
        effect_candidates = [r for r in receipts if r["method"] == data["method"]
                             and _target(r["url"]) == _target(data["resource"])]
        effect = _take(effect_candidates, used["effect"], when, window)
        openshell_says = middleware["action"] if middleware else None
        rows.append({
            "ledger_hash": record.get("record_hash"),
            "sandbox": data["sandbox"], "request_id": data.get("request_id"),
            "method": data["method"], "resource": data["resource"],
            "provenance": data.get("provenance"), "bull_decision": data["bull_decision"],
            "bull_allowed": data["allowed"], "bull_reason_code": data.get("reason_code"),
            "approval_id": data.get("approval_id"),
            "openshell_l7": l7["action"] if l7 else None,
            "openshell_middleware": openshell_says,
            "openshell_reason": middleware["reason"] if middleware else None,
            "effect_observed": effect is not None,
            "consistent": (
                middleware is not None
                and (openshell_says == "ALLOWED") == bool(data["allowed"])
                and (effect is not None) == bool(data["allowed"])
                and (data["allowed"] or data.get("reason_code", "") in middleware["reason"])),
        })
    summary = {
        "bull_decisions": len(rows),
        "matched_openshell_event": sum(r["openshell_middleware"] is not None for r in rows),
        "consistent": sum(r["consistent"] for r in rows),
        "effects_without_bull_allow": sum(r["effect_observed"] and not r["bull_allowed"]
                                          for r in rows),
        "unexplained_effects": len(receipts) - len(used["effect"]),
    }
    return {"rows": rows, "summary": summary}
