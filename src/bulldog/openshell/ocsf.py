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
from collections import defaultdict
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
    ``method``, ``url``. Receipts carry no sandbox identity, so they are
    assigned only to decisions BULL allowed (nearest at or after the
    decision); any receipt left over is an effect BULL never allowed.
    """
    receipts = receipts or []
    decisions = [r for r in ledger_records if r.get("event_type") == "openshell_egress"]
    used_mw: set[int] = set()
    used_l7: set[int] = set()
    used_effect: set[int] = set()
    rows = []
    for record in decisions:
        data = record["data"]
        when = _epoch(record["timestamp"])

        def same(item, engine, data=data):
            return (item["sandbox"] == data["sandbox"] and item["method"] == data["method"]
                    and _target(item["url"]) == _target(data["resource"])
                    and item["engine"] == engine)

        l7 = _take([e for e in events if same(e, "l7")], used_l7, when, window)
        middleware = _take([e for e in events if same(e, "middleware")], used_mw, when, window)
        effect = None
        if data["allowed"]:
            later = [r for r in receipts if r["method"] == data["method"]
                     and _target(r["url"]) == _target(data["resource"])
                     and r["time"] >= when - 0.05]
            effect = _take(later, used_effect, when, window)
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
    orphans = [e for e in events if e["engine"] == "middleware" and id(e) not in used_mw]
    unexplained = [r for r in receipts if id(r) not in used_effect]
    summary = {
        "bull_decisions": len(rows),
        "matched_openshell_event": sum(r["openshell_middleware"] is not None for r in rows),
        "consistent": sum(r["consistent"] for r in rows),
        "effects_without_bull_allow": len(unexplained),
        # Middleware events BULL never decided: expected only when BULL was
        # unreachable, which OpenShell must then fail closed.
        "openshell_events_without_bull_decision": len(orphans),
        "orphans_fail_closed": all(e["action"] == "DENIED" for e in orphans),
    }
    return {"rows": rows, "summary": summary,
            "orphan_events": orphans, "unexplained_effects": unexplained}


def correlate_exact(ledger_records, events, receipts):
    """Join normalized JSONL evidence by identity, never by timing.

    Each event/receipt must carry request_id, decision_id, action_digest and
    sandbox_id. OpenShell events also carry engine and action. This schema
    requires a native exporter that preserves middleware metadata; shorthand
    logs do not satisfy it. Ledger authenticity must be verified by the caller.
    """
    fields = ("request_id", "decision_id", "action_digest", "sandbox_id")
    def key(item):
        values = tuple(item.get(field) for field in fields)
        return values if all(isinstance(v, str) and v for v in values) else None

    decisions = defaultdict(list)
    layers = defaultdict(list)
    effects = defaultdict(list)
    missing = 0
    for record in ledger_records:
        if record.get("event_type") != "openshell_egress":
            continue
        data = record["data"]
        identity = key(data)
        if identity is None:
            missing += 1
        else:
            decisions[identity].append(data)
    for event in events:
        identity = key(event)
        if identity is None:
            missing += 1
        else:
            layers[(identity, event.get("engine"))].append(event)
    for receipt in receipts:
        identity = key(receipt)
        if identity is None:
            missing += 1
        else:
            effects[identity].append(receipt)
    duplicate = sum(max(0, len(v) - 1) for group in (decisions, layers, effects)
                    for v in group.values())
    # Reusing one request/decision ID with a different digest must not create
    # two apparently unique identities.
    for index in (0, 1):
        identifiers = [identity[index] for identity in decisions]
        duplicate += len(identifiers) - len(set(identifiers))
    rows = []
    for identity, candidates in decisions.items():
        data = candidates[0]
        l7 = layers.get((identity, "l7"), [])
        middleware = layers.get((identity, "middleware"), [])
        received = effects.get(identity, [])
        consistent = (len(candidates) == len(l7) == len(middleware) == 1
                      and (middleware[0].get("action") == "ALLOWED") == bool(data["allowed"])
                      and (not received or l7[0].get("action") == "ALLOWED")
                      and len(received) == int(bool(data["allowed"]) and l7[0].get("action") == "ALLOWED"))
        rows.append(dict(zip(fields, identity), bull_allowed=data["allowed"],
                         effects=len(received), consistent=consistent))
    unexplained = [r for identity, group in effects.items() for r in group
                   if len(decisions.get(identity, [])) != 1
                   or not decisions[identity][0]["allowed"]
                   or len(layers.get((identity, "l7"), [])) != 1
                   or layers[(identity, "l7")][0].get("action") != "ALLOWED"
                   or len(layers.get((identity, "middleware"), [])) != 1
                   or layers[(identity, "middleware")][0].get("action") != "ALLOWED"]
    orphans = sum(len(v) for (identity, _), v in layers.items() if identity not in decisions)
    summary = {"bull_decisions": sum(map(len, decisions.values())),
               "consistent": sum(r["consistent"] for r in rows),
               "duplicate_identities": duplicate, "missing_identity": missing,
               "effects_without_dual_allow": len(unexplained),
               "orphan_events": orphans,
               "exact": missing == duplicate == len(unexplained) == orphans == 0
                        and all(r["consistent"] for r in rows)}
    return {"rows": rows, "summary": summary, "unexplained_effects": unexplained}
