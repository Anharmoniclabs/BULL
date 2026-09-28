"""Correlate OpenShell OCSF events with BULL decisions into one audit trail.

OpenShell's supervisor writes OCSF v1.8 JSONL inside each sandbox
(``/var/log/openshell-ocsf.YYYY-MM-DD.log``). BULL's ledger records its own
decision for every request it sees. Joining the two answers, per action:
what BULL decided, what OpenShell's policy decided, and whether it happened.
"""

from __future__ import annotations

import json


def parse_ocsf(lines) -> list[dict]:
    events = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        events.append({
            "class": event.get("class_name"),
            "activity": event.get("activity_name"),
            "status": event.get("status"),
            "message": event.get("message", ""),
            "time_ms": event.get("time"),
            "sandbox": (event.get("container") or {}).get("uid")
                       or (event.get("container") or {}).get("name"),
            "raw_uid": (event.get("metadata") or {}).get("uid"),
            "dst": ((event.get("dst_endpoint") or {}).get("hostname")
                    or (event.get("dst_endpoint") or {}).get("ip")),
            "http": event.get("http_request") or {},
            "finding": (event.get("finding_info") or {}).get("title"),
        })
    return events


def correlate(ledger_records: list[dict], ocsf_events: list[dict]) -> list[dict]:
    """One row per BULL egress decision, with OpenShell's view of the same host."""
    rows = []
    for record in ledger_records:
        if record.get("event_type") != "openshell_egress":
            continue
        data = record["data"]
        host = data["resource"].split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        seen = [e for e in ocsf_events if host and host in (e.get("message") or "")
                or e.get("dst") == host]
        rows.append({
            "ledger_sequence": record.get("sequence"),
            "sandbox": data["sandbox"],
            "request_id": data["request_id"],
            "method": data["method"],
            "resource": data["resource"],
            "provenance": data["provenance"],
            "bull_decision": data["bull_decision"],
            "bull_allowed": data["allowed"],
            "approval_id": data.get("approval_id"),
            "openshell_events": [f"{e['class']}:{e['activity']}:{e['status']}" for e in seen][:6],
        })
    return rows
