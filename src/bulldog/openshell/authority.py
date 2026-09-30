"""BULL's decisions for OpenShell traffic and control-plane changes.

One authority instance backs both extension services, so a sandbox's
provenance, approvals and audit trail are shared between the data plane
(egress middleware) and the control plane (policy/provider interceptor).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlunsplit

from ..models import ActionRequest, Capability, Decision, Provenance
from ..policy import DeterministicPolicy
from .grants import host_matches, validate_grants
from .boundary import BoundaryDenied

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
# Protobuf JSON renders the NetworkEnforcementMode enum by name; YAML-facing
# callers use the short form. UNSPECIFIED means OpenShell's default, audit.
_ENFORCE = {"enforce", "NETWORK_ENFORCEMENT_MODE_ENFORCE", 1}


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason_code: str
    reason: str
    decision: str
    approval_id: str | None = None


class ApprovalStore:
    """Single-use human approvals bound to an exact request digest.

    An ESCALATE creates a pending entry; the request is denied, never held
    open. After an operator approves it, the next identical request (same
    sandbox, method, target and body digest) is admitted exactly once.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}
        self.on_change = lambda: None

    def restore(self, entries: dict) -> None:
        with self._lock:
            self._entries = {k: dict(v) for k, v in entries.items()}

    def pending_for(self, binding: str, summary: dict) -> str:
        with self._lock:
            for aid, entry in self._entries.items():
                if entry["binding"] == binding and entry["state"] == "pending":
                    return aid
            aid = secrets.token_hex(8)
            self._entries[aid] = {"binding": binding, "state": "pending", "summary": summary,
                                  "created": time.time()}
        self.on_change()
        return aid

    def approve(self, aid: str) -> dict:
        with self._lock:
            entry = self._entries.get(aid)
            if entry is None or entry["state"] != "pending":
                raise KeyError("no pending approval with that id")
            entry["state"] = "approved"
            entry["approved"] = time.time()
            copy = dict(entry)
        self.on_change()
        return copy

    def consume(self, binding: str) -> str | None:
        with self._lock:
            for aid, entry in self._entries.items():
                if entry["binding"] == binding and entry["state"] == "approved":
                    entry["state"] = "consumed"
                    break
            else:
                return None
        self.on_change()
        return aid

    def listing(self) -> dict:
        with self._lock:
            return {aid: dict(e) for aid, e in self._entries.items()}


class OpenShellAuthority:
    def __init__(self, grants: dict, ceiling: frozenset[Capability], ledger=None,
                 state_path=None):
        self.grants = validate_grants(grants)
        self.policy = DeterministicPolicy(project_root="/sandbox",
                                          global_capability_ceiling=ceiling)
        self.ledger = ledger
        self.approvals = ApprovalStore()
        self._lock = threading.RLock()
        self._epochs = {name: 0 for name in self.grants["sandboxes"]}
        self._removed = {name: set() for name in self.grants["sandboxes"]}
        self._tainted: dict[str, set[str]] = {}  # sandbox -> untrusted source hosts
        self._policy_hosts: dict[str, set[str]] = {}  # sandbox -> BULL-accepted hosts
        self.state_path = Path(state_path) if state_path else None
        self.approvals.on_change = self._save_locked
        self._load()

    def _save_locked(self) -> None:
        with self._lock:
            self._save()

    # ------------------------------------------------------------ helpers

    def _grant(self, sandbox: str) -> dict:
        with self._lock:
            grant = dict(self.grants["sandboxes"].get(sandbox, {"capabilities": [], "trusted_sources": []}))
            grant["capabilities"] = sorted(set(grant["capabilities"]) - self._removed.get(sandbox, set()))
            return grant

    def _audit(self, event: str, **data) -> None:
        if self.ledger is not None:
            self.ledger.append_event(event, data)

    @staticmethod
    def _trusted(grant: dict, host: str, port: int) -> bool:
        for source in grant["trusted_sources"]:
            name, _, wanted = source.partition(":")
            if host_matches(host, name) and (not wanted or wanted == str(port)):
                return True
        return False

    def _save(self) -> None:
        """Persist provenance and accepted policy so a restart cannot reset them."""
        if self.state_path is None:
            return
        state = {"tainted": {k: sorted(v) for k, v in self._tainted.items()},
                 "policy_hosts": {k: sorted(v) for k, v in self._policy_hosts.items()},
                 "approvals": self.approvals.listing(),
                 "authority_epochs": self._epochs,
                 "removed_capabilities": {k: sorted(v) for k, v in self._removed.items()}}
        temporary = self.state_path.with_suffix(".tmp")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("w") as stream:
            stream.write(json.dumps(state))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.state_path)
        directory = os.open(self.state_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _load(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        state = json.loads(self.state_path.read_text())
        self._tainted = {k: set(v) for k, v in state.get("tainted", {}).items()}
        self._policy_hosts = {k: set(v) for k, v in state.get("policy_hosts", {}).items()}
        self.approvals.restore(state.get("approvals", {}))
        self._epochs.update(state.get("authority_epochs", {}))
        self._removed.update({k: set(v) for k, v in state.get("removed_capabilities", {}).items()})

    def _within_ceiling(self, host: str) -> bool:
        return any(host_matches(host, p) for p in self.grants["host_ceiling"])

    def provenance(self, sandbox: str) -> tuple[Provenance, ...]:
        with self._lock:
            tainted = bool(self._tainted.get(sandbox))
        return (Provenance.INTERNET,) if tainted else (Provenance.LOCAL_TRUSTED,)

    # ---------------------------------------------------------- data plane

    def evaluate_request(self, *, sandbox: str, sandbox_id: str, request_id: str,
                         method: str, scheme: str, host: str, port: int, path: str,
                         query: str, body: bytes, binary: str, budget=None,
                         identity=None) -> Verdict:
        if budget is not None:
            budget.check()
        with self._lock:
            epoch = self._epochs.get(sandbox, 0)
        method = method.upper()
        capability = (Capability.NETWORK_OUTBOUND if method in READ_METHODS
                      else Capability.NETWORK_POST)
        grant = self._grant(sandbox)
        netloc = host if port in (0, 80, 443) else f"{host}:{port}"
        resource = urlunsplit((scheme or "https", netloc, path or "/", query, ""))
        action = ActionRequest(
            actor=f"openshell:{sandbox}",
            task="openshell sandbox egress",
            operation=f"http.{method.lower()}",
            resource=resource,
            capability=capability,
            granted_capabilities=frozenset(Capability(c) for c in grant["capabilities"]),
            provenance=self.provenance(sandbox),
            external_side_effect=capability == Capability.NETWORK_POST,
            metadata={"sandbox_id": sandbox_id, "binary": binary},
        )
        evaluation = self.policy.evaluate(action)
        decision = evaluation.decision
        body_digest = hashlib.sha256(body).hexdigest()
        binding = json.dumps([sandbox, epoch, method, scheme, host, port, path, query, body_digest])
        if budget is not None:
            budget.check()
        with self._lock:
            if epoch != self._epochs.get(sandbox, 0):
                raise BoundaryDenied("bull_authority_revoked")
        approval_id = None
        if decision == Decision.ESCALATE:
            consumed = self.approvals.consume(binding)
            if consumed:
                verdict = Verdict(True, "bull_approved", "operator approved this exact request",
                                  decision.value, consumed)
            else:
                approval_id = self.approvals.pending_for(binding, {
                    "sandbox": sandbox, "method": method, "resource": resource,
                    "body_sha256": body_digest, "reasons": list(evaluation.reasons)})
                verdict = Verdict(False, "bull_approval_required",
                                  f"approval {approval_id} required: "
                                  + "; ".join(evaluation.reasons),
                                  decision.value, approval_id)
        elif decision == Decision.DENY:
            verdict = Verdict(False, "bull_denied", "; ".join(evaluation.reasons), decision.value)
        else:
            verdict = Verdict(True, "bull_allowed", "; ".join(evaluation.reasons), decision.value)
        if verdict.allowed and capability == Capability.NETWORK_OUTBOUND and not self._trusted(
            grant, host, port
        ):
            # Content from this source flows back into the agent: later effects
            # are downstream of untrusted input.
            with self._lock:
                self._tainted.setdefault(sandbox, set()).add(f"{host}:{port}")
                self._save()
        self._audit("openshell_egress", sandbox=sandbox, sandbox_id=sandbox_id,
                    request_id=request_id, method=method, resource=resource,
                    authority_epoch=epoch,
                    decision_id=identity.decision_id if identity else None,
                    action_digest=identity.action_digest if identity else None,
                    upstream_request_id=identity.upstream_request_id if identity else None,
                    body_sha256=body_digest, binary=binary,
                    provenance=[p.value for p in action.provenance],
                    bull_decision=decision.value, risk=evaluation.risk,
                    allowed=verdict.allowed, reason_code=verdict.reason_code,
                    approval_id=verdict.approval_id)
        if budget is not None:
            budget.check()
        with self._lock:
            if epoch != self._epochs.get(sandbox, 0):
                raise BoundaryDenied("bull_authority_revoked")
        return verdict

    def revoke(self, sandbox: str, capabilities, *, mode="REVOKE_NEXT_EFFECT", terminate=None):
        """Remove capabilities from a signed parent and every signed descendant.

        Propagation occurs once on revocation (O(subtree)); each subsequent
        action checks its own grant and epoch in O(1). Emergency termination
        requires a host hook; no process or credential cleanup is simulated.
        """
        removed = {Capability(c).value for c in capabilities}
        if mode not in {"REVOKE_NEXT_EFFECT", "REVOKE_TERMINATE"}:
            raise ValueError("unsupported revocation mode")
        if mode == "REVOKE_TERMINATE" and not callable(terminate):
            raise ValueError("REVOKE_TERMINATE requires a trusted host termination hook")
        with self._lock:
            if sandbox not in self.grants["sandboxes"]:
                raise KeyError("unknown sandbox")
            affected = [sandbox]
            for name in affected:
                affected.extend(child for child, grant in self.grants["sandboxes"].items()
                                if grant.get("parent") == name)
                self._epochs[name] = self._epochs.get(name, 0) + 1
                self._removed.setdefault(name, set()).update(removed)
                if mode == "REVOKE_TERMINATE":
                    self._removed[name].update(self.grants["sandboxes"][name]["capabilities"])
            self._save()
            self._audit("openshell_revocation", sandbox=sandbox, affected=affected,
                        capabilities=sorted(removed), mode=mode, epochs=self._epochs.copy())
        if mode == "REVOKE_TERMINATE":
            for name in affected:
                terminate(name)
        return affected

    # -------------------------------------------------------- control plane

    @staticmethod
    def policy_endpoints(policy: dict | None) -> set[str]:
        """Every ``host:port`` a policy grants; authority is tracked per endpoint."""
        endpoints = set()
        for rule in (policy or {}).get("networkPolicies", {}).values():
            for endpoint in rule.get("endpoints", []):
                if endpoint.get("host"):
                    # Protobuf JSON renders integers as doubles (443.0).
                    ports = {int(p) for p in endpoint.get("ports") or []}
                    ports.add(int(endpoint.get("port") or 443))
                    endpoints |= {f"{endpoint['host'].lower()}:{p}" for p in ports}
        return endpoints

    @staticmethod
    def audit_mode_endpoints(policy: dict | None) -> list[str]:
        """Endpoints whose L7 rules only log. OpenShell defaults ``enforcement``
        to ``audit``, which allows rule violations; BULL requires ``enforce``."""
        found = []
        for name, rule in ((policy or {}).get("networkPolicies") or {}).items():
            for endpoint in rule.get("endpoints", []):
                if endpoint.get("rules") and endpoint.get("enforcement") not in _ENFORCE:
                    found.append(f"{name}:{endpoint.get('host', '')}")
        return sorted(found)

    @staticmethod
    def _host(endpoint: str) -> str:
        return endpoint.rsplit(":", 1)[0]

    def create_sandbox_patches(self, operation: dict) -> tuple[Verdict, list[dict]]:
        """modify_operation for CreateSandbox: attach BULL middleware to every host."""
        name = operation.get("name", "")
        policy = (operation.get("spec") or {}).get("policy") or {}
        endpoints = self.policy_endpoints(policy)
        hosts = {self._host(e) for e in endpoints}
        outside = sorted(h for h in hosts if not self._within_ceiling(h))
        if outside:
            verdict = Verdict(False, "bull_outside_ceiling",
                              f"policy grants hosts outside the signed BULL ceiling: {outside}",
                              Decision.DENY.value)
            self._audit("openshell_control", rpc="CreateSandbox", sandbox=name,
                        allowed=False, reason=verdict.reason)
            return verdict, []
        patches = []
        if "spec" not in operation:
            patches.append({"op": "add", "path": "/spec", "value": {}})
        if "policy" not in (operation.get("spec") or {}):
            patches.append({"op": "add", "path": "/spec/policy", "value": {}})
        patches += self.attach_patches(policy, "/spec/policy")
        with self._lock:
            self._policy_hosts[name] = endpoints
            self._save()
        self._audit("openshell_control", rpc="CreateSandbox", sandbox=name, allowed=True,
                    endpoints=sorted(endpoints), patched="bull middleware attached")
        return Verdict(True, "bull_attached", "BULL middleware attached",
                       Decision.ALLOW.value), patches

    def attach_patches(self, policy: dict, base: str) -> list[dict]:
        """JSON patches that attach BULL middleware to every host in ``policy``."""
        from . import MIDDLEWARE_NAME

        hosts = sorted({self._host(e) for e in self.policy_endpoints(policy)})
        attachment = {"name": "BULL governance", "middleware": MIDDLEWARE_NAME,
                      "onError": "fail_closed", "endpoints": {"include": hosts or ["bull.invalid"]},
                      "order": 1}
        patches = []
        if "networkMiddlewares" not in policy:
            patches.append({"op": "add", "path": f"{base}/networkMiddlewares", "value": {}})
        patches.append({"op": "add", "path": f"{base}/networkMiddlewares/{MIDDLEWARE_NAME}",
                        "value": attachment})
        return patches

    def update_config_patches(self, operation: dict) -> list[dict]:
        """modify_operation for UpdateConfig: a replacement policy stays mediated."""
        policy = operation.get("policy")
        return self.attach_patches(policy, "/policy") if policy else []

    def validate_create(self, operation: dict) -> Verdict:
        from . import MIDDLEWARE_NAME

        policy = (operation.get("spec") or {}).get("policy") or {}
        attached = (policy.get("networkMiddlewares") or {}).get(MIDDLEWARE_NAME)
        hosts = {self._host(e) for e in self.policy_endpoints(policy)}
        if not attached or not hosts <= set(attached.get("endpoints", {}).get("include", [])):
            return Verdict(False, "bull_unmediated", "BULL middleware must cover every host",
                           Decision.DENY.value)
        audit_only = self.audit_mode_endpoints(policy)
        if audit_only:
            return self._control_deny("CreateSandbox", operation.get("name", ""),
                                      "bull_l7_audit_mode",
                                      f"L7 rules must set enforcement: enforce: {audit_only}")
        return Verdict(True, "bull_valid", "sandbox is mediated by BULL", Decision.ALLOW.value)

    def validate_policy_change(self, rpc: str, operation: dict) -> Verdict:
        """UpdateConfig and draft approvals: no widening without approval."""
        from . import MIDDLEWARE_NAME

        sandbox = operation.get("sandbox") or operation.get("name") or ""
        if operation.get("global") and (operation.get("policy") or operation.get("mergeOperations")):
            return self._control_deny(rpc, sandbox, "bull_global_policy",
                                      "global policy changes are outside BULL's per-sandbox grants")
        new_hosts: set[str] = set()
        policy = operation.get("policy")
        if policy:
            new_hosts |= self.policy_endpoints(policy)
            attached = (policy.get("networkMiddlewares") or {}).get(MIDDLEWARE_NAME)
            if not attached:
                return self._control_deny(rpc, sandbox, "bull_unmediated",
                                          "a replacement policy must keep BULL middleware")
        audit_only = self.audit_mode_endpoints(policy)
        for merge in operation.get("mergeOperations", []) or []:
            rule = (merge.get("addRule") or {}).get("rule") or {}
            new_hosts |= self.policy_endpoints({"networkPolicies": {"x": rule}})
            audit_only += self.audit_mode_endpoints({"networkPolicies": {"x": rule}})
            allow = merge.get("addAllowRules")
            if allow:
                # New L7 rules on an existing endpoint are still new authority.
                new_hosts.add(f"{str(allow.get('host', '')).lower()}:{allow.get('port', 443)}"
                              f"#rules:{json.dumps(allow.get('rules', []), sort_keys=True)}")
        if audit_only:
            return self._control_deny(rpc, sandbox, "bull_l7_audit_mode",
                                      f"L7 rules must set enforcement: enforce: {audit_only}")
        if rpc in ("ApproveDraftChunk", "ApproveAllDraftChunks", "EditDraftChunk"):
            # Draft approvals merge agent-proposed access; BULL must approve.
            return self._widening(rpc, sandbox, {f"draft:{operation.get('chunkId', 'all')}"})
        with self._lock:
            known = set(self._policy_hosts.get(sandbox, set()))
        added = {h for h in new_hosts if h and h not in known}
        added_hosts = {self._host(h.split("#", 1)[0]) for h in added}
        outside = sorted(h for h in added_hosts if not self._within_ceiling(h))
        if outside:
            return self._control_deny(rpc, sandbox, "bull_outside_ceiling",
                                      f"hosts outside the signed BULL ceiling: {outside}")
        if added:
            return self._widening(rpc, sandbox, added)
        self._audit("openshell_control", rpc=rpc, sandbox=sandbox, allowed=True,
                    reason="no new authority")
        return Verdict(True, "bull_no_widening", "no new authority", Decision.ALLOW.value)

    def _widening(self, rpc: str, sandbox: str, added: set[str]) -> Verdict:
        binding = json.dumps(["policy", sandbox, sorted(added)])
        consumed = self.approvals.consume(binding)
        if consumed:
            with self._lock:
                self._policy_hosts.setdefault(sandbox, set()).update(
                    h for h in added if not h.startswith("draft:"))
                self._save()
            self._audit("openshell_control", rpc=rpc, sandbox=sandbox, allowed=True,
                        approval_id=consumed, added=sorted(added))
            return Verdict(True, "bull_approved", "operator approved this widening",
                           Decision.ESCALATE.value, consumed)
        aid = self.approvals.pending_for(binding, {"sandbox": sandbox, "rpc": rpc,
                                                   "adds": sorted(added)})
        self._audit("openshell_control", rpc=rpc, sandbox=sandbox, allowed=False,
                    approval_id=aid, added=sorted(added), reason="authority increase")
        return Verdict(False, "bull_approval_required",
                       f"approval {aid} required to widen policy with {sorted(added)}",
                       Decision.ESCALATE.value, aid)

    def _control_deny(self, rpc, sandbox, code, reason) -> Verdict:
        self._audit("openshell_control", rpc=rpc, sandbox=sandbox, allowed=False, reason=reason)
        return Verdict(False, code, reason, Decision.DENY.value)

    def validate_provider_attach(self, operation: dict) -> Verdict:
        sandbox = operation.get("sandboxName") or operation.get("sandbox") or ""
        grant = self._grant(sandbox)
        if Capability.CREDENTIAL_READ.value not in grant["capabilities"]:
            return self._control_deny("AttachSandboxProvider", sandbox, "bull_no_credential_use",
                                      "sandbox has no BULL grant to use provider credentials")
        return self._widening("AttachSandboxProvider", sandbox,
                              {f"provider:{operation.get('providerName', '')}"})
