"""Host authority for connected MCP tools, separate from the agent process.

All effects enter the selected profile's effect router. This service does not contain the
agent's native shell, browser, plugins or other MCP servers.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from .agent_session import AgentSession
from .agent_tool_registry import (
    EMPTY_INPUT,
    available_tools,
    capability_for,
    validate_gateway_config,
)
from .approval import ApprovalRequired
from .dispatcher import DispatchDenied, DispatchRequest
from .egress_proxy import EgressResponse
from .gateway_wire import (
    GatewayDenied,
    OUTPUT_FIELD_BYTES,
    RESULT_BYTES,
    json_size,
    safe_output,
)
from .integrity import build_integrity_manifest, sha256_file
from .models import Provenance
from .policy_bundle import load_policy_bundle
from .production_router import (
    LocalEffectRouter,
    ProductionEffect,
    ProductionEffectRouter,
)
from .profiles import LocalDispatcher, ProductionDispatcher
from .runtime import ExecutionResult
from .security_domain import SecurityDomainRegistry

COVERAGE = {
    "mode": "connected-tools-only",
    "whole_agent_contained": False,
    # This authority cannot see how its agent was started; a managed session
    # (bull agent launch) reports its own containment coverage.
    "managed_launcher": "AVAILABLE: bull agent launch",
    "remote_http": "DISABLED",
    "secret_export": "DISABLED",
    "argument_control": "fixed host-signed tools; empty arguments only",
    "identity": "dedicated agent OS UID; one signed lease per service",
    "enterprise_release": "UNQUALIFIED",
}


# Outcome fields always survive; bulky output is the only thing ever dropped.
_OUTCOME = (
    "call_id",
    "content_trust",
    "status",
    "executed",
    "decision",
    "returncode",
    "http_status",
)


def fit_result(response: dict, limit: int = RESULT_BYTES) -> dict:
    """Keep the true execution outcome deliverable whatever the output holds."""
    if json_size(response) <= limit:
        return response
    compact = {k: response[k] for k in _OUTCOME if k in response}
    return {**compact, "truncated": True, "output_omitted": True}


def _digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class GatewayAuthority:
    def __init__(
        self, dispatcher: ProductionDispatcher | LocalDispatcher, state_directory: Path
    ):
        self.router = (
            LocalEffectRouter(dispatcher)
            if isinstance(dispatcher, LocalDispatcher)
            else ProductionEffectRouter(dispatcher)
        )
        self.coverage = {**COVERAGE, "audit_mode": dispatcher.runtime.audit_mode}
        self.dispatcher = dispatcher
        self.runtime = dispatcher.runtime
        self.runtime.verify_trusted_state()
        bundle = self._bundle()
        self.config = validate_gateway_config(bundle.raw.get("agent_gateway"))
        if self.config["agent_uid"] == os.geteuid():
            raise GatewayDenied("agent and authority must use distinct OS UIDs")
        if not 0 < self.config["expires_at"] - time.time() <= 86400:
            raise GatewayDenied("lease must expire within 24 hours")
        self.project_root = Path(bundle.project_root).resolve(strict=True)
        if (
            state_directory == self.project_root
            or self.project_root in state_directory.parents
        ):
            raise GatewayDenied("authority state must be outside the project")
        self.policy_digest = _digest(bundle.raw)
        self.tcb_digest = _digest(
            build_integrity_manifest(Path(__file__).parent)["files"]
        )
        self.tools = available_tools(self.config, bundle.capability_ceiling)
        if any(
            tool["operation"] not in self.router.OPERATIONS
            for tool in self.tools.values()
        ):
            raise GatewayDenied(
                "signed registry includes effects unavailable in this audit profile"
            )
        if not self.tools:
            raise GatewayDenied("no tools within signed capability ceiling")
        self.registry = SecurityDomainRegistry(ledger=self.runtime.engine.ledger)
        if dispatcher.domain_registry is not None:
            raise GatewayDenied("gateway requires its own domain registry")
        dispatcher.domain_registry = self.registry
        # These are fixed operator-reviewed operations, not trusted model text.
        # Provenance of their returned content remains untrusted to the client.
        self.domain = self.registry.create_root(
            actor="gateway:"
            + self.config["tenant_id"]
            + ":"
            + self.config["project_id"],
            initial_prompt="Invoke only the fixed signed tool registry "
            + self.policy_digest,
            capability_ceiling=bundle.capability_ceiling,
            provenance=(Provenance.LOCAL_TRUSTED,),
            egress_hosts={
                urlsplit(x["url"]).hostname
                for x in self.tools.values()
                if x["operation"] == "network.request"
            },
        )
        self.session = AgentSession(state_directory, self.config, self.policy_digest)

    def _bundle(self):
        return load_policy_bundle(
            self.runtime._policy_bundle_path, self.runtime._policy_key
        )

    def close(self):
        self.session.close()

    def _refresh(self):
        self.runtime.verify_trusted_state()
        if _digest(self._bundle().raw) != self.policy_digest:
            raise GatewayDenied(
                "signed policy changed; restart with a new reviewed lease"
            )
        self.registry.require_active(self.domain.domain_id)
        self.session.check()

    def _audit(self, event: str, **fields):
        self.runtime.engine.ledger.append_event(
            event,
            {
                "tenant_id": self.config["tenant_id"],
                "project_id": self.config["project_id"],
                "session_id": self.config["session_id"],
                "domain_id": self.domain.domain_id,
                "policy_digest": self.policy_digest,
                **fields,
            },
        )

    def handle(self, message: dict, *, peer_uid: int) -> dict:
        # peer_uid is supplied exclusively by the server's SO_PEERCRED check.
        if peer_uid != self.config["agent_uid"]:
            raise GatewayDenied("peer is not enrolled for this lease")
        if not isinstance(message, dict):
            raise GatewayDenied("request must be an object")
        self._refresh()
        if message == {"method": "status"}:
            return {
                "coverage": dict(self.coverage),
                "lease": self.session.status(),
                "authority_tcb_sha256": self.tcb_digest,
                "policy_sha256": self.policy_digest,
            }
        if message == {"method": "list"}:
            return {
                "tools": [
                    {
                        "name": x["name"],
                        "description": x["description"],
                        "inputSchema": dict(EMPTY_INPUT),
                    }
                    for x in self.tools.values()
                ],
                "coverage": dict(self.coverage),
            }
        if (
            set(message) != {"method", "name", "arguments", "call_id"}
            or message["method"] != "call"
        ):
            raise GatewayDenied("unknown request or authority-bearing fields")
        if type(message["arguments"]) is not dict or message["arguments"]:
            raise GatewayDenied("tools accept empty arguments only")
        if not isinstance(message["name"], str) or message["name"] not in self.tools:
            raise GatewayDenied("tool is not in this lease")
        call_id = message["call_id"]
        if not isinstance(call_id, str) or not re.fullmatch(r"[0-9a-f]{32}", call_id):
            raise GatewayDenied("invalid call ID")
        tool = self.tools[message["name"]]
        effect = self._effect(tool)
        self.session.begin(call_id, tool["name"])
        try:
            self._audit(
                "gateway_attempt",
                call_id=call_id,
                tool=tool["name"],
                untrusted_selector=True,
                operation=tool["operation"],
            )
            # Recheck revocation and policy at the effect boundary, not just list.
            self.runtime.verify_trusted_state()
            self.session.check_lease()
            if (
                _digest(self._bundle().raw) != self.policy_digest
                or (self.session.directory / "REVOKED").exists()
            ):
                raise DispatchDenied("authority changed before dispatch")
            result = self.router.dispatch(effect)
            response = self._result(result, tool, call_id)
            self._audit(
                "gateway_result",
                call_id=call_id,
                tool=tool["name"],
                executed=response["executed"],
                result_digest=_digest(response),
            )
        except ApprovalRequired as exc:
            self.session.finish(call_id, "approval_required")
            return {
                "status": "APPROVAL_REQUIRED",
                "executed": False,
                "call_id": call_id,
                "approval_request_id": exc.request["request_id"],
                "detail": "Operator approval is required. This connector cannot submit proofs or auto-approve.",
            }
        except DispatchDenied:
            self.session.finish(call_id, "denied")
            return {"status": "DENIED", "executed": False, "call_id": call_id}
        except BaseException:
            self.session.finish(call_id, "uncertain")
            raise  # Transport returns a fixed error, never exception text or secrets.
        self.session.finish(call_id, "completed")
        return response

    def _effect(self, tool: dict) -> ProductionEffect:
        if tool["operation"] == "process.execute":
            executable = Path(tool["argv"][0]).resolve(strict=True)
            if executable != Path(tool["argv"][0]):
                raise GatewayDenied(
                    "registered executable path must be canonical without symlinks"
                )
            if (
                executable == self.project_root
                or self.project_root in executable.parents
            ):
                raise GatewayDenied("executable must be installed outside the project")
            # Pin a system/operator-installed file, not an agent-writable program.
            for path in (executable, *executable.parents):
                info = path.stat()
                if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
                    raise GatewayDenied(
                        "executable or ancestor is writable by an untrusted identity"
                    )
            if (
                not executable.is_file()
                or sha256_file(executable) != tool["executable_sha256"]
            ):
                raise GatewayDenied("registered executable changed")
            params = {
                "argv": tuple(tool["argv"]),
                "project_root": self.project_root,
                "timeout": tool["timeout"],
            }
            proposal = {
                "task": "fixed host-signed tool " + tool["name"],
                "operation": "execute",
                "resource": tool["argv"][0],
            }
            command = tuple(tool["argv"])
        else:
            params = {"url": tool["url"], "method": tool["method"]}
            proposal = {
                "task": "fixed host-signed tool " + tool["name"],
                "operation": "fetch",
                "resource": tool["url"],
            }
            command = None
        request = DispatchRequest(
            proposal=proposal,
            trusted=self.registry.trusted_context(self.domain.domain_id),
            granted_capabilities=frozenset({capability_for(tool)}),
            domain_id=self.domain.domain_id,
            authorized_command=command,
        )
        return ProductionEffect(tool["operation"], request, params)

    @staticmethod
    def _result(result, tool: dict, call_id: str) -> dict:
        base = {"call_id": call_id, "content_trust": "untrusted tool output"}
        if isinstance(result, ExecutionResult):
            stdout, cut_out, raw_out = safe_output(result.stdout)
            stderr, cut_err, raw_err = safe_output(result.stderr)
            response = {
                **base,
                "status": "COMPLETED" if result.executed else "DENIED",
                "executed": result.executed,
                "decision": result.evaluation.decision.value,
                "authorized_argv": tool["argv"],
                "returncode": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": cut_out or cut_err,
                "controls_replaced": raw_out or raw_err,
            }
        elif isinstance(result, EgressResponse):
            body, cut, replaced = safe_output(
                result.body[: 2 * OUTPUT_FIELD_BYTES].decode("utf-8", "replace")
            )
            cut = cut or len(result.body) > 2 * OUTPUT_FIELD_BYTES
            response = {
                **base,
                "status": "COMPLETED",
                "executed": True,
                "http_status": result.status,
                "body": body,
                "truncated": cut,
                "controls_replaced": replaced,
            }
        else:
            raise GatewayDenied("unsupported effect result")
        return fit_result(response)
