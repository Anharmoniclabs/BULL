"""gRPC services OpenShell calls: supervisor middleware and gateway interceptor.

Both run outside every sandbox, in the BULL authority process. Register them
fail-closed: if BULL is unavailable, OpenShell blocks the affected traffic
and rejects the governed control-plane writes.
"""

from __future__ import annotations

from concurrent import futures
import json
import logging

import grpc
from google.protobuf import json_format, struct_pb2

from . import INTERCEPTOR_NAME, MIDDLEWARE_NAME, OPENSHELL_PROTOCOL
from ._proto import extension_pb2 as ext
from ._proto import gateway_interceptor_pb2 as gi
from ._proto import gateway_interceptor_pb2_grpc as gi_grpc
from ._proto import supervisor_middleware_pb2 as mw
from ._proto import supervisor_middleware_pb2_grpc as mw_grpc
from .authority import OpenShellAuthority

LOG = logging.getLogger("bull.openshell")
MAX_PAYLOAD = 256 * 1024
SERVICE = "openshell.v1.OpenShell"


def _metadata(name: str) -> ext.PeerMetadata:
    major, minor = OPENSHELL_PROTOCOL
    return ext.PeerMetadata(
        protocol_version=ext.ProtocolVersion(major=major, minor=minor),
        implementation_name=f"bull/{name}",
        implementation_version="bull-openshell-0.1",
    )


def _struct(message) -> dict:
    return json_format.MessageToDict(message) if message is not None else {}


class BullMiddleware(mw_grpc.SupervisorMiddlewareServicer):
    def __init__(self, authority: OpenShellAuthority):
        self.authority = authority

    def Describe(self, request, context):
        return mw.MiddlewareManifest(
            name=MIDDLEWARE_NAME,
            service_version="0.1",
            bindings=[mw.MiddlewareBinding(
                operation=mw.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST,
                phase=mw.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS,
                max_payload_bytes=MAX_PAYLOAD,
            )],
            extension=_metadata("supervisor-middleware"),
        )

    def ValidateConfig(self, request, context):
        config = _struct(request.config)
        if config:
            return mw.ValidateConfigResponse(valid=False, reason="BULL takes no per-policy config")
        return mw.ValidateConfigResponse(valid=True)

    def EvaluateHttpRequest(self, request, context):
        target, ctx = request.target, request.context
        verdict = self.authority.evaluate_request(
            sandbox=ctx.sandbox, sandbox_id=ctx.sandbox_id, request_id=ctx.request_id,
            method=target.method, scheme=target.scheme, host=target.host, port=target.port,
            path=target.path, query=target.query, body=bytes(request.body),
            binary=ctx.originating_process.binary,
        )
        return mw.HttpRequestResult(
            decision=mw.DECISION_ALLOW if verdict.allowed else mw.DECISION_DENY,
            reason=verdict.reason[:500],
            reason_code=verdict.reason_code,
            metadata={"bull_decision": verdict.decision,
                      **({"bull_approval_id": verdict.approval_id} if verdict.approval_id else {})},
        )

    def EvaluateWebSocketSession(self, request_iterator, context):
        # Not bound in the manifest; refuse if OpenShell ever sends one.
        for event in request_iterator:
            if event.HasField("preflight"):
                yield mw.WebSocketSessionEventResult(preflight_decision=mw.WebSocketPreflightDecision(
                    action=mw.WEB_SOCKET_PREFLIGHT_ACTION_DENY,
                    reason="BULL does not mediate WebSocket sessions", reason_code="bull.unsupported"))
                return


GOVERNED = {
    "CreateSandbox": (gi.GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION,
                      gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE),
    "UpdateConfig": (gi.GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION,
                     gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE),
    "AttachSandboxProvider": (gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE,),
    "ApproveDraftChunk": (gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE,),
    "ApproveAllDraftChunks": (gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE,),
    "EditDraftChunk": (gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE,),
}


class BullInterceptor(gi_grpc.GatewayInterceptorServicer):
    def __init__(self, authority: OpenShellAuthority):
        self.authority = authority

    def Describe(self, request, context):
        return gi.InterceptorManifest(
            name=INTERCEPTOR_NAME,
            failure_policy="fail_closed",
            bindings=[gi.InterceptorBinding(
                id=f"bull-{method.lower()}",
                selector=gi.InterceptorSelector(rpc=f"{SERVICE}/{method}"),
                phases=list(phases), failure_policy="fail_closed",
            ) for method, phases in GOVERNED.items()],
            extension=_metadata("gateway-interceptor"),
        )

    def SnapshotProviderProfiles(self, request, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "BULL vends no provider profiles")

    def Evaluate(self, request, context):
        method = request.method or request.binding_id
        phase = request.WhichOneof("phase")
        if phase == "modify_operation":
            operation = _struct(request.modify_operation.proposed_operation)
            LOG.info("interceptor %s modify payload %s", method, json.dumps(operation)[:2000])
            if method == "CreateSandbox":
                verdict, patches = self.authority.create_sandbox_patches(operation)
                return self._result(verdict, patches)
            if method == "UpdateConfig":
                result = gi.InterceptorResult(allowed=True)
                for patch in self.authority.update_config_patches(operation):
                    value = struct_pb2.Value()
                    json_format.ParseDict(patch["value"], value)
                    result.patches.append(gi.JsonPatch(op=patch["op"], path=patch["path"],
                                                       value=value))
                return result
            return gi.InterceptorResult(allowed=True)
        if phase == "validate":
            operation = _struct(request.validate.proposed_operation)
            LOG.info("interceptor %s validate payload %s", method, json.dumps(operation)[:2000])
            if method == "CreateSandbox":
                return self._result(self.authority.validate_create(operation))
            if method == "AttachSandboxProvider":
                return self._result(self.authority.validate_provider_attach(operation))
            if method in GOVERNED:
                return self._result(self.authority.validate_policy_change(method, operation))
            return self._result(None)
        return gi.InterceptorResult(allowed=True)  # post_commit is observational

    @staticmethod
    def _result(verdict, patches=()) -> gi.InterceptorResult:
        if verdict is None:
            return gi.InterceptorResult(allowed=False, reason="ungoverned RPC reached BULL",
                                        status_code="PERMISSION_DENIED")
        result = gi.InterceptorResult(
            allowed=verdict.allowed,
            reason="" if verdict.allowed else verdict.reason[:500],
            status_code="" if verdict.allowed else "PERMISSION_DENIED",
            log_annotations={"bull_code": verdict.reason_code,
                             **({"bull_approval_id": verdict.approval_id}
                                if verdict.approval_id else {})},
        )
        for patch in patches:
            value = struct_pb2.Value()
            json_format.ParseDict(patch.get("value"), value)
            result.patches.append(gi.JsonPatch(op=patch["op"], path=patch["path"], value=value))
        return result


def serve(authority: OpenShellAuthority, *, middleware_bind: str, interceptor_bind: str):
    """Start both services; returns the two grpc.Server objects."""
    options = [("grpc.max_receive_message_length", 5 * 1024 * 1024)]
    servers = []
    for servicer, add, bind in (
        (BullMiddleware(authority), mw_grpc.add_SupervisorMiddlewareServicer_to_server,
         middleware_bind),
        (BullInterceptor(authority), gi_grpc.add_GatewayInterceptorServicer_to_server,
         interceptor_bind),
    ):
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=16), options=options)
        add(servicer, server)
        if server.add_insecure_port(bind) == 0:
            raise OSError(f"could not bind {bind}")
        server.start()
        servers.append(server)
    return servers
