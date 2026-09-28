from types import SimpleNamespace
from unittest.mock import create_autospec
import pytest

from bulldog.dispatcher import DispatchDenied, DispatchRequest
from bulldog.production_router import ProductionEffect, ProductionEffectRouter
from bulldog.profiles import ProductionDispatcher
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.models import Capability, Provenance


def router():
    dispatcher = object.__new__(ProductionDispatcher)
    calls = []
    dispatcher.execute = (
        lambda request, argv, **kw: calls.append(("execute", tuple(argv), kw)) or "ran"
    )
    dispatcher.fetch_egress = create_autospec(
        dispatcher.fetch_egress,
        side_effect=lambda **kw: calls.append(("network", kw)) or "fetched",
    )
    dispatcher.get_secret = create_autospec(
        dispatcher.get_secret,
        side_effect=lambda **kw: calls.append(("secret", kw)) or "secret",
    )
    return ProductionEffectRouter(dispatcher), calls


def request():
    return DispatchRequest(
        {},
        TrustedExecutionContext("operator", (Provenance.HUMAN,), "context"),
        frozenset(Capability),
        domain_id="host-domain",
    )


def test_unknown_effect_is_unreachable():
    gate, calls = router()
    with pytest.raises(DispatchDenied, match="no production adapter"):
        gate.dispatch(
            ProductionEffect("message.send", request(), {"body": "agent text"})
        )
    assert calls == []


def test_exact_execute_schema_routes_only_through_production_dispatcher(tmp_path):
    gate, calls = router()
    effect = ProductionEffect(
        "process.execute",
        request(),
        {"argv": ["/usr/bin/true"], "project_root": str(tmp_path), "timeout": 5},
    )
    assert gate.dispatch(effect) == "ran"
    assert calls[0][0] == "execute"
    with pytest.raises(DispatchDenied, match="exact"):
        gate.dispatch(
            ProductionEffect(
                "process.execute",
                request(),
                {
                    "argv": ["/usr/bin/true"],
                    "project_root": str(tmp_path),
                    "timeout": 5,
                    "agent_override": True,
                },
            )
        )


def test_coverage_is_explicit_about_unimplemented_effects():
    coverage = ProductionEffectRouter.coverage()
    assert coverage["default"] == "DENY"
    assert "publish" in coverage["unsupported"]


def test_network_signature_and_domain_are_forwarded():
    gate, calls = router()
    req = request()
    assert (
        gate.dispatch(
            ProductionEffect(
                "network.request", req, {"url": "https://example.com/", "method": "GET"}
            )
        )
        == "fetched"
    )
    assert calls == [
        (
            "network",
            {
                "url": "https://example.com/",
                "method": "GET",
                "domain_id": "host-domain",
                "request": req,
                "approval": None,
            },
        )
    ]


@pytest.mark.parametrize(
    "extra",
    [
        {"headers": {"Authorization": "not-a-real-token"}, "body": None},
        {"headers": {}, "body": "payload"},
    ],
)
def test_unsupported_network_payload_never_reaches_broker(extra):
    gate, calls = router()
    with pytest.raises(DispatchDenied):
        gate.dispatch(
            ProductionEffect(
                "network.request",
                request(),
                {"url": "https://example.com/", "method": "GET", **extra},
            )
        )
    assert calls == []


def test_secret_route_forwards_host_domain():
    gate, calls = router()
    req = request()
    gate.dispatch(
        ProductionEffect(
            "secret.read",
            req,
            {"token": "fixture", "name": "fixture", "sandbox_id": "host-domain"},
        )
    )
    assert calls[0][1]["domain_id"] == req.domain_id
