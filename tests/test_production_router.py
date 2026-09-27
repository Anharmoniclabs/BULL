from types import SimpleNamespace
import pytest

from bulldog.dispatcher import DispatchDenied, DispatchRequest
from bulldog.production_router import ProductionEffect, ProductionEffectRouter
from bulldog.profiles import ProductionDispatcher


def router():
    dispatcher = object.__new__(ProductionDispatcher)
    calls = []
    dispatcher.execute = lambda request, argv, **kw: calls.append(("execute", tuple(argv), kw)) or "ran"
    dispatcher.fetch_egress = lambda **kw: calls.append(("network", kw)) or "fetched"
    dispatcher.get_secret = lambda **kw: calls.append(("secret", kw)) or "secret"
    return ProductionEffectRouter(dispatcher), calls


def request():
    return object.__new__(DispatchRequest)


def test_unknown_effect_is_unreachable():
    gate, calls = router()
    with pytest.raises(DispatchDenied, match="no production adapter"):
        gate.dispatch(ProductionEffect("message.send", request(), {"body": "agent text"}))
    assert calls == []


def test_exact_execute_schema_routes_only_through_production_dispatcher(tmp_path):
    gate, calls = router()
    effect = ProductionEffect("process.execute", request(),
                              {"argv": ["/usr/bin/true"], "project_root": str(tmp_path), "timeout": 5})
    assert gate.dispatch(effect) == "ran"
    assert calls[0][0] == "execute"
    with pytest.raises(DispatchDenied, match="exact"):
        gate.dispatch(ProductionEffect("process.execute", request(),
                                      {"argv": ["/usr/bin/true"], "project_root": str(tmp_path),
                                       "timeout": 5, "agent_override": True}))


def test_coverage_is_explicit_about_unimplemented_effects():
    coverage = ProductionEffectRouter.coverage()
    assert coverage["default"] == "DENY"
    assert "publish" in coverage["unsupported"]
