"""OpenShell as a BULL execution backend: probe it, and refuse it when unready.

BULL does not launch OpenShell sandboxes itself here; it verifies that the
gateway it is about to trust is running, is the expected version, and has
negotiated BULL's middleware and interceptor, before any governed work runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import subprocess
import urllib.request

from . import INTERCEPTOR_NAME, MIDDLEWARE_NAME


class OpenShellUnavailable(RuntimeError):
    pass


@dataclass
class OpenShellProbe:
    healthy: bool
    version: str
    extensions: str
    checks: dict = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return all(self.checks.values())


class OpenShellBackend:
    backend_name = "nvidia-openshell"

    def __init__(self, *, cli: str, gateway_endpoint: str, health_url: str,
                 expected_version: str | None = None):
        self.cli, self.endpoint = cli, gateway_endpoint
        self.health_url, self.expected_version = health_url, expected_version

    def _cli(self, *args) -> str:
        done = subprocess.run([self.cli, "--gateway-endpoint", self.endpoint, *args],
                              capture_output=True, text=True, timeout=30)
        return done.stdout + done.stderr

    def probe(self) -> OpenShellProbe:
        try:
            with urllib.request.urlopen(self.health_url, timeout=5) as response:
                healthy = response.status == 200
        except OSError:
            healthy = False
        version = self._cli("--version").strip() if healthy else ""
        info = self._cli("gateway", "info") if healthy else ""
        checks = {
            "gateway_healthy": healthy,
            "bull_middleware_negotiated": MIDDLEWARE_NAME in info,
            "bull_interceptor_negotiated": INTERCEPTOR_NAME in info,
        }
        if self.expected_version:
            checks["expected_version"] = self.expected_version in version
        return OpenShellProbe(healthy, version, info, checks)

    def require_strict(self) -> OpenShellProbe:
        probe = self.probe()
        if not probe.ready:
            missing = [k for k, ok in probe.checks.items() if not ok]
            raise OpenShellUnavailable(f"OpenShell backend not ready: {missing}")
        return probe
