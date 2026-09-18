from __future__ import annotations

import pytest

from bulldog.sandbox_backends import (
    LinuxNamespaceBackend,
    MacOSSeatbeltBackend,
    SandboxBackendUnavailable,
    SandboxPolicy,
    WindowsAppContainerBackend,
    select_backend,
)


def test_policy_rejects_invalid_network_mode():
    with pytest.raises(ValueError, match="network_mode"):
        SandboxPolicy(network_mode="open-internet")


def test_policy_rejects_direct_secret_grant():
    with pytest.raises(ValueError, match="secret broker"):
        SandboxPolicy(allow_secrets=True)


def test_policy_rejects_nonpositive_output_limit():
    with pytest.raises(ValueError, match="max_output_bytes"):
        SandboxPolicy(max_output_bytes=0)


def test_linux_selects_linux_backend():
    assert isinstance(select_backend("Linux"), LinuxNamespaceBackend)


def test_macos_is_explicitly_fail_closed_until_native_backend_exists():
    backend = select_backend("Darwin")
    assert isinstance(backend, MacOSSeatbeltBackend)
    assert backend.probe().strict is False
    with pytest.raises(SandboxBackendUnavailable, match="not implemented"):
        backend.require_strict()


def test_windows_is_explicitly_fail_closed_until_native_backend_exists():
    backend = select_backend("Windows")
    assert isinstance(backend, WindowsAppContainerBackend)
    assert backend.probe().strict is False
    with pytest.raises(SandboxBackendUnavailable, match="not implemented"):
        backend.require_strict()


def test_unknown_host_is_fail_closed():
    backend = select_backend("FreeBSD")
    assert backend.probe().strict is False
    with pytest.raises(SandboxBackendUnavailable):
        backend.require_strict()
