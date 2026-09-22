from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Iterable

from .models import Capability


class PolicyBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicyBundle:
    project_root: str
    capability_ceiling: frozenset[Capability]
    key_id: str
    raw: dict


def _canonical_bytes(payload: dict) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_policy_bundle(
    *,
    project_root: str = "/workspace",
    allowed_capabilities: Iterable[Capability | str],
    key: bytes | str,
    key_id: str = "deployment-policy",
    human_approval: dict | None = None,
) -> dict:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise PolicyBundleError("policy signing key cannot be empty")

    capabilities = sorted(
        Capability(value).value
        for value in allowed_capabilities
    )
    payload = {
        "format": "bull-policy-v1",
        "project_root": str(project_root),
        "allowed_capabilities": capabilities,
        "signature": {
            "type": "hmac-sha256",
            "key_id": str(key_id),
            "value": "",
        },
    }
    if human_approval is not None:
        from .approval import validate_config
        payload["human_approval"] = validate_config(human_approval)
    payload["signature"]["value"] = hmac.new(
        key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    return payload


def verify_policy_bundle(payload: dict, key: bytes | str) -> PolicyBundle:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise PolicyBundleError("policy verification key cannot be empty")
    if payload.get("format") != "bull-policy-v1":
        raise PolicyBundleError("unsupported policy bundle format")

    signature = payload.get("signature")
    if not isinstance(signature, dict):
        raise PolicyBundleError("policy bundle is unsigned")
    if signature.get("type") != "hmac-sha256":
        raise PolicyBundleError("unsupported policy signature type")

    expected = hmac.new(
        key,
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    supplied = str(signature.get("value", ""))
    if not hmac.compare_digest(expected, supplied):
        raise PolicyBundleError("policy bundle signature mismatch")

    project_root = str(payload.get("project_root", "")).strip()
    if not project_root.startswith("/"):
        raise PolicyBundleError("policy project root must be absolute")

    try:
        capabilities = frozenset(
            Capability(value)
            for value in payload.get("allowed_capabilities", ())
        )
    except Exception as exc:
        raise PolicyBundleError("policy bundle contains invalid capability") from exc
    if not capabilities:
        raise PolicyBundleError("policy capability ceiling cannot be empty")

    if "human_approval" in payload:
        from .approval import validate_config
        validate_config(payload["human_approval"])

    return PolicyBundle(
        project_root=project_root,
        capability_ceiling=capabilities,
        key_id=str(signature.get("key_id", "")),
        raw=dict(payload),
    )


def load_policy_bundle(path: str | Path, key: bytes | str) -> PolicyBundle:
    try:
        payload = json.loads(Path(path).resolve(strict=True).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyBundleError(f"unable to read policy bundle: {exc}") from exc
    return verify_policy_bundle(payload, key)
