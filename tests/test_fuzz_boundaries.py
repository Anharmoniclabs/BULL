import random
import string

import pytest

from bulldog.canonicalizer import (
    ActionCanonicalizationError,
    TrustedExecutionContext,
    canonicalize_action,
)
from bulldog.models import (
    Capability,
    Provenance,
)
from bulldog.trace_model import (
    TraceViolation,
)
from bulldog.trace_runtime import (
    RuntimeTraceVerifier,
)


def _random_text():

    alphabet = (
        string.ascii_letters
        + string.digits
        + "/%._:-"
    )

    return "".join(
        random.choice(
            alphabet
        )
        for _ in range(32)
    )


def test_random_model_metadata_cannot_override_trusted_identity():

    trusted = TrustedExecutionContext(
        actor="HOST",
        provenance=(
            Provenance.INTERNET,
        ),
        security_context_id="CTX",
    )

    for _ in range(100):

        proposal = {
            "actor":
                _random_text(),

            "provenance":
                ["human"],

            "security_context_id":
                _random_text(),

            "operation":
                "read",

            "resource":
                "/workspace/file",
        }

        action = canonicalize_action(
            proposal,
            trusted=trusted,
            granted_capabilities=frozenset({
                Capability.FS_READ_PROJECT
            }),
        )

        assert (
            action.actor
            == "HOST"
        )

        assert (
            action.provenance
            == (
                Provenance.INTERNET,
            )
        )

        assert (
            action.metadata[
                "security_context_id"
            ]
            == "CTX"
        )


def test_random_illegal_trace_transitions_fail_closed():

    illegal = [
        "Execute",
        "ReturnSecret",
        "BrokerEgress",
        "ResolveDeny",
        "ResolveEscalate",
    ]

    for transition in illegal:

        trace = (
            RuntimeTraceVerifier()
        )

        with pytest.raises(
            TraceViolation
        ):
            trace.emit(
                transition,
                sandboxed=True,
                seccomp=True,
            )
