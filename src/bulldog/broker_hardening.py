from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import secrets
import threading
import time

from .secret_broker import (
    SecretBroker,
    SecretBrokerError,
)


class BrokerGrantError(
    RuntimeError
):
    pass


@dataclass
class ScopedGrant:

    grant_id: str

    sandbox_id: str

    names: frozenset[str]

    expires_at: float

    max_uses: int

    uses: int = 0

    revoked: bool = False


class HardenedSecretBroker(
    SecretBroker
):
    """
    Adds:
      - sandbox binding
      - usage limits
      - revocation
      - replay/over-use rejection
      - synchronized grant accounting
    """

    def __init__(
        self,
        *args,
        **kwargs,
    ):

        super().__init__(
            *args,
            **kwargs,
        )

        self._scoped: dict[
            str,
            ScopedGrant
        ] = {}

        self._scoped_lock = (
            threading.Lock()
        )


    def issue_scoped_grant(
        self,
        *,
        sandbox_id: str,
        allowed_names:
            set[str]
            | frozenset[str],
        ttl_seconds: float = 30.0,
        max_uses: int = 1,
    ) -> ScopedGrant:

        if max_uses < 1:
            raise ValueError(
                "max_uses must be >= 1"
            )

        names = frozenset(
            str(x)
            for x in allowed_names
        )

        unknown = names.difference(
            self._secrets
        )

        if unknown:
            raise SecretBrokerError(
                "unknown secrets: "
                + ", ".join(
                    sorted(unknown)
                )
            )

        grant_id = (
            secrets.token_urlsafe(
                32
            )
        )

        grant = ScopedGrant(
            grant_id=grant_id,
            sandbox_id=str(
                sandbox_id
            ),
            names=names,
            expires_at=(
                time.time()
                + ttl_seconds
            ),
            max_uses=int(
                max_uses
            ),
        )

        with self._scoped_lock:
            self._scoped[
                grant_id
            ] = grant

        return grant


    def revoke_scoped(
        self,
        grant_id: str,
    ) -> None:

        with self._scoped_lock:

            grant = self._scoped.get(
                grant_id
            )

            if grant is not None:
                grant.revoked = True


    def get_scoped(
        self,
        *,
        grant_id: str,
        sandbox_id: str,
        name: str,
    ) -> str:

        with self._scoped_lock:

            grant = self._scoped.get(
                grant_id
            )

            if grant is None:
                raise BrokerGrantError(
                    "unknown grant"
                )

            if grant.revoked:
                raise BrokerGrantError(
                    "grant revoked"
                )

            if (
                time.time()
                > grant.expires_at
            ):
                raise BrokerGrantError(
                    "grant expired"
                )

            if (
                str(sandbox_id)
                != grant.sandbox_id
            ):
                raise BrokerGrantError(
                    "grant belongs to another sandbox"
                )

            if name not in grant.names:
                raise BrokerGrantError(
                    "secret not granted"
                )

            if (
                grant.uses
                >= grant.max_uses
            ):
                raise BrokerGrantError(
                    "grant usage exhausted"
                )

            grant.uses += 1

        return self._secrets[
            name
        ]
