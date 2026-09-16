from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import socket
import ssl
import urllib.parse

from .egress_proxy import (
    EgressDenied,
    EgressResponse,
)


class _PinnedHTTPSConnection(
    http.client.HTTPSConnection
):

    def __init__(
        self,
        *,
        hostname: str,
        ip: str,
        port: int,
        timeout: float,
    ):

        self._bull_hostname = (
            hostname
        )

        self._bull_ip = ip

        context = (
            ssl.create_default_context()
        )

        super().__init__(
            host=hostname,
            port=port,
            timeout=timeout,
            context=context,
        )


    def connect(
        self
    ) -> None:

        raw = socket.create_connection(
            (
                self._bull_ip,
                self.port,
            ),
            self.timeout,
        )

        self.sock = (
            self._context
            .wrap_socket(
                raw,
                server_hostname=(
                    self._bull_hostname
                ),
            )
        )


def resolve_public_once(
    hostname: str,
    port: int,
) -> str:

    infos = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
    )

    public = []

    for info in infos:

        raw = info[4][0].split(
            "%",
            1,
        )[0]

        address = (
            ipaddress.ip_address(
                raw
            )
        )

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            continue

        public.append(
            str(address)
        )

    if not public:
        raise EgressDenied(
            "no permitted public destination"
        )

    # Pin one validated address.
    return sorted(
        set(public)
    )[0]


def pinned_https_fetch(
    *,
    url: str,
    allowed_hosts:
        set[str]
        | frozenset[str],
    method: str = "GET",
    timeout: float = 8.0,
    max_bytes: int = 1024 * 1024,
) -> EgressResponse:

    parsed = urllib.parse.urlsplit(
        url
    )

    if parsed.scheme != "https":
        raise EgressDenied(
            "HTTPS required"
        )

    if (
        parsed.username
        or parsed.password
    ):
        raise EgressDenied(
            "URL credentials forbidden"
        )

    hostname = (
        parsed.hostname
        or ""
    ).lower().rstrip(".")

    normalized_hosts = {
        x.lower().rstrip(".")
        for x in allowed_hosts
    }

    if hostname not in normalized_hosts:
        raise EgressDenied(
            "hostname not granted"
        )

    method = method.upper()

    if method not in {
        "GET",
        "HEAD",
    }:
        raise EgressDenied(
            "method not granted"
        )

    port = (
        parsed.port
        or 443
    )

    ip = resolve_public_once(
        hostname,
        port,
    )

    path = (
        parsed.path
        or "/"
    )

    if parsed.query:
        path += (
            "?"
            + parsed.query
        )

    connection = (
        _PinnedHTTPSConnection(
            hostname=hostname,
            ip=ip,
            port=port,
            timeout=timeout,
        )
    )

    try:

        connection.request(
            method,
            path,
            headers={
                "Host":
                    hostname,

                "User-Agent":
                    "BULL-PinnedEgress/1",
            },
        )

        response = (
            connection.getresponse()
        )

        # Redirects stay disabled.
        if (
            300
            <= response.status
            < 400
        ):
            raise EgressDenied(
                "redirect denied"
            )

        body = response.read(
            max_bytes + 1
        )

        if len(body) > max_bytes:
            raise EgressDenied(
                "response too large"
            )

        return EgressResponse(
            status=int(
                response.status
            ),
            headers={
                str(k): str(v)
                for k, v
                in response.getheaders()
            },
            body=body,
        )

    finally:

        connection.close()
