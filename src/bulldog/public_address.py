"""One definition of "public destination" for every egress path.

Deny-listing categories (private, loopback, ...) misses shared address space
(100.64.0.0/10, used for some cloud metadata services) and IPv6 forms that
embed an internal IPv4 address. Require ``is_global`` for the address and for
any IPv4 address it carries.
"""

from __future__ import annotations

import ipaddress

_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def embedded_ipv4(address: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    found = []
    if address.ipv4_mapped:
        found.append(address.ipv4_mapped)
    if address.sixtofour:
        found.append(address.sixtofour)
    if address.teredo:
        found.extend(address.teredo)
    if address in _NAT64:
        found.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    return found


def is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> bool:
    if isinstance(address, str):
        address = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(address, ipaddress.IPv6Address):
        inner = embedded_ipv4(address)
        if inner:
            return all(x.is_global and not x.is_multicast for x in inner)
    return address.is_global and not address.is_multicast
