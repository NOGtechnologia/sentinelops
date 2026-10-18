"""Identity normalisation: user names, host names and IP addresses (spec 5.3).

Original spelling is always preserved in the event; the functions here produce
the *comparison keys* used for grouping, correlation and entity linking.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

#: Placeholder values Windows and syslog emit when a field has no value.
#: "None" is deliberately *not* a placeholder: it is the name of the default
#: Windows group (RID 513) on workgroup machines (seen in the EVTX fixtures).
_EMPTY_MARKERS = frozenset({"", "-", "n/a", "(null)"})


@dataclass(frozen=True, slots=True)
class UserIdentity:
    name: str
    domain: str | None

    @property
    def key(self) -> str:
        """Case-insensitive comparison key without domain (``alice``)."""
        return self.name.casefold()


def is_empty(value: str | None) -> bool:
    return value is None or value.strip().casefold() in _EMPTY_MARKERS


def split_user(raw: str | None, domain: str | None = None) -> UserIdentity | None:
    """Split ``DOMAIN\\user`` and ``user@domain`` notations.

    >>> split_user("MUSTERFIRMA\\\\Alice")
    UserIdentity(name='Alice', domain='MUSTERFIRMA')
    >>> split_user("alice@musterfirma.example")
    UserIdentity(name='alice', domain='musterfirma.example')
    """
    if raw is None or is_empty(raw):
        return None
    value = raw.strip()
    found_domain = None if is_empty(domain) else (domain or "").strip()
    if "\\" in value:
        left, _, right = value.partition("\\")
        if right:
            value, found_domain = right, left or found_domain
    elif "@" in value:
        left, _, right = value.rpartition("@")
        if left and right:
            value, found_domain = left, right
    return UserIdentity(name=value, domain=found_domain)


def user_key(raw: str | None) -> str | None:
    """Comparison key for a user name in any notation."""
    identity = split_user(raw)
    return identity.key if identity else None


def host_key(raw: str | None) -> str | None:
    """Comparison key for a host: short name, case folded (``DC01.example`` -> ``dc01``)."""
    if raw is None or is_empty(raw):
        return None
    value = raw.strip().rstrip(".")
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value.split(".", 1)[0].casefold()
    return value


def canonical_ip(raw: str | None) -> str | None:
    """Validate and canonicalise an IP address.

    * IPv4-mapped IPv6 addresses (``::ffff:192.0.2.1``) become plain IPv4.
    * IPv6 is returned in compressed lowercase form.
    * Brackets, zone ids (``%eth0``) and Windows placeholders are handled.
    Returns ``None`` for anything that is not an IP address.
    """
    if raw is None or is_empty(raw):
        return None
    value = raw.strip().strip("[]")
    if "%" in value:
        value = value.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return address.compressed


def is_internal_ip(value: str) -> bool:
    """Private, loopback and link-local addresses count as internal."""
    address = ipaddress.ip_address(value)
    if address.is_loopback or address.is_link_local:
        return True
    return address.is_private and not _is_documentation(address)


_DOC_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _is_documentation(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # RFC 5737 / RFC 3849 ranges are flagged "private" by Python's ipaddress but
    # represent *external* addresses in our test data (spec section 11).
    return any(address in net for net in _DOC_NETS if net.version == address.version)


def network_key(value: str) -> str:
    """The /24 (IPv4) or /64 (IPv6) network an address belongs to."""
    address = ipaddress.ip_address(value)
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
