import pytest

from sentinelops.normalize.identities import (
    UserIdentity,
    canonical_ip,
    host_key,
    is_empty,
    is_internal_ip,
    network_key,
    split_user,
    user_key,
)


@pytest.mark.parametrize(
    ("raw", "domain", "expected"),
    [
        ("MUSTERFIRMA\\Erika.Muster", None, UserIdentity("Erika.Muster", "MUSTERFIRMA")),
        ("erika.muster@musterfirma.example", None, UserIdentity("erika.muster", "musterfirma.example")),
        ("erika.muster", "MUSTERFIRMA", UserIdentity("erika.muster", "MUSTERFIRMA")),
        ("erika.muster", "-", UserIdentity("erika.muster", None)),
        ("  root ", None, UserIdentity("root", None)),
        ("\\alice", "DOM", UserIdentity("alice", "DOM")),
        ("DOM\\", None, UserIdentity("DOM\\", None)),
        ("@domain", None, UserIdentity("@domain", None)),
    ],
)
def test_split_user(raw: str, domain: str | None, expected: UserIdentity) -> None:
    assert split_user(raw, domain) == expected


@pytest.mark.parametrize("raw", [None, "", "-", "  ", "N/A", "(null)"])
def test_split_user_empty(raw: str | None) -> None:
    assert split_user(raw) is None
    assert is_empty(raw)


def test_none_is_a_real_group_name() -> None:
    assert not is_empty("None")


def test_user_key_unifies_notations() -> None:
    assert user_key("MUSTERFIRMA\\Erika.Muster") == user_key("erika.muster@musterfirma.example") == "erika.muster"
    assert user_key("-") is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("DC01.musterfirma.example", "dc01"), ("dc01.", "dc01"), ("10.0.0.1", "10.0.0.1"), ("-", None), (None, None), (".", None)],
)
def test_host_key(raw: str | None, expected: str | None) -> None:
    assert host_key(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.45", "203.0.113.45"),
        ("::ffff:203.0.113.45", "203.0.113.45"),
        ("[2001:DB8::1]", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("-", None),
        ("not-an-ip", None),
        ("999.1.1.1", None),
        (None, None),
    ],
)
def test_canonical_ip(raw: str | None, expected: str | None) -> None:
    assert canonical_ip(raw) == expected


@pytest.mark.parametrize(
    ("ip", "internal"),
    [
        ("10.20.1.5", True),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("169.254.0.3", True),
        ("203.0.113.45", False),  # RFC 5737 = "external" in test data
        ("198.51.100.7", False),
        ("2001:db8::1", False),
        ("8.8.8.8", False),
    ],
)
def test_is_internal_ip(ip: str, internal: bool) -> None:
    assert is_internal_ip(ip) is internal


def test_network_key() -> None:
    assert network_key("203.0.113.45") == "203.0.113.0/24"
    assert network_key("2001:db8:1:2::5") == "2001:db8:1:2::/64"
