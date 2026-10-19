"""Pseudonymised case reports (spec 16.2)."""

from __future__ import annotations

from sentinelops.reports.pseudonymize import build_mapping, pseudonymize_report

ENTITIES = [
    {"type": "user", "key": "anna", "display": "MUSTERFIRMA\\Anna"},
    {"type": "host", "key": "ws-017", "display": "WS-017.musterfirma.example"},
    {"type": "ip", "key": "192.0.2.5", "display": "192.0.2.5"},
    {"type": "user", "key": "admin", "display": "admin"},
]


def _report() -> dict[str, object]:
    return {
        "metadata": {"software_version": "1.0.0"},
        "case": {"title": "Brute Force auf ein Konto: anna", "entities": ENTITIES},
        "evidence": [
            {"raw": "Failed password for anna from 192.0.2.5 port 22", "user.name": "anna"},
            {"raw": "logon MUSTERFIRMA\\Anna on WS-017.musterfirma.example from 192.0.2.50"},
            {"raw": "anna@musterfirma.example added to Administrators by admin", "count": 3},
        ],
    }


def test_mapping_is_stable_and_ordered() -> None:
    mapping = build_mapping(ENTITIES)
    assert mapping["anna"] == mapping["musterfirma\\anna"] == "USER_2"
    assert mapping["admin"] == "USER_1"
    assert mapping["ws-017"] == "HOST_1"
    assert mapping["192.0.2.5"] == "IP_1"
    assert build_mapping(list(reversed(ENTITIES))) == mapping


def test_report_values_are_replaced_keys_and_lookalikes_kept() -> None:
    result = pseudonymize_report(_report())
    evidence = result["evidence"]
    assert result["case"]["title"] == "Brute Force auf ein Konto: USER_2"
    assert evidence[0] == {"raw": "Failed password for USER_2 from IP_1 port 22", "user.name": "USER_2"}
    # 192.0.2.50 is a different address; the domain-qualified display name is replaced as a whole
    assert evidence[1]["raw"] == "logon USER_2 on HOST_1 from 192.0.2.50"
    # mail address local part is replaced, "Administrators" does not contain the token "admin"
    assert evidence[2]["raw"] == "USER_2@musterfirma.example added to Administrators by USER_1"
    assert evidence[2]["count"] == 3
    assert result["metadata"] == {"pseudonymized": True, "software_version": "1.0.0"}
    assert pseudonymize_report(_report()) == result


def test_report_without_entities_is_only_marked() -> None:
    result = pseudonymize_report({"metadata": {}, "case": {"title": "x"}})
    assert result == {"metadata": {"pseudonymized": True}, "case": {"title": "x"}}
