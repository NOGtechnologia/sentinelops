from datetime import UTC, datetime

import pytest

from sentinelops.normalize.dedupe import (
    Deduplicator,
    event_id_for,
    file_hash,
    json_fingerprint,
    stable_hash,
    syslog_fingerprint,
    windows_fingerprint,
)
from sentinelops.normalize.quality import (
    Limits,
    Malformed,
    check_line,
    clip,
    decode_text,
    json_depth,
    load_json,
)
from sentinelops.normalize.schema import CanonicalEvent, MalformedCode, format_timestamp

T = datetime(2026, 3, 12, 9, 30, 1, 5, tzinfo=UTC)


def test_stable_hash_is_order_independent_for_dicts_and_sets() -> None:
    assert stable_hash({"a": 1, "b": 2}) == stable_hash({"b": 2, "a": 1})
    assert stable_hash({"x", "y"}) == stable_hash({"y", "x"})
    assert stable_hash(T) == stable_hash(format_timestamp(T))
    assert len(stable_hash("x", length=12)) == 12


def test_stable_hash_rejects_unknown_types() -> None:
    with pytest.raises(TypeError):
        stable_hash(object())


def test_windows_fingerprint_normalises_case() -> None:
    a = windows_fingerprint("DC01.musterfirma.example", "Security", 42, "Microsoft-Windows-Security-Auditing", T)
    b = windows_fingerprint("dc01.MUSTERFIRMA.example", "security", "42", "microsoft-windows-security-auditing", T)
    assert event_id_for(a) == event_id_for(b)
    assert event_id_for(windows_fingerprint(None, None, None, None, T))


def test_syslog_fingerprint_distinguishes_messages() -> None:
    a = syslog_fingerprint("srv-lnx01", T, "sshd", "123", "Failed password for root")
    b = syslog_fingerprint("srv-lnx01", T, "sshd", "123", "Failed password for admin")
    assert event_id_for(a) != event_id_for(b)
    assert syslog_fingerprint(None, T, None, None, "x")[1:5] == ("", format_timestamp(T), "", "")


def test_json_fingerprint_key_fields_and_hash() -> None:
    record = {"id": "e-1", "nested": {"k": 1}, "x": 2}
    assert json_fingerprint("p", record, ["id", "nested.k", "missing.path"]) == ("json", "p", ("e-1", 1, None))
    assert json_fingerprint("p", record, None) == json_fingerprint("p", {"x": 2, "nested": {"k": 1}, "id": "e-1"}, [])


def test_deduplicator() -> None:
    dedupe = Deduplicator()
    assert dedupe.check("e1", "r1") is None
    assert dedupe.check("e1", "r2") == "r1"
    assert dedupe.check("e2", "r3") is None


def test_file_hash() -> None:
    assert file_hash(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_decode_text() -> None:
    assert decode_text("﻿hällo".encode()) == "hällo"
    bad = decode_text(b"ab\xffcd")
    assert isinstance(bad, Malformed)
    assert bad.code is MalformedCode.INVALID_ENCODING
    assert bad.position == 2
    nul = decode_text(b"a\x00b")
    assert isinstance(nul, Malformed)
    assert nul.code is MalformedCode.INVALID_ENCODING
    big = decode_text(b"x" * 11, Limits(max_record_bytes=10))
    assert isinstance(big, Malformed)
    assert big.code is MalformedCode.OVERSIZED


def test_check_line() -> None:
    assert check_line("short") is None
    problem = check_line("x" * 11, Limits(max_line_bytes=10))
    assert problem is not None
    assert problem.code is MalformedCode.OVERSIZED


def test_json_depth() -> None:
    assert json_depth(1, 5) == 0
    assert json_depth({"a": [1, {"b": {}}]}, 10) == 4
    assert json_depth([[[[]]]], 2) == 3  # stops counting once over the limit
    assert json_depth({"a": {"b": {"c": {}}}}, 2) == 3


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ('{"a": 1', MalformedCode.TRUNCATED),
        ('{"a": "x', MalformedCode.TRUNCATED),
        ('{"a": 1}}', MalformedCode.PARSE_ERROR),
        ("not json", MalformedCode.PARSE_ERROR),
        ("[" * 5000 + "]" * 5000, MalformedCode.OVERSIZED),
        ('{"a": {"b": {"c": {"d": 1}}}}', MalformedCode.OVERSIZED),
    ],
)
def test_load_json_errors(text: str, code: MalformedCode) -> None:
    result = load_json(text, Limits(max_json_depth=3))
    assert isinstance(result, Malformed)
    assert result.code is code


def test_load_json_ok() -> None:
    assert load_json('{"a": [1, 2]}') == {"a": [1, 2]}


def test_clip() -> None:
    assert clip("abc", Limits(max_field_chars=5)) == "abc"
    assert clip("abcdefgh", Limits(max_field_chars=5)) == "abcde…"


def test_canonical_event_access_and_serialisation() -> None:
    event = CanonicalEvent(
        event_id="e1",
        timestamp=T,
        fields={"event.action": "logon", "event.outcome": "success", "event.ingested": T, "user.name": "alice"},
        original={"winlog.event_data.TargetSid": "S-1-5-21-1", "b": 1, "a": 2},
    )
    assert event.get("@timestamp") == T
    assert event.get("user.name") == "alice"
    assert event.get("winlog.event_data.TargetSid") == "S-1-5-21-1"
    assert event.get("nothing") is None
    assert event.action == "logon"
    assert event.outcome == "success"
    data = event.to_dict()
    assert data["@timestamp"] == "2026-03-12T09:30:01.000005Z"
    assert data["event.ingested"] == "2026-03-12T09:30:01.000005Z"
    assert list(data["original"]) == ["a", "b", "winlog.event_data.TargetSid"]
    assert CanonicalEvent.from_dict(data) == event
    naive = datetime(2026, 3, 12, 9, 30, 1, 5)  # naive values are taken as UTC
    assert format_timestamp(naive) == "2026-03-12T09:30:01.000005Z"
    bare = CanonicalEvent(event_id="e2", timestamp=T, fields={"event.action": 5})
    assert bare.action is None
    assert bare.outcome == "unknown"
    assert "original" not in bare.to_dict()
