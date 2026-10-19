"""Edge cases of the parsers that the golden files do not reach."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from sentinelops.ingest.local import InputFile, file_sha256, ingest_files
from sentinelops.ingest.processing import process_stream
from sentinelops.normalize.dedupe import Deduplicator
from sentinelops.normalize.quality import Limits, Malformed
from sentinelops.normalize.schema import MalformedCode
from sentinelops.parsers.base import ParseContext, RawRecord, iter_lines
from sentinelops.parsers.json_mapped import (
    JsonMappedParser,
    MappingProfile,
    ProfileError,
    load_profile,
    load_profiles,
    lookup,
    map_document,
    validate_profile,
)
from sentinelops.parsers.json_split import split_json
from sentinelops.parsers.linux_auth import match_message
from sentinelops.parsers.registry import UnknownSourceTypeError, get_parser
from sentinelops.parsers.windows_evtx import WindowsEvtxParser
from sentinelops.parsers.windows_json import to_winevent
from sentinelops.parsers.windows_xml import WindowsXmlParser, split_events
from sentinelops.settings import PROFILES_DIR

REF = datetime(2026, 3, 12, 9, 30, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def ctx(**kw: object) -> ParseContext:
    return ParseContext(reference_utc=REF, timezone=ZoneInfo("Europe/Berlin"), **kw)  # type: ignore[arg-type]


def statuses(parser: object, data: bytes) -> list[tuple[str, str | None]]:
    out = process_stream(parser, io.BytesIO(data), ctx(), Deduplicator(), "f", REF)  # type: ignore[arg-type]
    return [(o.status.value, o.error.code.value if o.error else None) for o in out]


# --- EVTX -----------------------------------------------------------------------------


def test_evtx_bad_magic_and_truncated_file() -> None:
    parser = WindowsEvtxParser()
    assert statuses(parser, b"not an evtx file at all") == [("malformed", "PARSE_ERROR")]
    data = (FIXTURES / "evtx" / "new-user-security.evtx").read_bytes()
    result = statuses(parser, data[:5000])
    assert all(s in ("accepted", "malformed") for s, _ in result)


def test_evtx_record_without_data_and_bad_json() -> None:
    parser = WindowsEvtxParser()
    assert isinstance(parser.parse(RawRecord(1, b"\xff"), ctx()), Malformed)
    assert isinstance(parser.parse(RawRecord(1, b"{not json"), ctx()), Malformed)
    assert isinstance(parser.parse(RawRecord(1, b'{"x": 1}'), ctx()), Malformed)


def test_evtx_consecutive_error_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelops.parsers import windows_evtx

    class Broken:
        def __init__(self, _: object) -> None:
            pass

        def records_json(self) -> object:
            class It:
                calls = 0

                def __iter__(self) -> object:
                    return self

                def __next__(self) -> dict[str, object]:
                    It.calls += 1
                    if It.calls == 1:
                        return {"data": 5}
                    raise RuntimeError("bad chunk")

            return It()

    monkeypatch.setattr(windows_evtx, "PyEvtxParser", Broken)
    monkeypatch.setattr(windows_evtx, "MAX_CONSECUTIVE_ERRORS", 3)
    result = statuses(WindowsEvtxParser(), windows_evtx.EVTX_MAGIC + b"\x00" * 10)
    assert result == [("malformed", "PARSE_ERROR")] * 4

    class Fails:
        def __init__(self, _: object) -> None:
            raise OSError("header broken")

    monkeypatch.setattr(windows_evtx, "PyEvtxParser", Fails)
    assert statuses(WindowsEvtxParser(), windows_evtx.EVTX_MAGIC) == [("malformed", "PARSE_ERROR")]


# --- XML ------------------------------------------------------------------------------


def test_xml_utf16_export_and_entities() -> None:
    xml = (FIXTURES / "windows_xml" / "security_sample.xml").read_text(encoding="utf-8")
    for encoding, bom in (("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")):
        data = bom + xml.encode(encoding)
        assert [s for s, _ in statuses(WindowsXmlParser(), data)] == ["accepted"] * 7
    bomb = b'<!DOCTYPE x [<!ENTITY a "aaaa">]><Event xmlns="x"><System><EventID>1</EventID></System>&a;</Event>'
    assert statuses(WindowsXmlParser(), bomb) == [("malformed", "PARSE_ERROR")]
    wrong_root = b"<Event><System></System></Event>"
    assert statuses(WindowsXmlParser(), wrong_root) == [("malformed", "SCHEMA_VIOLATION")]
    classic = (
        b'<Event xmlns="x"><System><EventID>4625</EventID><TimeCreated SystemTime="2026-03-12T08:00:00Z"/>'
        b"</System><EventData><Data>first</Data><Data>second</Data></EventData></Event>"
    )
    out = list(process_stream(WindowsXmlParser(), io.BytesIO(classic), ctx(), Deduplicator(), "f", REF))
    assert out[0].event is not None
    assert out[0].event.original["winlog.event_data.Data0"] == "first"
    bad_time = b'<Event xmlns="x"><System><EventID>1</EventID><TimeCreated SystemTime="yesterday"/></System></Event>'
    assert statuses(WindowsXmlParser(), bad_time) == [("malformed", "PARSE_ERROR")]


def test_xml_splitter_oversized_and_chunk_boundaries() -> None:
    event = b'<Event xmlns="x"><System><EventID>1</EventID></System></Event>'
    data = b"junk" * 10 + event + b"<Event " + b"x" * 300 + b"</Event>" + event
    records = list(split_events(io.BytesIO(data), max_record_bytes=200, chunk_size=7))
    kinds = ["bad" if isinstance(r, tuple) else "ok" for r in records]
    assert kinds == ["ok", "bad", "ok"]
    assert records[1][1].code is MalformedCode.OVERSIZED  # type: ignore[index]


# --- JSON split & mapped ----------------------------------------------------------------


def test_json_array_scalars_and_unclosed() -> None:
    data = b'[{"a": 1}, "str,ing", 5, {"b": [1, {"c": "]"}]}]'
    records = list(split_json(io.BytesIO(data), Limits(), chunk_size=3))
    kinds = [r[1].code.value if isinstance(r, tuple) else "ok" for r in records]
    assert kinds == ["ok", "SCHEMA_VIOLATION", "SCHEMA_VIOLATION", "ok"]
    unclosed = list(split_json(io.BytesIO(b'[{"a": 1}, '), Limits()))
    assert isinstance(unclosed[-1], tuple)
    assert unclosed[-1][1].code is MalformedCode.TRUNCATED
    big = list(split_json(io.BytesIO(b'[{"a": "' + b"x" * 100 + b'"}]'), Limits(max_record_bytes=20)))
    assert big[0][1].code is MalformedCode.OVERSIZED  # type: ignore[index]
    assert list(split_json(io.BytesIO(b"   \n "), Limits())) == []
    long_line = list(split_json(io.BytesIO(b'{"a": "' + b"x" * 100 + b'"}\n'), Limits(max_line_bytes=20)))
    assert long_line[0][1].code is MalformedCode.OVERSIZED  # type: ignore[index]


def test_iter_lines_clips_overlong_lines() -> None:
    lines = list(iter_lines(io.BytesIO(b"a" * 50 + b"\nshort\r\nlast"), Limits(max_line_bytes=10), chunk_size=4))
    assert [len(r.content) for r in lines] == [11, 5, 4]
    assert lines[1].offset == 51


PROFILE = {
    "name": "edge",
    "timestamp": {"field": "t", "format": "strptime:%d.%m.%Y %H:%M", "timezone": "Europe/Berlin"},
    "fields": {"user.name": "u", "logon.type": "lt", "source.port": "p", "user.target.name": "tu", "host.name": "h"},
    "action": {"field": "kind", "map": {"1": "logon"}, "default": "logon-failed"},
    "outcome": {"field": "ok", "map": {"true": "success", "false": "failure"}},
    "examples": [{"input": {"t": "12.03.2026 10:30"}, "expect": {"@timestamp": "2026-03-12T09:30:00.000000Z"}}],
}


def test_mapped_profile_conversions() -> None:
    profile = MappingProfile.model_validate(PROFILE)
    validate_profile(profile, REF)
    good = map_document(
        profile,
        {
            "t": "12.03.2026 10:30",
            "u": "DOM\\anna",
            "lt": "3",
            "p": 22,
            "tu": "-",
            "h": "x" * 20000,
            "kind": 1,
            "ok": True,
        },
        ctx(),
    )
    assert not isinstance(good, Malformed)
    assert good.fields["user.domain"] == "DOM"
    assert good.fields["logon.type"] == 3
    assert good.fields["event.action"] == "logon"
    assert good.fields["event.outcome"] == "success"
    assert len(good.fields["host.name"]) < 20000
    bad_int = map_document(profile, {"t": "12.03.2026 10:30", "lt": "three"}, ctx())
    assert isinstance(bad_int, Malformed)
    assert map_document(profile, [1, 2], ctx()).code is MalformedCode.SCHEMA_VIOLATION  # type: ignore[union-attr]
    aware = MappingProfile.model_validate(
        {**PROFILE, "timestamp": {"field": "t", "format": "strptime:%Y-%m-%d %H:%M%z"}}
    )
    result = map_document(aware, {"t": "2026-03-12 10:30+0100"}, ctx())
    assert not isinstance(result, Malformed)
    assert result.time.utc == REF
    nonstr = map_document(aware, {"t": 5}, ctx())
    assert isinstance(nonstr, Malformed)
    iso = MappingProfile.model_validate({**PROFILE, "timestamp": {"field": "t"}})
    assert isinstance(map_document(iso, {"t": 5}, ctx()), Malformed)
    epoch = MappingProfile.model_validate({**PROFILE, "timestamp": {"field": "t", "format": "epoch_s"}})
    assert isinstance(map_document(epoch, {"t": True}, ctx()), Malformed)
    assert not isinstance(map_document(epoch, {"t": "1773307800.5"}, ctx()), Malformed)


def test_lookup_paths() -> None:
    doc = {"a.b": 1, "a": {"b": 2, "c": [10, 20]}}
    assert lookup(doc, "a.b") == 1
    assert lookup(doc, "a.c.1") == 20
    assert lookup(doc, "a.c.5") is None
    assert lookup(doc, "x.y") is None


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"fields": {"event.id": "x"}}, "not a mappable"),
        ({"action": {"map": {"x": "explode"}}}, "unknown event.action"),
        ({"outcome": {"map": {"x": "maybe"}}}, "invalid outcome"),
        ({"timestamp": {"field": "t", "format": "rfc822"}}, "unsupported timestamp format"),
        ({"timestamp": {"field": "t", "timezone": "Mars/Base"}}, "unknown time zone"),
        ({"constants": {"event.action": "explode"}}, "unknown event.action"),
    ],
)
def test_profile_validation_errors(change: dict[str, object], message: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match=message):
        MappingProfile.model_validate({**PROFILE, **change})


def test_profile_example_mismatches(tmp_path: Path) -> None:
    bad = MappingProfile.model_validate({**PROFILE, "examples": [{"input": {"t": "x"}, "expect": {}}]})
    with pytest.raises(ProfileError, match="PARSE_ERROR"):
        validate_profile(bad, REF)
    wrong = MappingProfile.model_validate(
        {**PROFILE, "examples": [{"input": {"t": "12.03.2026 10:30"}, "expect_malformed": "PARSE_ERROR"}]}
    )
    with pytest.raises(ProfileError, match="expected"):
        validate_profile(wrong, REF)
    value = MappingProfile.model_validate(
        {**PROFILE, "examples": [{"input": {"t": "12.03.2026 10:30"}, "expect": {"user.name": "nobody"}}]}
    )
    with pytest.raises(ProfileError, match="user.name"):
        validate_profile(value, REF)
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [", encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profile(broken, REF)
    dup = tmp_path / "profiles"
    dup.mkdir()
    for n in ("a.yaml", "b.yaml"):
        (dup / n).write_text((PROFILES_DIR / "generic.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ProfileError, match="duplicate"):
        load_profiles(dup, REF)


def test_registry_and_local_ingest(tmp_path: Path) -> None:
    with pytest.raises(UnknownSourceTypeError):
        get_parser("json:missing", {})
    with pytest.raises(UnknownSourceTypeError):
        get_parser("csv", {})
    log = FIXTURES / "syslog_3164" / "auth.log"
    seen: set[str] = set()
    first = ingest_files([InputFile(log, "syslog_3164", "Europe/Berlin")], {}, REF, seen_files=seen)
    again = ingest_files(
        [InputFile(log, "syslog_3164", "Europe/Berlin")], {}, REF, seen_files=seen, keep_outcomes=False
    )
    assert first.counts() == {"accepted": 13, "duplicate": 0, "malformed": 2}
    assert again.skipped_files == [str(log)]
    assert len(file_sha256(log)) == 64
    mapped = JsonMappedParser(load_profiles(PROFILES_DIR, REF)["generic"])
    assert mapped.source_type == "json:generic"


def test_windows_json_shapes_edge() -> None:
    assert isinstance(to_winevent([1]), Malformed)
    event = to_winevent(
        {
            "Event": {
                "System": {"EventID": {"#text": "4624"}, "TimeCreated": {}},
                "UserData": {"X": {"SubjectUserName": "a", "Nested": {"#text": "v"}}},
            }
        }
    )
    assert not isinstance(event, Malformed)
    assert event.data == {"SubjectUserName": "a", "Nested": "v"}
    ps = to_winevent(
        {
            "Id": 4624,
            "LogName": "Security",
            "TimeCreated": "/Date(99999999999999999999)/",
            "EventData": {"Flag": True, "N": 1.5, "Obj": {"a": 1}},
        }
    )
    assert not isinstance(ps, Malformed)
    assert ps.time_created is None
    assert ps.data == {"Flag": "true", "N": "1.5"}
    beat = to_winevent({"winlog": {"event_id": True, "event_data": "nope", "user_data": {"A": "b"}}})
    assert isinstance(beat, Malformed)


def test_linux_patterns_unknown_program_and_path() -> None:
    assert match_message(None, "x") is None
    assert match_message("nginx", "Failed password for root") is None
    assert match_message("/usr/sbin/sshd", "Accepted publickey for a from 10.0.0.1 port 1 ssh2") is not None
    no_match = match_message("sshd", "Server listening on 0.0.0.0 port 22.")
    assert no_match is None
    host = match_message("sshd", "Failed password for root from host.example port 22 ssh2")
    assert host is not None
    assert host.fields["source.host"] == "host.example"
