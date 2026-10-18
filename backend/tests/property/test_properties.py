"""Property tests (spec 15.2): parsers never crash, duplicate imports change
nothing, time normalisation around DST switches is consistent."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sentinelops.ingest.processing import process_stream
from sentinelops.normalize.dedupe import Deduplicator
from sentinelops.normalize.schema import RecordStatus
from sentinelops.normalize.timestamps import localize
from sentinelops.parsers.base import ParseContext
from sentinelops.parsers.json_mapped import load_profiles
from sentinelops.parsers.registry import get_parser, source_types
from sentinelops.settings import PROFILES_DIR

REF = datetime(2026, 3, 12, 9, 30, tzinfo=UTC)
PROFILES = load_profiles(PROFILES_DIR, REF)
TYPES = source_types(PROFILES)
BERLIN = ZoneInfo("Europe/Berlin")

LINE_FRAGMENTS = st.sampled_from([
    b"Mar 12 10:00:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2",
    b"<38>1 2026-03-12T10:00:00Z srv sshd 1 - - Accepted password for a from 10.0.0.1 port 2 ssh2",
    b'{"ts": 1773309000000, "seq": 1, "gateway": "vpn01", "type": "auth", "result": "ok", "user": "a"}',
    b'{"@timestamp": "2026-03-12T10:00:00Z", "winlog": {"event_id": 4625, "event_data": {"TargetUserName": "x"}}}',
    b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID>'
    b'<TimeCreated SystemTime="2026-03-12T10:00:00Z"/></System></Event>',
    b'{"__REALTIME_TIMESTAMP": "1773309000000000", "MESSAGE": "x", "SYSLOG_IDENTIFIER": "sshd"}',
    b"[", b"]", b"{", b"}", b"\xff\xfe", b"\x00", b"<!DOCTYPE x [<!ENTITY a 'b'>]>", b'"', b"\\",
])


def run(source_type: str, data: bytes, dedupe: Deduplicator | None = None) -> list[tuple[str, str | None]]:
    parser = get_parser(source_type, PROFILES)
    ctx = ParseContext(reference_utc=REF, timezone=BERLIN)
    outcomes = process_stream(parser, io.BytesIO(data), ctx, dedupe or Deduplicator(), "f" * 64, REF)
    return [(o.status.value, o.event_id) for o in outcomes]


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(TYPES), st.binary(max_size=2000))
def test_parsers_never_crash_on_arbitrary_bytes(source_type: str, data: bytes) -> None:
    for status, _ in run(source_type, data):
        assert status in {s.value for s in RecordStatus}


@settings(max_examples=150, deadline=None)
@given(st.sampled_from(TYPES), st.lists(LINE_FRAGMENTS, max_size=12), st.sampled_from([b"\n", b"\r\n", b"", b" "]))
def test_parsers_never_crash_on_structured_garbage(source_type: str, parts: list[bytes], sep: bytes) -> None:
    run(source_type, sep.join(parts))


@settings(max_examples=60, deadline=None)
@given(st.sampled_from(["syslog_3164", "syslog_5424", "json:musterfirma_vpn", "windows_json", "journald_json"]),
       st.lists(LINE_FRAGMENTS, min_size=1, max_size=10))
def test_duplicate_import_changes_nothing(source_type: str, parts: list[bytes]) -> None:
    data = b"\n".join(parts) + b"\n"
    dedupe = Deduplicator()
    first = run(source_type, data, dedupe)
    second = run(source_type, data, dedupe)
    accepted_first = {e for s, e in first if s == "accepted"}
    assert not any(s == "accepted" for s, _ in second)
    assert {e for s, e in second if s == "duplicate"} == accepted_first | {e for s, e in first if s == "duplicate"}


@settings(max_examples=200, deadline=None)
@given(st.datetimes(min_value=datetime(2025, 3, 1), max_value=datetime(2027, 11, 30)))
def test_localize_matches_zoneinfo_or_flags_the_gap(naive: datetime) -> None:
    result = localize(naive, BERLIN)
    back = result.utc.astimezone(BERLIN).replace(tzinfo=None)
    if result.flags == ("nonexistent_local_time",):
        assert back - naive == timedelta(hours=1)  # spring forward gap is skipped
    else:
        assert back == naive
    assert result.utc.tzinfo is UTC


@settings(max_examples=100, deadline=None)
@given(st.integers(min_value=0, max_value=3 * 3600 - 1))
def test_monotone_stream_through_fall_back(offset: int) -> None:
    """A chronological stream of local times across the October switch maps to
    non-decreasing UTC times when the previous event is passed as context."""
    start_utc = datetime(2026, 10, 24, 23, 0, tzinfo=UTC)  # 01:00 CEST
    previous = None
    for step in range(0, offset + 1, max(1, offset // 20 or 1)):
        true_utc = start_utc + timedelta(seconds=step)
        local_naive = true_utc.astimezone(BERLIN).replace(tzinfo=None)
        result = localize(local_naive, BERLIN, previous)
        assert result.utc == true_utc
        previous = result.utc
