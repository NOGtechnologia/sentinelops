from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from sentinelops.normalize.schema import TimeQuality
from sentinelops.normalize.timestamps import (
    FLAG_AMBIGUOUS_LOCAL_TIME,
    FLAG_ANCIENT_TIMESTAMP,
    FLAG_FUTURE_TIMESTAMP,
    FLAG_NONEXISTENT_LOCAL_TIME,
    NormalizedTime,
    SkewPolicy,
    TimestampError,
    apply_skew_policy,
    from_epoch,
    infer_year,
    localize,
    normalize_iso,
    parse_iso8601,
    parse_rfc3164_time,
    worst_quality,
)

BERLIN = ZoneInfo("Europe/Berlin")


@pytest.mark.parametrize(
    ("text", "expected", "has_offset"),
    [
        ("2026-03-12T09:30:00Z", datetime(2026, 3, 12, 9, 30, tzinfo=UTC), True),
        ("2026-03-12T09:30:00.1234567Z", datetime(2026, 3, 12, 9, 30, 0, 123456, tzinfo=UTC), True),
        ("2026-03-12 10:30:00+01:00", datetime(2026, 3, 12, 9, 30, tzinfo=UTC), True),
        ("2026-03-12T10:30:00+0100", datetime(2026, 3, 12, 9, 30, tzinfo=UTC), True),
        ("2026-03-12T05:00:00-05:00", datetime(2026, 3, 12, 10, 0, tzinfo=UTC), True),
        ("2026-03-12T09:30:00,5z", datetime(2026, 3, 12, 9, 30, 0, 500000, tzinfo=UTC), True),
        ("2026-03-12T09:30:00", datetime(2026, 3, 12, 9, 30), False),
    ],
)
def test_parse_iso8601(text: str, expected: datetime, has_offset: bool) -> None:
    assert parse_iso8601(text) == (expected, has_offset)


@pytest.mark.parametrize("text", ["", "12.03.2026 10:00", "2026-13-01T00:00:00Z", "2026-03-12T10:00:00+25:00"])
def test_parse_iso8601_rejects(text: str) -> None:
    with pytest.raises(TimestampError):
        parse_iso8601(text)


def test_localize_regular_time() -> None:
    result = localize(datetime(2026, 3, 12, 10, 30), BERLIN)
    assert result.utc == datetime(2026, 3, 12, 9, 30, tzinfo=UTC)
    assert result.quality is TimeQuality.ASSUMED_TIMEZONE
    assert result.flags == ()


def test_localize_rejects_aware() -> None:
    with pytest.raises(TimestampError):
        localize(datetime(2026, 3, 12, tzinfo=UTC), BERLIN)


def test_spring_forward_nonexistent_hour() -> None:
    # 2026-03-29 02:00 CET -> 03:00 CEST: 02:30 does not exist in Berlin.
    result = localize(datetime(2026, 3, 29, 2, 30), BERLIN)
    assert result.flags == (FLAG_NONEXISTENT_LOCAL_TIME,)
    assert result.utc == datetime(2026, 3, 29, 1, 30, tzinfo=UTC)  # == 03:30 CEST


def test_spring_forward_neighbours_exact() -> None:
    before = localize(datetime(2026, 3, 29, 1, 59), BERLIN)
    after = localize(datetime(2026, 3, 29, 3, 0), BERLIN)
    assert before.utc == datetime(2026, 3, 29, 0, 59, tzinfo=UTC)
    assert after.utc == datetime(2026, 3, 29, 1, 0, tzinfo=UTC)
    assert before.flags == after.flags == ()


def test_fall_back_ambiguous_first_occurrence() -> None:
    # 2026-10-25 03:00 CEST -> 02:00 CET: 02:30 happens twice.
    result = localize(datetime(2026, 10, 25, 2, 30), BERLIN)
    assert result.flags == (FLAG_AMBIGUOUS_LOCAL_TIME,)
    assert result.utc == datetime(2026, 10, 25, 0, 30, tzinfo=UTC)


def test_fall_back_ambiguous_second_occurrence_from_stream_context() -> None:
    previous = datetime(2026, 10, 25, 1, 50, tzinfo=UTC)  # 02:50 CET, second pass
    result = localize(datetime(2026, 10, 25, 2, 10), BERLIN, previous_utc=previous)
    assert result.utc == datetime(2026, 10, 25, 1, 10, tzinfo=UTC)


def test_fall_back_stream_keeps_order() -> None:
    previous = datetime(2026, 10, 25, 0, 20, tzinfo=UTC)  # 02:20 CEST, first pass
    result = localize(datetime(2026, 10, 25, 2, 40), BERLIN, previous_utc=previous)
    assert result.utc == datetime(2026, 10, 25, 0, 40, tzinfo=UTC)


@pytest.mark.parametrize(
    ("month", "day", "reference", "expected"),
    [
        (3, 12, datetime(2026, 3, 12, 11), 2026),
        (12, 31, datetime(2027, 1, 1, 0, 5), 2026),  # year wrap
        (1, 1, datetime(2026, 12, 31, 23, 59), 2026),  # within tolerance -> same year
        (3, 13, datetime(2026, 3, 12, 11), 2026),  # one day ahead is tolerated (time zones)
        (3, 20, datetime(2026, 3, 12, 11), 2025),
        (2, 29, datetime(2026, 3, 1), 2024),  # leap day falls back to last leap year
    ],
)
def test_infer_year(month: int, day: int, reference: datetime, expected: int) -> None:
    assert infer_year(month, day, reference) == expected


def test_infer_year_impossible_date() -> None:
    with pytest.raises(TimestampError):
        infer_year(2, 30, datetime(2026, 3, 1))


def test_rfc3164_time() -> None:
    ref = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    result = parse_rfc3164_time("Mar 12 10:15:01", BERLIN, ref)
    assert result.utc == datetime(2026, 3, 12, 9, 15, 1, tzinfo=UTC)
    assert result.quality is TimeQuality.INFERRED_YEAR


def test_rfc3164_space_padded_day_and_year_wrap() -> None:
    ref = datetime(2027, 1, 1, 0, 30, tzinfo=UTC)
    result = parse_rfc3164_time("Dec 31 23:59:59", ZoneInfo("UTC"), ref)
    assert result.utc == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
    padded = parse_rfc3164_time("Jan  1 00:10:00", ZoneInfo("UTC"), ref)
    assert padded.utc == datetime(2027, 1, 1, 0, 10, tzinfo=UTC)


def test_rfc3164_during_dst_switch_keeps_flag() -> None:
    ref = datetime(2026, 10, 25, 12, tzinfo=UTC)
    result = parse_rfc3164_time("Oct 25 02:30:00", BERLIN, ref)
    assert result.flags == (FLAG_AMBIGUOUS_LOCAL_TIME,)
    assert result.quality is TimeQuality.INFERRED_YEAR


@pytest.mark.parametrize("text", ["Mar 12", "Foo 12 10:00:00", "Mar xx 10:00:00", "Mar 12 10:00", "Mar 12 25:00:00"])
def test_rfc3164_invalid(text: str) -> None:
    with pytest.raises(TimestampError):
        parse_rfc3164_time(text, BERLIN, datetime(2026, 3, 12, tzinfo=UTC))


def test_skew_policy() -> None:
    now = datetime(2026, 3, 12, 12, tzinfo=UTC)
    policy = SkewPolicy(future_tolerance=timedelta(minutes=5), past_limit=timedelta(days=30))
    ok = NormalizedTime(now, TimeQuality.EXACT)
    assert apply_skew_policy(ok, now, policy) is ok
    future = apply_skew_policy(NormalizedTime(now + timedelta(hours=1), TimeQuality.EXACT), now, policy)
    assert future.quality is TimeQuality.CLOCK_SKEW_SUSPECTED
    assert future.flags == (FLAG_FUTURE_TIMESTAMP,)
    ancient = apply_skew_policy(NormalizedTime(now - timedelta(days=31), TimeQuality.INFERRED_YEAR), now, policy)
    assert ancient.flags == (FLAG_ANCIENT_TIMESTAMP,)
    assert ancient.utc == now - timedelta(days=31)  # flagged, never dropped


def test_worst_quality() -> None:
    assert worst_quality(TimeQuality.EXACT, TimeQuality.INFERRED_YEAR) is TimeQuality.INFERRED_YEAR


def test_normalize_iso_with_and_without_offset() -> None:
    assert normalize_iso("2026-03-12T10:00:00Z", BERLIN).quality is TimeQuality.EXACT
    local = normalize_iso("2026-03-12T10:00:00", BERLIN)
    assert local.quality is TimeQuality.ASSUMED_TIMEZONE
    assert local.utc == datetime(2026, 3, 12, 9, tzinfo=UTC)


@pytest.mark.parametrize(
    ("value", "unit", "expected"),
    [
        (1773307800, "s", datetime(2026, 3, 12, 9, 30, tzinfo=UTC)),
        (1773307800123, "ms", datetime(2026, 3, 12, 9, 30, 0, 123000, tzinfo=UTC)),
        (1773307800123456, "us", datetime(2026, 3, 12, 9, 30, 0, 123456, tzinfo=UTC)),
        (1773307800.5, "s", datetime(2026, 3, 12, 9, 30, 0, 500000, tzinfo=UTC)),
    ],
)
def test_from_epoch(value: float, unit: str, expected: datetime) -> None:
    assert from_epoch(value, unit).utc == expected


@pytest.mark.parametrize(("value", "unit"), [(1, "h"), (True, "s"), (10**30, "s"), (float("nan"), "s")])
def test_from_epoch_invalid(value: float, unit: str) -> None:
    with pytest.raises(TimestampError):
        from_epoch(value, unit)
