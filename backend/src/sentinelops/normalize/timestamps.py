"""Timestamp normalisation (spec section 5.4).

All functions are pure. The current time is always passed in explicitly so the
behaviour is deterministic (CLAUDE.md rule 7).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sentinelops.normalize.schema import TIME_QUALITY_SEVERITY, TimeQuality

MONTHS: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

FLAG_AMBIGUOUS_LOCAL_TIME = "ambiguous_local_time"
FLAG_NONEXISTENT_LOCAL_TIME = "nonexistent_local_time"
FLAG_FUTURE_TIMESTAMP = "future_timestamp"
FLAG_ANCIENT_TIMESTAMP = "ancient_timestamp"

_ISO_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
    r"(?:[.,](?P<frac>\d{1,9}))?(?P<tz>Z|z|[+-]\d{2}:?\d{2})?$"
)


class TimestampError(ValueError):
    """Raised when a timestamp cannot be interpreted."""


@dataclass(frozen=True, slots=True)
class NormalizedTime:
    utc: datetime
    quality: TimeQuality
    flags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class SkewPolicy:
    """Tolerances for ``clock_skew_suspected`` (configurable per installation)."""

    future_tolerance: timedelta = timedelta(minutes=5)
    past_limit: timedelta = timedelta(days=365 * 2)


def worst_quality(*qualities: TimeQuality) -> TimeQuality:
    return max(qualities, key=lambda q: TIME_QUALITY_SEVERITY[q])


def parse_iso8601(text: str) -> tuple[datetime, bool]:
    """Parse an ISO 8601 / RFC 3339 timestamp.

    Returns ``(value, has_offset)``. Fractions beyond microseconds are
    truncated (Windows uses 100 ns ticks, RFC 5424 allows up to 6 digits).
    """
    match = _ISO_RE.match(text.strip())
    if match is None:
        raise TimestampError(f"not an ISO 8601 timestamp: {text[:64]!r}")
    frac = (match.group("frac") or "0")[:6].ljust(6, "0")
    try:
        # The offset is parsed separately below; a naive value is intended here.
        base = datetime.strptime(  # noqa: DTZ007
            f"{match.group('date')} {match.group('h')}:{match.group('m')}:{match.group('s')}",
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError as exc:
        raise TimestampError(str(exc)) from exc
    value = base.replace(microsecond=int(frac))
    tz = match.group("tz")
    if tz is None:
        return value, False
    if tz in ("Z", "z"):
        return value.replace(tzinfo=UTC), True
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    hours, minutes = int(digits[:2]), int(digits[2:])
    if hours > 23 or minutes > 59:
        raise TimestampError(f"invalid UTC offset: {tz}")
    offset = timedelta(hours=hours, minutes=minutes) * sign
    return (value - offset).replace(tzinfo=UTC), True


def localize(naive: datetime, tz: ZoneInfo, previous_utc: datetime | None = None) -> NormalizedTime:
    """Interpret a naive local wall clock time in ``tz`` and convert to UTC.

    * Ambiguous times (the repeated hour when clocks go back) resolve to the
      first occurrence unless that would put the event more than 30 minutes
      before ``previous_utc`` of the same stream, in which case the second
      occurrence is used. The event is flagged ``ambiguous_local_time``.
    * Non-existent times (the skipped hour when clocks go forward) are
      interpreted with the offset valid before the transition, which maps them
      into the first hour after the gap; flagged ``nonexistent_local_time``.
    """
    if naive.tzinfo is not None:
        raise TimestampError("localize() expects a naive datetime")
    first = naive.replace(tzinfo=tz, fold=0)
    second = naive.replace(tzinfo=tz, fold=1)
    first_utc = first.astimezone(UTC)
    second_utc = second.astimezone(UTC)
    flags: tuple[str, ...] = ()
    result = first_utc
    if first_utc != second_utc:
        # Round trip tells ambiguous (exists twice) apart from non-existent.
        if first_utc.astimezone(tz).replace(tzinfo=None) == naive:
            flags = (FLAG_AMBIGUOUS_LOCAL_TIME,)
            if previous_utc is not None and first_utc < previous_utc - timedelta(minutes=30):
                result = second_utc
        else:
            flags = (FLAG_NONEXISTENT_LOCAL_TIME,)
    return NormalizedTime(utc=result, quality=TimeQuality.ASSUMED_TIMEZONE, flags=flags)


def infer_year(month: int, day: int, reference_local: datetime) -> int:
    """Choose the year for an RFC 3164 timestamp that carries none.

    The candidate in the reference year is used unless it lies more than one
    day in the future relative to the reference (ingest) time - then the
    record must stem from the previous year (year wrap: December lines read in
    January). February 29 falls back to the closest previous leap year.
    """
    year = reference_local.year
    for candidate_year in (year, year - 1, year - 2, year - 3, year - 4):
        try:
            candidate = reference_local.replace(
                year=candidate_year, month=month, day=day, hour=0, minute=0, second=0, microsecond=0
            )
        except ValueError:
            continue
        if candidate <= reference_local + timedelta(days=1):
            return candidate_year
    raise TimestampError(f"cannot infer year for {month:02d}-{day:02d}")


def parse_rfc3164_time(
    text: str,
    tz: ZoneInfo,
    reference_utc: datetime,
    previous_utc: datetime | None = None,
) -> NormalizedTime:
    """Parse ``Mmm dd hh:mm:ss`` (RFC 3164 section 4.1.2) without year/zone."""
    parts = text.split()
    if len(parts) != 3:
        raise TimestampError(f"invalid RFC 3164 timestamp: {text!r}")
    month = MONTHS.get(parts[0].lower())
    if month is None:
        raise TimestampError(f"invalid month: {parts[0]!r}")
    try:
        day = int(parts[1])
        hour_s, minute_s, second_s = parts[2].split(":")
        hour, minute, second = int(hour_s), int(minute_s), int(second_s)
    except ValueError as exc:
        raise TimestampError(f"invalid RFC 3164 timestamp: {text!r}") from exc
    reference_local = reference_utc.astimezone(tz).replace(tzinfo=None)
    year = infer_year(month, day, reference_local)
    try:
        naive = datetime(year, month, day, hour, minute, second)  # noqa: DTZ001 - naive local time, localised below
    except ValueError as exc:
        raise TimestampError(str(exc)) from exc
    local = localize(naive, tz, previous_utc)
    return NormalizedTime(utc=local.utc, quality=TimeQuality.INFERRED_YEAR, flags=local.flags)


def apply_skew_policy(value: NormalizedTime, now_utc: datetime, policy: SkewPolicy) -> NormalizedTime:
    """Flag (never drop) timestamps in the future or far in the past."""
    if value.utc > now_utc + policy.future_tolerance:
        flag = FLAG_FUTURE_TIMESTAMP
    elif value.utc < now_utc - policy.past_limit:
        flag = FLAG_ANCIENT_TIMESTAMP
    else:
        return value
    return NormalizedTime(
        utc=value.utc,
        quality=worst_quality(value.quality, TimeQuality.CLOCK_SKEW_SUSPECTED),
        flags=(*value.flags, flag),
    )


def normalize_iso(text: str, default_tz: ZoneInfo, previous_utc: datetime | None = None) -> NormalizedTime:
    """Normalise an ISO timestamp; without offset the source time zone is assumed."""
    value, has_offset = parse_iso8601(text)
    if has_offset:
        return NormalizedTime(utc=value, quality=TimeQuality.EXACT)
    return localize(value, default_tz, previous_utc)


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_EPOCH_UNITS: dict[str, int] = {"s": 1_000_000, "ms": 1_000, "us": 1}


def from_epoch(value: int | float, unit: str) -> NormalizedTime:
    """Convert an epoch timestamp (``s``, ``ms``, ``us``) to UTC."""
    factor = _EPOCH_UNITS.get(unit)
    if factor is None:
        raise TimestampError(f"unknown epoch unit: {unit}")
    if isinstance(value, bool):
        raise TimestampError("boolean is not a timestamp")
    try:
        micros = value * factor if isinstance(value, int) else round(value * factor)
        utc = _EPOCH + timedelta(microseconds=micros)
    except (OverflowError, ValueError) as exc:
        raise TimestampError(f"epoch out of range: {value}") from exc
    return NormalizedTime(utc=utc, quality=TimeQuality.EXACT)
