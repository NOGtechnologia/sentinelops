"""Structured JSON events mapped via YAML profiles (spec 5.2).

A profile maps arbitrary JSON fields onto the canonical schema, including time
format, time zone and result mapping. Profiles are validated with Pydantic and
their embedded examples are executed on load (``validate_profile``), so a
broken profile is rejected before it touches data.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from sentinelops.normalize.actions import ACTION_META
from sentinelops.normalize.dedupe import json_fingerprint
from sentinelops.normalize.identities import canonical_ip, split_user
from sentinelops.normalize.quality import Malformed, clip, decode_text, load_json
from sentinelops.normalize.schema import CANONICAL_FIELDS, MalformedCode, Outcome
from sentinelops.normalize.timestamps import (
    NormalizedTime,
    SkewPolicy,
    TimestampError,
    apply_skew_policy,
    from_epoch,
    localize,
    normalize_iso,
)
from sentinelops.parsers.base import ParseContext, ParsedEvent, ParseResult, RawRecord
from sentinelops.parsers.json_split import split_json

_MAPPABLE = frozenset(CANONICAL_FIELDS) - {
    "event.id",
    "@timestamp",
    "event.original_time",
    "event.time_quality",
    "event.ingested",
    "log.source_type",
    "log.raw_record_id",
    "quality.flags",
}
_INT_FIELDS = frozenset({"source.port", "logon.type"})


class TimestampSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    format: str = "iso8601"
    timezone: str = "UTC"

    @field_validator("format")
    @classmethod
    def _format(cls, value: str) -> str:
        if value in ("iso8601", "epoch_s", "epoch_ms", "epoch_us") or value.startswith("strptime:"):
            return value
        raise ValueError(f"unsupported timestamp format {value!r}")

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {value!r}") from exc
        return value


class ValueMap(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str | None = None
    map: dict[str, str] = Field(default_factory=dict)
    default: str | None = None


class ProfileExample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input: dict[str, Any]
    expect: dict[str, Any] = Field(default_factory=dict)
    expect_malformed: MalformedCode | None = None


class MappingProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,40}$")
    version: int = 1
    description: str = ""
    timestamp: TimestampSpec
    fields: dict[str, str] = Field(default_factory=dict)
    constants: dict[str, Any] = Field(default_factory=dict)
    action: ValueMap = Field(default_factory=ValueMap)
    outcome: ValueMap = Field(default_factory=ValueMap)
    fingerprint_keys: list[str] = Field(default_factory=list)
    keep_original: list[str] = Field(default_factory=list)
    examples: list[ProfileExample] = Field(min_length=1)

    @field_validator("fields", "constants")
    @classmethod
    def _canonical(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - _MAPPABLE)
        if unknown:
            raise ValueError(f"not a mappable canonical field: {', '.join(unknown)}")
        return value

    @model_validator(mode="after")
    def _actions(self) -> MappingProfile:
        targets = set(self.action.map.values()) | ({self.action.default} if self.action.default else set())
        constant = self.constants.get("event.action")
        if isinstance(constant, str):
            targets.add(constant)
        unknown = sorted(targets - set(ACTION_META))
        if unknown:
            raise ValueError(f"unknown event.action values: {', '.join(unknown)}")
        outcomes = set(self.outcome.map.values()) | ({self.outcome.default} if self.outcome.default else set())
        bad = sorted(outcomes - {o.value for o in Outcome})
        if bad:
            raise ValueError(f"invalid outcome values: {', '.join(bad)}")
        return self

    @property
    def source_type(self) -> str:
        return f"json:{self.name}"


class ProfileError(ValueError):
    pass


def lookup(doc: Mapping[str, Any], path: str) -> Any:
    """Resolve a dotted path; a literal key containing dots wins over nesting."""
    if path in doc:
        return doc[path]
    current: Any = doc
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _scalar(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _timestamp(
    profile: MappingProfile, doc: Mapping[str, Any], ctx: ParseContext
) -> tuple[NormalizedTime, str] | Malformed:
    raw = lookup(doc, profile.timestamp.field)
    if raw is None or raw == "":
        return Malformed(MalformedCode.MISSING_TIMESTAMP, f"field {profile.timestamp.field!r} missing")
    tz = ZoneInfo(profile.timestamp.timezone)
    fmt = profile.timestamp.format
    try:
        if fmt == "iso8601":
            if not isinstance(raw, str):
                raise TimestampError("ISO timestamp must be a string")
            value = normalize_iso(raw, tz, ctx.previous_utc)
        elif fmt.startswith("epoch_"):
            number: Any = raw
            if isinstance(raw, str):
                number = int(raw) if raw.isdigit() else float(raw)
            if not isinstance(number, (int, float)) or isinstance(number, bool):
                raise TimestampError("epoch timestamp must be numeric")
            value = from_epoch(number, fmt.removeprefix("epoch_"))
        else:
            if not isinstance(raw, str):
                raise TimestampError("strptime timestamp must be a string")
            parsed = datetime.strptime(raw, fmt.removeprefix("strptime:"))  # noqa: DTZ007 - zone handled below
            if parsed.tzinfo is not None:
                value = normalize_iso(parsed.isoformat(), tz)
            else:
                value = localize(parsed, tz, ctx.previous_utc)
    except (TimestampError, ValueError, OverflowError) as exc:
        return Malformed(MalformedCode.PARSE_ERROR, f"invalid timestamp: {exc}")
    return apply_skew_policy(value, ctx.reference_utc, ctx.skew), str(raw)


def map_document(profile: MappingProfile, doc: Any, ctx: ParseContext) -> ParsedEvent | Malformed:
    if not isinstance(doc, Mapping):
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "record is not a JSON object")
    stamp = _timestamp(profile, doc, ctx)
    if isinstance(stamp, Malformed):
        return stamp
    time, original_time = stamp
    fields: dict[str, Any] = {"event.kind": "event", "event.time_quality": time.quality.value}
    fields.update(profile.constants)
    for target, path in sorted(profile.fields.items()):
        value = _scalar(lookup(doc, path))
        if value is None or value == "":
            continue
        if target in _INT_FIELDS:
            if isinstance(value, str) and value.isdigit():
                value = int(value)
            if not isinstance(value, int) or isinstance(value, bool):
                return Malformed(MalformedCode.SCHEMA_VIOLATION, f"{target} must be an integer")
        elif target == "source.ip":
            ip = canonical_ip(str(value))
            if ip is None:
                return Malformed(MalformedCode.SCHEMA_VIOLATION, f"source.ip is not an IP address: {str(value)[:64]!r}")
            value = ip
        elif target in ("user.name", "user.target.name"):
            identity = split_user(str(value))
            if identity is None:
                continue
            value = identity.name
            if identity.domain:
                fields.setdefault(target.replace(".name", ".domain"), identity.domain)
        elif isinstance(value, str):
            value = clip(value, ctx.limits)
        fields[target] = value
    action = _mapped(profile.action, doc)
    if action is not None:
        fields["event.action"] = action
    outcome = _mapped(profile.outcome, doc)
    fields["event.outcome"] = outcome or fields.get("event.outcome") or Outcome.UNKNOWN.value
    meta = ACTION_META.get(str(fields.get("event.action")))
    if meta is not None:
        fields.setdefault("event.category", list(meta[0]))
        fields.setdefault("event.type", list(meta[1]))
    if time.flags:
        fields["quality.flags"] = list(time.flags)
    original = {f"json.{path}": _scalar(lookup(doc, path)) for path in profile.keep_original}
    return ParsedEvent(
        fingerprint=json_fingerprint(profile.name, doc, profile.fingerprint_keys),
        time=time,
        original_time=original_time,
        fields=fields,
        original={k: v for k, v in original.items() if v is not None},
    )


def _mapped(spec: ValueMap, doc: Mapping[str, Any]) -> str | None:
    if spec.field is None:
        return spec.default
    raw = _scalar(lookup(doc, spec.field))
    if raw is None:
        return spec.default
    key = str(raw).lower() if not isinstance(raw, str) else raw
    return spec.map.get(key, spec.map.get(key.lower(), spec.default))


class JsonMappedParser:
    def __init__(self, profile: MappingProfile) -> None:
        self.profile = profile
        self.source_type = profile.source_type

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        yield from split_json(stream, ctx.limits)

    def parse(self, raw: RawRecord, ctx: ParseContext) -> ParseResult:
        text = decode_text(raw.content, ctx.limits)
        if isinstance(text, Malformed):
            return text
        doc = load_json(text, ctx.limits)
        if isinstance(doc, Malformed):
            return doc
        return map_document(self.profile, doc, ctx)


def validate_profile(profile: MappingProfile, reference_utc: datetime) -> None:
    """Run the profile's embedded examples; raise :class:`ProfileError` on mismatch."""
    # Examples test the mapping, not the clock: skew checks are disabled here.
    no_skew = SkewPolicy(future_tolerance=timedelta(days=36500), past_limit=timedelta(days=36500))
    for index, example in enumerate(profile.examples, start=1):
        ctx = ParseContext(reference_utc=reference_utc, skew=no_skew)
        result = map_document(profile, example.input, ctx)
        if example.expect_malformed is not None:
            if not isinstance(result, Malformed) or result.code != example.expect_malformed:
                raise ProfileError(f"{profile.name} example {index}: expected {example.expect_malformed}")
            continue
        if isinstance(result, Malformed):
            raise ProfileError(f"{profile.name} example {index}: {result.code} {result.detail}")
        actual = {**result.fields, "@timestamp": result.time.utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        for key, expected in example.expect.items():
            if actual.get(key) != expected:
                raise ProfileError(f"{profile.name} example {index}: {key}={actual.get(key)!r}, expected {expected!r}")


def load_profile(path: Path, reference_utc: datetime) -> MappingProfile:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        profile = MappingProfile.model_validate(data)
    except (yaml.YAMLError, ValidationError) as exc:
        raise ProfileError(f"{path.name}: {exc}") from exc
    validate_profile(profile, reference_utc)
    return profile


def load_profiles(directory: Path, reference_utc: datetime) -> dict[str, MappingProfile]:
    profiles: dict[str, MappingProfile] = {}
    for path in sorted(directory.glob("*.yaml")):
        profile = load_profile(path, reference_utc)
        if profile.name in profiles:
            raise ProfileError(f"duplicate profile name {profile.name}")
        profiles[profile.name] = profile
    return profiles
