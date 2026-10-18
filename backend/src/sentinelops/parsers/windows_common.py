"""Mapping of Windows Security events to the canonical schema.

Event ids and field names were verified against the Microsoft documentation
("Advanced security audit policy settings", event pages 4624 ... 1102), see
``docs/data-sources.md``. All three Windows input formats (EVTX, XML, JSON)
are first converted into :class:`WinEvent` and then mapped here, so the same
event produces the same canonical record and fingerprint in every format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sentinelops.normalize.dedupe import windows_fingerprint
from sentinelops.normalize.identities import canonical_ip, is_empty, split_user
from sentinelops.normalize.quality import Limits, Malformed, clip
from sentinelops.normalize.schema import MalformedCode, Outcome
from sentinelops.normalize.timestamps import (
    NormalizedTime,
    SkewPolicy,
    TimestampError,
    apply_skew_policy,
    normalize_iso,
)
from sentinelops.parsers.base import ParseContext, ParsedEvent


@dataclass(frozen=True, slots=True)
class WinEvent:
    provider: str | None
    event_id: int
    channel: str | None
    computer: str | None
    record_id: str | None
    time_created: str | None
    data: dict[str, str]


@dataclass(frozen=True, slots=True)
class EventSpec:
    action: str
    category: tuple[str, ...]
    type: tuple[str, ...]
    outcome: Outcome | None  # None = derived from Status field
    role: str  # how users are mapped, see _map_users


#: Supported Security log events (V1 scope, spec 5.2).
EVENT_SPECS: dict[int, EventSpec] = {
    4624: EventSpec("logon", ("authentication",), ("start",), Outcome.SUCCESS, "logon"),
    4625: EventSpec("logon-failed", ("authentication",), ("start",), Outcome.FAILURE, "logon"),
    4634: EventSpec("logoff", ("authentication",), ("end",), Outcome.SUCCESS, "logon"),
    4647: EventSpec("logoff", ("authentication",), ("end",), Outcome.SUCCESS, "logon"),
    4648: EventSpec("explicit-credential-logon", ("authentication",), ("start",), Outcome.SUCCESS, "subject+target"),
    4672: EventSpec("special-privileges-assigned", ("iam",), ("admin",), Outcome.SUCCESS, "subject"),
    4720: EventSpec("user-created", ("iam",), ("user", "creation"), Outcome.SUCCESS, "subject+target"),
    4722: EventSpec("user-enabled", ("iam",), ("user", "change"), Outcome.SUCCESS, "subject+target"),
    4724: EventSpec("password-reset", ("iam",), ("user", "change"), Outcome.SUCCESS, "subject+target"),
    4726: EventSpec("user-deleted", ("iam",), ("user", "deletion"), Outcome.SUCCESS, "subject+target"),
    4728: EventSpec("user-added-to-group", ("iam",), ("group", "change"), Outcome.SUCCESS, "group"),
    4732: EventSpec("user-added-to-group", ("iam",), ("group", "change"), Outcome.SUCCESS, "group"),
    4756: EventSpec("user-added-to-group", ("iam",), ("group", "change"), Outcome.SUCCESS, "group"),
    4740: EventSpec("account-locked", ("iam",), ("user", "change"), Outcome.SUCCESS, "lockout"),
    4768: EventSpec("kerberos-tgt-request", ("authentication",), ("start",), None, "kerberos"),
    4771: EventSpec("kerberos-preauth-failed", ("authentication",), ("start",), Outcome.FAILURE, "kerberos"),
    4776: EventSpec("ntlm-validation", ("authentication",), ("start",), None, "ntlm"),
    1102: EventSpec("audit-log-cleared", ("configuration",), ("deletion",), Outcome.SUCCESS, "subject"),
}

_AUTH_PACKAGES = {"kerberos": "kerberos", "ntlm": "ntlm", "negotiate": "negotiate", "ntlm v2": "ntlm"}
_CN_RE = re.compile(r"^CN=((?:\\,|[^,])+)", re.IGNORECASE)


def _clean(data: dict[str, str], key: str) -> str | None:
    value = data.get(key)
    if value is None or is_empty(value):
        return None
    return value


def _member_name(member: str | None) -> str | None:
    """``CN=Erika Muster,OU=...`` -> ``Erika Muster``; plain names stay unchanged."""
    if member is None:
        return None
    match = _CN_RE.match(member)
    if match:
        return match.group(1).replace("\\,", ",")
    return member


def _set_user(fields: dict[str, Any], prefix: str, name: str | None, domain: str | None, sid: str | None) -> None:
    identity = split_user(name, domain)
    if identity is not None:
        fields[f"{prefix}.name"] = identity.name
        if identity.domain:
            fields[f"{prefix}.domain"] = identity.domain
    if sid:
        fields[f"{prefix}.id"] = sid


def _map_users(spec: EventSpec, d: dict[str, str], fields: dict[str, Any]) -> None:
    subject = (_clean(d, "SubjectUserName"), _clean(d, "SubjectDomainName"), _clean(d, "SubjectUserSid"))
    target = (
        _clean(d, "TargetUserName"),
        _clean(d, "TargetDomainName"),
        _clean(d, "TargetUserSid") or _clean(d, "TargetSid"),
    )
    if spec.role in ("logon", "kerberos", "ntlm"):
        _set_user(fields, "user", *target)
    elif spec.role == "subject":
        _set_user(fields, "user", *subject)
    elif spec.role == "subject+target":
        _set_user(fields, "user", *subject)
        _set_user(fields, "user.target", *target)
    elif spec.role == "lockout":
        _set_user(fields, "user", *subject)
        _set_user(fields, "user.target", target[0], None, target[2])
        caller = _clean(d, "TargetDomainName")  # 4740: caller computer name
        if caller:
            fields["source.host"] = caller
    elif spec.role == "group":
        _set_user(fields, "user", *subject)
        if target[0]:
            fields["group.name"] = target[0]
        if target[2]:
            fields["group.id"] = target[2]
        member_sid = _clean(d, "MemberSid")
        member = _member_name(_clean(d, "MemberName"))
        if member_sid and member_sid == subject[2] and subject[0]:
            # The actor added itself: use its account name instead of the
            # directory display name (CN) so both refer to the same entity.
            member = subject[0]
        _set_user(fields, "user.target", member, None, member_sid)


def _status_outcome(d: dict[str, str]) -> Outcome:
    status = (_clean(d, "Status") or "").lower()
    if not status:
        return Outcome.UNKNOWN
    return Outcome.SUCCESS if status in ("0x0", "0", "0x00000000") else Outcome.FAILURE


def normalize_windows_time(text: str | None, ctx: ParseContext) -> NormalizedTime | Malformed:
    if text is None or is_empty(text):
        return Malformed(MalformedCode.MISSING_TIMESTAMP, "TimeCreated missing")
    try:
        value = normalize_iso(text, ctx.timezone, ctx.previous_utc)
    except TimestampError as exc:
        return Malformed(MalformedCode.PARSE_ERROR, f"invalid TimeCreated: {exc}")
    return apply_skew_policy(value, ctx.reference_utc, ctx.skew or SkewPolicy())


def to_parsed(event: WinEvent, ctx: ParseContext, limits: Limits) -> ParsedEvent | Malformed:
    """Map a :class:`WinEvent` to canonical fields."""
    time = normalize_windows_time(event.time_created, ctx)
    if isinstance(time, Malformed):
        return time
    data = {k: clip(v, limits) for k, v in event.data.items()}
    spec = EVENT_SPECS.get(event.event_id)
    fields: dict[str, Any] = {
        "event.kind": "event",
        "event.code": str(event.event_id),
        "host.os.type": "windows",
    }
    if event.provider:
        fields["event.provider"] = event.provider
    if event.computer:
        fields["host.name"] = event.computer
    if spec is not None:
        fields["event.action"] = spec.action
        fields["event.category"] = list(spec.category)
        fields["event.type"] = list(spec.type)
        fields["event.outcome"] = (spec.outcome or _status_outcome(data)).value
        _map_users(spec, data, fields)
    else:
        fields["event.action"] = f"windows-event-{event.event_id}"
        fields["event.outcome"] = Outcome.UNKNOWN.value
        _set_user(
            fields,
            "user",
            _clean(data, "SubjectUserName"),
            _clean(data, "SubjectDomainName"),
            _clean(data, "SubjectUserSid"),
        )
    ip = canonical_ip(_clean(data, "IpAddress"))
    if ip:
        fields["source.ip"] = ip
    port = _clean(data, "IpPort")
    if port and port.isdigit() and int(port) > 0:
        fields["source.port"] = int(port)
    workstation = _clean(data, "WorkstationName") or _clean(data, "Workstation")
    if workstation and "source.host" not in fields:
        fields["source.host"] = workstation
    logon_type = _clean(data, "LogonType")
    if logon_type and logon_type.isdigit():
        fields["logon.type"] = int(logon_type)
    package = (_clean(data, "AuthenticationPackageName") or _clean(data, "PackageName") or "").lower()
    if spec is not None and spec.role in ("kerberos", "ntlm"):
        # 4768/4771 are Kerberos by definition, 4776 is NTLM credential
        # validation (PackageName is MICROSOFT_AUTHENTICATION_PACKAGE_V1_0).
        fields["auth.method"] = spec.role
    elif package:
        fields["auth.method"] = next((v for k, v in _AUTH_PACKAGES.items() if package.startswith(k)), package)
    process = _clean(data, "ProcessName")
    if process:
        fields["process.name"] = process
    pid = _clean(data, "ProcessId")
    if pid:
        fields["process.pid"] = pid
    if time.flags:
        fields["quality.flags"] = list(time.flags)
    fields["event.time_quality"] = time.quality.value
    original: dict[str, Any] = {f"winlog.event_data.{k}": v for k, v in data.items()}
    original["winlog.event_id"] = event.event_id
    if event.channel:
        original["winlog.channel"] = event.channel
    if event.provider:
        original["winlog.provider_name"] = event.provider
    if event.record_id:
        original["winlog.record_id"] = event.record_id
    fingerprint = windows_fingerprint(event.computer, event.channel, event.record_id, event.provider, time.utc)
    return ParsedEvent(
        fingerprint=fingerprint,
        time=time,
        original_time=event.time_created or "",
        fields=fields,
        original=original,
    )
