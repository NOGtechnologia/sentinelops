"""journald JSON export (``journalctl -o json``), one object per line.

Field meanings follow ``systemd.journal-fields(7)``: ``__REALTIME_TIMESTAMP``
(microseconds since the epoch, as a decimal string), ``_HOSTNAME``,
``SYSLOG_IDENTIFIER``, ``_PID``/``SYSLOG_PID`` and ``MESSAGE``. ``MESSAGE`` is an
array of byte values when it is not valid UTF-8; such records are malformed
(``INVALID_ENCODING``) unless they decode cleanly.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, BinaryIO

from sentinelops.normalize.quality import Malformed, decode_text, load_json
from sentinelops.normalize.schema import MalformedCode, SourceType
from sentinelops.normalize.timestamps import TimestampError, apply_skew_policy, from_epoch
from sentinelops.parsers.base import ParseContext, ParseResult, RawRecord
from sentinelops.parsers.json_split import split_json
from sentinelops.parsers.syslog_common import SyslogMessage, to_parsed


def _message(value: Any) -> str | Malformed:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(b, int) and 0 <= b < 256 for b in value):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            return Malformed(MalformedCode.INVALID_ENCODING, f"MESSAGE bytes not UTF-8 at {exc.start}", exc.start)
    return Malformed(MalformedCode.SCHEMA_VIOLATION, "MESSAGE missing or of unexpected type")


def to_message(doc: Any, ctx: ParseContext) -> SyslogMessage | Malformed:
    if not isinstance(doc, Mapping):
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "record is not a JSON object")
    raw_ts = doc.get("__REALTIME_TIMESTAMP")
    if not isinstance(raw_ts, str) or not raw_ts.isdigit():
        return Malformed(MalformedCode.MISSING_TIMESTAMP, "__REALTIME_TIMESTAMP missing")
    try:
        time = apply_skew_policy(from_epoch(int(raw_ts), "us"), ctx.reference_utc, ctx.skew)
    except TimestampError as exc:
        return Malformed(MalformedCode.PARSE_ERROR, str(exc))
    message = _message(doc.get("MESSAGE"))
    if isinstance(message, Malformed):
        return message
    pid = doc.get("SYSLOG_PID") or doc.get("_PID")
    host = doc.get("_HOSTNAME")
    program = doc.get("SYSLOG_IDENTIFIER") or doc.get("_COMM")
    extra: dict[str, Any] = {}
    unit = doc.get("_SYSTEMD_UNIT")
    if isinstance(unit, str):
        extra["journald.unit"] = unit
    return SyslogMessage(
        time=time,
        original_time=raw_ts,
        host=host if isinstance(host, str) else ctx.default_host,
        program=program if isinstance(program, str) else None,
        pid=pid if isinstance(pid, str) else None,
        message=message,
        extra=extra,
    )


class JournaldJsonParser:
    source_type = SourceType.JOURNALD_JSON.value

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        yield from split_json(stream, ctx.limits)

    def parse(self, raw: RawRecord, ctx: ParseContext) -> ParseResult:
        text = decode_text(raw.content, ctx.limits)
        if isinstance(text, Malformed):
            return text
        doc = load_json(text, ctx.limits)
        if isinstance(doc, Malformed):
            return doc
        message = to_message(doc, ctx)
        if isinstance(message, Malformed):
            return message
        return to_parsed(message, ctx.limits)
