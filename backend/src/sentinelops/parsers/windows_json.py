"""Windows events as JSON (NDJSON or JSON array).

Three shapes are recognised (see ``docs/data-sources.md``):

* **Winlogbeat-like**: ``{"winlog": {"event_id", "provider_name", "channel",
  "computer_name", "record_id", "event_data": {...}}, "@timestamp": ...}``
* **evtx JSON** (``evtx_dump -o json`` / pyevtx-rs): ``{"Event": {"System":
  {...}, "EventData": {...}}}``
* **Get-WinEvent** with named event data, produced by the PowerShell recipe in
  the user guide: ``{"Id", "ProviderName", "LogName", "MachineName",
  "RecordId", "TimeCreated", "EventData": {...}}``. ``TimeCreated`` may be ISO
  8601 (PowerShell 7) or ``/Date(ms)/`` (Windows PowerShell 5.1).
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any, BinaryIO

from sentinelops.normalize.quality import Malformed, decode_text, load_json
from sentinelops.normalize.schema import MalformedCode, SourceType, format_timestamp
from sentinelops.normalize.timestamps import TimestampError, from_epoch
from sentinelops.parsers.base import ParseContext, ParseResult, RawRecord
from sentinelops.parsers.json_split import split_json
from sentinelops.parsers.windows_common import WinEvent, to_parsed

_MS_DATE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$")


def _str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    return None


def _data(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(item, Mapping) and "#text" in item:
            item = item["#text"]
        text = _str(item)
        if text is not None:
            out[str(key)] = text
    return out


def _attr(value: Any, name: str) -> Any:
    if isinstance(value, Mapping):
        attributes = value.get("#attributes")
        if isinstance(attributes, Mapping):
            return attributes.get(name)
    return None


def _event_id(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("#text")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def _ps_time(value: Any) -> str | None:
    text = _str(value)
    if text is None:
        return None
    match = _MS_DATE.match(text.replace("\\/", "/"))
    if match:
        try:
            return format_timestamp(from_epoch(int(match.group(1)), "ms").utc)
        except TimestampError:
            return None
    return text


def to_winevent(doc: Any) -> WinEvent | Malformed:
    if not isinstance(doc, Mapping):
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "record is not a JSON object")
    if isinstance(doc.get("winlog"), Mapping):
        w = doc["winlog"]
        event_id = _event_id(w.get("event_id"))
        provider, channel, computer = _str(w.get("provider_name")), _str(w.get("channel")), _str(w.get("computer_name"))
        record_id, time_created, data = _str(w.get("record_id")), _str(doc.get("@timestamp")), _data(w.get("event_data"))
        if isinstance(w.get("user_data"), Mapping):
            data.update(_data(w["user_data"]))
    elif isinstance(doc.get("Event"), Mapping):
        ev = doc["Event"]
        system = ev.get("System") if isinstance(ev.get("System"), Mapping) else {}
        event_id = _event_id(system.get("EventID"))
        provider = _str(_attr(system.get("Provider"), "Name"))
        channel, computer = _str(system.get("Channel")), _str(system.get("Computer"))
        record_id = _str(system.get("EventRecordID"))
        time_created = _str(_attr(system.get("TimeCreated"), "SystemTime"))
        data = _data(ev.get("EventData"))
        user_data = ev.get("UserData")
        if isinstance(user_data, Mapping):
            for wrapper in user_data.values():
                data.update(_data(wrapper))
    elif "Id" in doc and ("ProviderName" in doc or "LogName" in doc):
        event_id = _event_id(doc.get("Id"))
        provider, channel, computer = _str(doc.get("ProviderName")), _str(doc.get("LogName")), _str(doc.get("MachineName"))
        record_id, time_created, data = _str(doc.get("RecordId")), _ps_time(doc.get("TimeCreated")), _data(doc.get("EventData"))
    else:
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "unknown Windows JSON shape")
    if event_id is None:
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "event id missing or not numeric")
    return WinEvent(provider, event_id, channel, computer, record_id, time_created, data)


class WindowsJsonParser:
    source_type = SourceType.WINDOWS_JSON.value

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        yield from split_json(stream, ctx.limits)

    def parse(self, raw: RawRecord, ctx: ParseContext) -> ParseResult:
        text = decode_text(raw.content, ctx.limits)
        if isinstance(text, Malformed):
            return text
        doc = load_json(text, ctx.limits)
        if isinstance(doc, Malformed):
            return doc
        event = to_winevent(doc)
        if isinstance(event, Malformed):
            return event
        return to_parsed(event, ctx, ctx.limits)
