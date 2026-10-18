"""Output writers for all SentinelOps input formats.

Every writer returns the 1-based record position for each written record, in
exactly the way the SentinelOps splitters count them (XML: n-th ``<Event>``;
line formats: line number; JSON arrays: element index).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr
from zoneinfo import ZoneInfo

from musterfirma.org import Organisation
from musterfirma.records import SysRecord, VpnRecord, WinRecord

BERLIN = ZoneInfo("Europe/Berlin")
PROVIDER_GUIDS = {
    "Microsoft-Windows-Security-Auditing": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
    "Microsoft-Windows-Eventlog": "{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}",
}
TASKS = {4624: 12544, 4625: 12544, 4634: 12545, 4672: 12548, 4720: 13824, 4722: 13824, 4724: 13824,
         4726: 13824, 4728: 13826, 4732: 13826, 4756: 13826, 4740: 13824, 4768: 14339, 4776: 14336, 1102: 104}
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def win_time(t: datetime) -> str:
    t = t.astimezone(UTC)
    return f"{t:%Y-%m-%dT%H:%M:%S}.{t.microsecond:06d}0Z"


def _computer(org: Organisation, host: str) -> str:
    return org.host_by_name(host).fqdn


def render_xml_event(org: Organisation, rec: WinRecord) -> str:
    keywords = "0x8010000000000000" if rec.event_id in (4625, 4771, 4776) else "0x8020000000000000"
    provider = rec.provider
    system = (
        f"<System><Provider Name={quoteattr(provider)} Guid={quoteattr(PROVIDER_GUIDS.get(provider, '{00000000-0000-0000-0000-000000000000}'))}/>"
        f"<EventID>{rec.event_id}</EventID><Version>0</Version><Level>0</Level><Task>{TASKS.get(rec.event_id, 0)}</Task>"
        f"<Opcode>0</Opcode><Keywords>{keywords}</Keywords><TimeCreated SystemTime={quoteattr(win_time(rec.time))}/>"
        f"<EventRecordID>{rec.record_id}</EventRecordID><Correlation/><Execution ProcessID=\"636\" ThreadID=\"1856\"/>"
        f"<Channel>{escape(rec.channel)}</Channel><Computer>{escape(_computer(org, rec.host))}</Computer><Security/></System>"
    )
    if rec.user_data:
        inner = "".join(f"<{k}>{escape(v)}</{k}>" for k, v in rec.data.items())
        body = f"<UserData><LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\">{inner}</LogFileCleared></UserData>"
    else:
        body = "<EventData>" + "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in rec.data.items()) + "</EventData>"
    return f"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">{system}{body}</Event>"


def winlogbeat_doc(org: Organisation, rec: WinRecord) -> dict[str, Any]:
    winlog: dict[str, Any] = {
        "event_id": rec.event_id,
        "provider_name": rec.provider,
        "channel": rec.channel,
        "computer_name": _computer(org, rec.host),
        "record_id": rec.record_id,
    }
    winlog["user_data" if rec.user_data else "event_data"] = dict(rec.data)
    return {"@timestamp": win_time(rec.time), "winlog": winlog, "host": {"name": rec.host}}


def getwinevent_doc(org: Organisation, rec: WinRecord) -> dict[str, Any]:
    return {
        "Id": rec.event_id,
        "ProviderName": rec.provider,
        "LogName": rec.channel,
        "MachineName": _computer(org, rec.host),
        "RecordId": rec.record_id,
        "TimeCreated": rec.time.astimezone(BERLIN).isoformat(timespec="microseconds"),
        "EventData": dict(rec.data),
    }


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def write_windows_xml(path: Path, org: Organisation, records: Sequence[WinRecord]) -> list[int]:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
        for rec in records:
            fh.write(render_xml_event(org, rec))
            fh.write("\n")
        fh.write("</Events>\n")
    return list(range(1, len(records) + 1))


def write_winlogbeat(path: Path, org: Organisation, records: Sequence[WinRecord]) -> list[int]:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(_dump(winlogbeat_doc(org, rec)) + "\n")
    return list(range(1, len(records) + 1))


def write_getwinevent_array(path: Path, org: Organisation, records: Sequence[WinRecord]) -> list[int]:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("[\n")
        for index, rec in enumerate(records):
            fh.write(_dump(getwinevent_doc(org, rec)))
            fh.write(",\n" if index < len(records) - 1 else "\n")
        fh.write("]\n")
    return list(range(1, len(records) + 1))


def rfc3164_line(rec: SysRecord, tz: ZoneInfo = BERLIN) -> str:
    local = rec.time.astimezone(tz)
    tag = f"{rec.program}[{rec.pid}]" if rec.pid is not None else rec.program
    return f"{MONTHS[local.month - 1]} {local.day:2d} {local:%H:%M:%S} {rec.host} {tag}: {rec.message}"


def rfc5424_line(rec: SysRecord, tz: ZoneInfo = BERLIN) -> str:
    local = rec.time.astimezone(tz).isoformat(timespec="microseconds")
    pid = str(rec.pid) if rec.pid is not None else "-"
    return f"<38>1 {local} {rec.host} {rec.program} {pid} - - {rec.message}"


def journald_doc(rec: SysRecord) -> dict[str, Any]:
    micros = int(rec.time.astimezone(UTC).timestamp()) * 1_000_000 + rec.time.microsecond
    doc: dict[str, Any] = {
        "__REALTIME_TIMESTAMP": str(micros),
        "_HOSTNAME": rec.host,
        "SYSLOG_IDENTIFIER": rec.program,
        "MESSAGE": rec.message,
    }
    if rec.pid is not None:
        doc["_PID"] = str(rec.pid)
    return doc


def write_lines(path: Path, lines: Sequence[str]) -> list[int]:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(line + "\n")
    return list(range(1, len(lines) + 1))


def vpn_doc(rec: VpnRecord) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "ts": int(rec.time.astimezone(UTC).timestamp() * 1000),
        "seq": rec.seq,
        "gateway": rec.gateway,
        "product": "mf-vpn",
        "type": rec.type,
        "result": rec.result,
        "user": rec.user,
        "method": rec.method,
        "client": {"ip": rec.ip, "port": rec.port},
    }
    if rec.reason:
        doc["reason"] = rec.reason
    return doc


def write_vpn(path: Path, records: Sequence[VpnRecord]) -> list[int]:
    return write_lines(path, [_dump(vpn_doc(r)) for r in records])
