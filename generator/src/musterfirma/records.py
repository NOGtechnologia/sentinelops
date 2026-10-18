"""Generator-internal record types, independent of the output format."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class WinRecord:
    host: str  # short host name, e.g. dc01
    time: datetime  # UTC
    event_id: int
    data: dict[str, str]
    provider: str = "Microsoft-Windows-Security-Auditing"
    channel: str = "Security"
    user_data: bool = False  # 1102 stores its fields in UserData/LogFileCleared
    record_id: int = 0  # assigned by the writer, per host
    scenario: str | None = None
    evidence: bool = False  # must end up in an alert of the scenario


@dataclass
class SysRecord:
    host: str
    time: datetime  # UTC
    program: str
    pid: int | None
    message: str
    scenario: str | None = None
    evidence: bool = False


@dataclass
class VpnRecord:
    time: datetime
    type: str  # auth | auth_fail | disconnect
    result: str  # ok | fail
    user: str
    method: str
    ip: str
    port: int
    reason: str | None = None
    gateway: str = "vpn01"
    seq: int = 0
    scenario: str | None = None
    evidence: bool = False


Record = WinRecord | SysRecord | VpnRecord


@dataclass
class ScenarioTruth:
    id: str
    number: int
    title: str
    expected_rules: list[str]
    min_priority: str  # P1..P4 - the case must be at least this severe
    max_priority: str | None = None  # e.g. P4 for the false-positive trap
    records: list[Record] = field(default_factory=list)
