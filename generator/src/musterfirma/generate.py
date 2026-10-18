"""Dataset orchestration: normal days + scenarios + data quality cases.

The output is fully determined by the seed name and the parameters (no wall
clock, no unordered iteration): same inputs => byte-identical files.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from musterfirma.ground_truth import (
    FileEntry,
    GroundTruth,
    Label,
    LabelSet,
    Locator,
    Persona,
    ScenarioEntry,
)
from musterfirma.normal import generate_day
from musterfirma.org import Organisation, build_organisation
from musterfirma.quality import Labelled, broken_syslog, broken_vpn, broken_windows_xml
from musterfirma.records import Record, ScenarioTruth, SysRecord, VpnRecord, WinRecord
from musterfirma.scenarios import SCENARIOS
from musterfirma.writers import (
    BERLIN,
    journald_doc,
    rfc3164_line,
    rfc5424_line,
    write_getwinevent_array,
    write_lines,
    write_vpn,
    write_windows_xml,
    write_winlogbeat,
)

SEEDS = ("dev", "holdout")
DEMO_NOW = datetime(2026, 3, 12, 10, 30, tzinfo=BERLIN)
GENERATOR_VERSION = "1.0.0"
#: srv-print01 has a misconfigured clock (data quality case "Uhrzeit-Versatz").
SKEWED_HOST = "srv-print01"
SKEW = timedelta(hours=3)


@dataclass(frozen=True)
class GeneratorConfig:
    seed: str = "dev"
    start: date = date(2026, 3, 9)
    end: datetime = DEMO_NOW
    events_per_day: int = 50_000
    scenarios: bool = True
    quality: bool = True
    holidays: tuple[date, ...] = (date(2026, 4, 3), date(2026, 4, 6), date(2026, 5, 1))

    @property
    def seed_int(self) -> int:
        return int.from_bytes(hashlib.sha256(f"sentinelops-generator/{self.seed}".encode()).digest()[:8], "big")


@dataclass
class _FileSpec:
    path: str
    source_type: str
    timezone: str
    records: list[Record] = field(default_factory=list)


def _file_for(rec: Record, org: Organisation) -> tuple[str, str, str]:
    if isinstance(rec, VpnRecord):
        return "vpn/vpn01.ndjson", "json:musterfirma_vpn", "UTC"
    if isinstance(rec, WinRecord):
        role = org.host_by_name(rec.host).role
        if role == "dc":
            return "windows/dc_security.xml", "windows_xml", "UTC"
        if role == "workstation":
            return "windows/workstations_getwinevent.json", "windows_json", "UTC"
        return "windows/servers_winlogbeat.ndjson", "windows_json", "UTC"
    if rec.host == "srv-lnx02":
        return "linux/srv-lnx02_syslog5424.log", "syslog_5424", "Europe/Berlin"
    if rec.host == "srv-lnx04":
        return "linux/srv-lnx04_journal.json", "journald_json", "UTC"
    return f"linux/{rec.host}_auth.log", "syslog_3164", "Europe/Berlin"


def _sort_key(item: tuple[int, Record]) -> tuple[datetime, int]:
    return item[1].time, item[0]


def build_records(cfg: GeneratorConfig, org: Organisation, rng: random.Random) -> tuple[list[Record], list[ScenarioTruth]]:
    records: list[Record] = []
    day = cfg.start
    end_utc = cfg.end.astimezone(UTC)
    while datetime.combine(day, datetime.min.time(), tzinfo=BERLIN) < cfg.end:
        records.extend(r for r in generate_day(org, rng, day, cfg.events_per_day, frozenset(cfg.holidays)) if r.time <= end_utc)
        day += timedelta(days=1)
    truths: list[ScenarioTruth] = []
    if cfg.scenarios:
        for fn, offset in SCENARIOS:
            truth = fn(org, rng, cfg.start + timedelta(days=offset))
            truths.append(truth)
            records.extend(truth.records)
    for rec in records:
        if isinstance(rec, WinRecord) and rec.host == SKEWED_HOST:
            rec.time = rec.time + SKEW
    return records, truths


def _render(spec: _FileSpec, org: Organisation, out_dir: Path) -> list[int]:
    path = out_dir / spec.path
    path.parent.mkdir(parents=True, exist_ok=True)
    recs = spec.records
    if spec.source_type == "windows_xml":
        return write_windows_xml(path, org, [r for r in recs if isinstance(r, WinRecord)])
    if spec.path.endswith("_getwinevent.json"):
        return write_getwinevent_array(path, org, [r for r in recs if isinstance(r, WinRecord)])
    if spec.source_type == "windows_json":
        return write_winlogbeat(path, org, [r for r in recs if isinstance(r, WinRecord)])
    if spec.source_type == "json:musterfirma_vpn":
        return write_vpn(path, [r for r in recs if isinstance(r, VpnRecord)])
    sys_recs = [r for r in recs if isinstance(r, SysRecord)]
    if spec.source_type == "syslog_5424":
        return write_lines(path, [rfc5424_line(r) for r in sys_recs])
    if spec.source_type == "journald_json":
        return write_lines(path, [json.dumps(journald_doc(r), ensure_ascii=False, separators=(",", ":")) for r in sys_recs])
    return write_lines(path, [rfc3164_line(r) for r in sys_recs])


def _write_labelled(path: Path, items: Sequence[Labelled], wrap_xml: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        if wrap_xml:
            fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
        for item in items:
            data = item.content if isinstance(item.content, bytes) else item.content.encode("utf-8")
            fh.write(data + b"\n")
        if wrap_xml:
            fh.write(b"</Events>\n")


def generate(cfg: GeneratorConfig, out_dir: Path) -> GroundTruth:
    rng = random.Random(cfg.seed_int)  # noqa: S311 - deterministic test data, not cryptography
    org = build_organisation(rng)
    records, truths = build_records(cfg, org, rng)

    specs: dict[str, _FileSpec] = {}
    for rec in records:
        path, source_type, tz = _file_for(rec, org)
        specs.setdefault(path, _FileSpec(path, source_type, tz)).records.append(rec)

    # chronological order per file + per-host record ids / VPN sequence numbers
    duplicates: dict[str, list[int]] = {}
    for spec in specs.values():
        ordered = sorted(enumerate(spec.records), key=_sort_key)
        spec.records = [r for _, r in ordered]
        counters: dict[str, int] = {}
        for rec in spec.records:
            if isinstance(rec, WinRecord):
                counters[rec.host] = counters.get(rec.host, 100_000) + 1
                rec.record_id = counters[rec.host]
            elif isinstance(rec, VpnRecord):
                counters["vpn"] = counters.get("vpn", 0) + 1
                rec.seq = counters["vpn"]
        if cfg.quality and spec.source_type in ("syslog_3164", "windows_json") and not spec.path.endswith(".json"):
            # exact duplicates (e.g. a forwarder re-sending): every 500th normal record
            dup_positions: list[int] = []
            extended: list[Record] = []
            for index, rec in enumerate(spec.records):
                extended.append(rec)
                if index % 500 == 250 and rec.scenario is None:
                    extended.append(rec)
                    dup_positions.append(len(extended))
            spec.records = extended
            duplicates[spec.path] = dup_positions

    files: list[FileEntry] = []
    labels: dict[str, LabelSet] = {}
    positions: dict[int, Locator] = {}
    for path in sorted(specs):
        spec = specs[path]
        written = _render(spec, org, out_dir)
        exceptions: dict[str, Label] = {}
        dup_set = set(duplicates.get(path, []))
        end_utc = cfg.end.astimezone(UTC)
        for pos, rec in zip(written, spec.records, strict=True):
            if pos in dup_set:
                exceptions[str(pos)] = Label(status="duplicate")
                continue
            if id(rec) not in positions:
                positions[id(rec)] = Locator(file=path, position=pos)
            flag = "future_timestamp" if rec.time > end_utc + timedelta(minutes=5) else None
            if rec.evidence or flag:
                exceptions[str(pos)] = Label(status="accepted", assessment="suspicious" if rec.evidence else "normal", flag=flag)
        labels[path] = LabelSet(exceptions=exceptions)
        files.append(_file_entry(out_dir, path, spec.source_type, spec.timezone, len(written)))

    if cfg.quality:
        for path, source_type, tz, items, xml in (
            ("quality/broken_auth.log", "syslog_3164", "Europe/Berlin", broken_syslog(), False),
            ("quality/broken_windows.xml", "windows_xml", "UTC", broken_windows_xml(), True),
            ("quality/broken_vpn.ndjson", "json:musterfirma_vpn", "UTC", broken_vpn(), False),
        ):
            _write_labelled(out_dir / path, items, wrap_xml=xml)
            labels[path] = LabelSet(exceptions={
                str(i): Label(status=item.status, code=item.code, flag=item.flag)
                for i, item in enumerate(items, start=1) if item.status != "accepted" or item.code or item.flag
            })
            files.append(_file_entry(out_dir, path, source_type, tz, len(items)))

    scenario_entries = [
        ScenarioEntry(
            id=t.id,
            number=t.number,
            title=t.title,
            expected_rules=t.expected_rules,
            min_priority=t.min_priority,
            max_priority=t.max_priority,
            evidence=[positions[id(r)] for r in t.records if r.evidence],
            context=[positions[id(r)] for r in t.records if not r.evidence],
        )
        for t in truths
    ]
    truth = GroundTruth(
        generator_version=GENERATOR_VERSION,
        seed=cfg.seed,
        start=cfg.start.isoformat(),
        end=cfg.end.isoformat(),
        demo_now=DEMO_NOW.isoformat(),
        events_per_day=cfg.events_per_day,
        files=files,
        scenarios=scenario_entries,
        labels=labels,
        personas=[Persona(name=u.name, display=u.display, department=u.department) for u in org.users[:8]],
        privileged_accounts=[a.name for a in org.admins] + ["svc_backup"],
        hub_hosts=["dc01", "dc02", "srv-gw01"],
        monitoring_accounts=["svc_monitor"],
    )
    (out_dir / "ground_truth.json").write_text(truth.model_dump_json(indent=1) + "\n", encoding="utf-8", newline="\n")
    return truth


def _file_entry(out_dir: Path, path: str, source_type: str, tz: str, records: int) -> FileEntry:
    data = (out_dir / path).read_bytes()
    return FileEntry(path=path, source_type=source_type, timezone=tz, records=records, sha256=hashlib.sha256(data).hexdigest())


def summary(truth: GroundTruth) -> dict[str, Any]:
    return {
        "seed": truth.seed,
        "files": len(truth.files),
        "records": sum(f.records for f in truth.files),
        "scenarios": [s.id for s in truth.scenarios],
    }
