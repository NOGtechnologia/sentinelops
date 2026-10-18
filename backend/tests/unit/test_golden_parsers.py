"""Parser golden files: fixture -> expected normalised JSON (spec 15.2).

Regenerate after an intended change with ``UPDATE_GOLDEN=1 pytest`` and review
the diff - golden files are part of the specification of the parsers.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from sentinelops.ingest.processing import process_stream
from sentinelops.normalize.dedupe import Deduplicator, file_hash
from sentinelops.parsers.base import ParseContext
from sentinelops.parsers.json_mapped import load_profiles
from sentinelops.parsers.registry import get_parser
from sentinelops.settings import PROFILES_DIR

FIXTURES = Path(__file__).parent.parent / "fixtures"
REFERENCE = datetime(2026, 3, 12, 12, 0, tzinfo=UTC)

CASES: list[tuple[str, str, str]] = [
    ("windows_xml/security_sample.xml", "windows_xml", "UTC"),
    ("windows_json/events.json", "windows_json", "UTC"),
    ("evtx/new-user-security.evtx", "windows_evtx", "UTC"),
    ("syslog_3164/auth.log", "syslog_3164", "Europe/Berlin"),
    ("syslog_5424/messages.log", "syslog_5424", "Europe/Berlin"),
    ("journald/journal.json", "journald_json", "UTC"),
    ("json_vpn/vpn.ndjson", "json:musterfirma_vpn", "UTC"),
]


def run_fixture(relative: str, source_type: str, tz: str) -> list[dict[str, Any]]:
    path = FIXTURES / relative
    profiles = load_profiles(PROFILES_DIR, REFERENCE)
    parser = get_parser(source_type, profiles)
    ctx = ParseContext(reference_utc=REFERENCE, timezone=ZoneInfo(tz))
    out: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        for outcome in process_stream(parser, stream, ctx, Deduplicator(), file_hash(path.read_bytes()), REFERENCE):
            item: dict[str, Any] = {"position": outcome.raw.position, "status": outcome.status.value}
            if outcome.error is not None:
                item["error"] = {"code": outcome.error.code.value, "detail": outcome.error.detail}
            if outcome.duplicate_of is not None:
                item["duplicate_of"] = outcome.duplicate_of
            if outcome.event is not None:
                item["event"] = outcome.event.to_dict()
            out.append(item)
    return out


@pytest.mark.parametrize(("relative", "source_type", "tz"), CASES)
def test_golden(relative: str, source_type: str, tz: str) -> None:
    actual = run_fixture(relative, source_type, tz)
    golden = (FIXTURES / relative).with_suffix(".golden.json")
    rendered = json.dumps(actual, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden.write_text(rendered, encoding="utf-8", newline="\n")
    assert golden.exists(), f"golden file missing: {golden.name} (run with UPDATE_GOLDEN=1)"
    assert rendered == golden.read_text(encoding="utf-8")


def test_same_event_same_id_across_windows_formats() -> None:
    xml = run_fixture("windows_xml/security_sample.xml", "windows_xml", "UTC")
    js = run_fixture("windows_json/events.json", "windows_json", "UTC")
    assert xml[0]["event"]["event.id"] == js[0]["event"]["event.id"]
    xml_fields = {k: v for k, v in xml[0]["event"].items() if k not in ("log.source_type", "log.raw_record_id")}
    js_fields = {k: v for k, v in js[0]["event"].items() if k not in ("log.source_type", "log.raw_record_id")}
    assert xml_fields == js_fields
