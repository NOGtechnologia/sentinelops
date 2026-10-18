"""In-memory ingestion of files (used by the CLI, tests and the benchmark).

The database backed ingestion (``ingest/runs.py``) uses the same
:func:`process_stream`; this module only collects results in memory.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from sentinelops.ingest.processing import RecordOutcome, process_stream
from sentinelops.normalize.dedupe import Deduplicator
from sentinelops.normalize.schema import CanonicalEvent, RecordStatus
from sentinelops.parsers.base import ParseContext
from sentinelops.parsers.json_mapped import MappingProfile
from sentinelops.parsers.registry import get_parser


@dataclass(frozen=True)
class InputFile:
    path: Path
    source_type: str
    timezone: str = "UTC"


@dataclass
class LocalIngestResult:
    events: list[CanonicalEvent] = field(default_factory=list)
    outcomes: dict[str, list[RecordOutcome]] = field(default_factory=dict)
    skipped_files: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        result = {s.value: 0 for s in RecordStatus}
        for items in self.outcomes.values():
            for outcome in items:
                result[outcome.status.value] += 1
        return result


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest_files(
    files: Iterable[InputFile],
    profiles: Mapping[str, MappingProfile],
    reference_utc: datetime,
    dedupe: Deduplicator | None = None,
    seen_files: set[str] | None = None,
    keep_outcomes: bool = True,
) -> LocalIngestResult:
    """Parse and normalise files. Re-importing a file with a known hash is a no-op."""
    dedupe = dedupe if dedupe is not None else Deduplicator()
    seen_files = seen_files if seen_files is not None else set()
    result = LocalIngestResult()
    for item in files:
        digest = file_sha256(item.path)
        if digest in seen_files:
            result.skipped_files.append(str(item.path))
            continue
        seen_files.add(digest)
        parser = get_parser(item.source_type, profiles)
        ctx = ParseContext(reference_utc=reference_utc, timezone=ZoneInfo(item.timezone))
        outcomes: list[RecordOutcome] = []
        with item.path.open("rb") as stream:
            for outcome in process_stream(parser, stream, ctx, dedupe, digest, reference_utc):
                if outcome.event is not None:
                    result.events.append(outcome.event)
                if keep_outcomes:
                    outcomes.append(outcome)
        result.outcomes[str(item.path)] = outcomes
    return result
