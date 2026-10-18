"""Record level processing: split -> parse -> normalise -> deduplicate.

Pure orchestration without storage. Every raw record yields exactly one
:class:`RecordOutcome` (``accepted``, ``duplicate`` or ``malformed``).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO

from sentinelops.normalize.dedupe import Deduplicator, event_id_for, stable_hash
from sentinelops.normalize.quality import Malformed
from sentinelops.normalize.schema import CanonicalEvent, RecordStatus
from sentinelops.parsers.base import ParseContext, ParsedEvent, Parser, RawRecord


@dataclass(frozen=True, slots=True)
class RecordOutcome:
    raw_record_id: str
    raw: RawRecord
    status: RecordStatus
    event: CanonicalEvent | None = None
    error: Malformed | None = None
    duplicate_of: str | None = None
    event_id: str | None = None


def raw_record_id(file_sha256: str, position: int) -> str:
    return stable_hash("raw", file_sha256, position)


def build_event(parsed: ParsedEvent, source_type: str, raw_id: str, ingested: datetime) -> CanonicalEvent:
    event_id = event_id_for(parsed.fingerprint)
    fields = dict(parsed.fields)
    fields["event.original_time"] = parsed.original_time
    fields["event.ingested"] = ingested
    fields["log.source_type"] = source_type
    fields["log.raw_record_id"] = raw_id
    return CanonicalEvent(event_id=event_id, timestamp=parsed.time.utc, fields=fields, original=dict(parsed.original))


def process_stream(
    parser: Parser,
    stream: BinaryIO,
    ctx: ParseContext,
    dedupe: Deduplicator,
    file_sha256: str,
    ingested: datetime,
) -> Iterator[RecordOutcome]:
    for item in parser.split(stream, ctx):
        if isinstance(item, tuple):
            raw, error = item
            yield RecordOutcome(raw_record_id(file_sha256, raw.position), raw, RecordStatus.MALFORMED, error=error)
            continue
        raw = item
        raw_id = raw_record_id(file_sha256, raw.position)
        result = parser.parse(raw, ctx)
        if isinstance(result, Malformed):
            yield RecordOutcome(raw_id, raw, RecordStatus.MALFORMED, error=result)
            continue
        event = build_event(result, parser.source_type, raw_id, ingested)
        ctx.previous_utc = event.timestamp
        original = dedupe.check(event.event_id, raw_id)
        if original is not None:
            yield RecordOutcome(raw_id, raw, RecordStatus.DUPLICATE, duplicate_of=original, event_id=event.event_id)
            continue
        yield RecordOutcome(raw_id, raw, RecordStatus.ACCEPTED, event=event, event_id=event.event_id)
