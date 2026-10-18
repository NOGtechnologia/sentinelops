"""Windows EVTX binary logs via ``evtx`` (pyevtx-rs), see ADR-0005.

The library renders each binary record as JSON (same shape as
``evtx_dump -o json``). That rendering is stored as the raw record - a single
EVTX record is not addressable as bytes on its own - and mapped by the same
code as the other Windows formats, which guarantees identical normalisation.
Rendering to JSON instead of XML is ~3x faster (Phase 0 measurement).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, BinaryIO, cast

from evtx import PyEvtxParser

from sentinelops.normalize.quality import Malformed, decode_text, load_json
from sentinelops.normalize.schema import MalformedCode, SourceType
from sentinelops.parsers.base import ParseContext, ParseResult, RawRecord
from sentinelops.parsers.windows_common import to_parsed
from sentinelops.parsers.windows_json import to_winevent

EVTX_MAGIC = b"ElfFile\x00"
#: Guard against a corrupt file making the record iterator fail forever.
MAX_CONSECUTIVE_ERRORS = 1000


class WindowsEvtxParser:
    source_type = SourceType.WINDOWS_EVTX.value

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        head = stream.read(len(EVTX_MAGIC))
        if head != EVTX_MAGIC:
            yield RawRecord(1, head), Malformed(MalformedCode.PARSE_ERROR, "not an EVTX file (bad magic)", 0)
            return
        stream.seek(0)
        try:
            # The bundled stub types the iterator as itself; records are dicts.
            records = cast(Iterator[dict[str, Any]], iter(PyEvtxParser(stream).records_json()))
        except (OSError, RuntimeError, ValueError) as exc:
            yield RawRecord(1, b""), Malformed(MalformedCode.PARSE_ERROR, f"EVTX header: {exc}", 0)
            return
        position = 0
        consecutive_errors = 0
        while True:
            position += 1
            try:
                record = next(records)
            except StopIteration:
                return
            except (OSError, RuntimeError, ValueError) as exc:
                yield RawRecord(position, b""), Malformed(MalformedCode.PARSE_ERROR, f"EVTX record: {exc}")
                consecutive_errors += 1
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    return
                continue
            consecutive_errors = 0
            data = record.get("data")
            if not isinstance(data, str):
                yield RawRecord(position, b""), Malformed(MalformedCode.PARSE_ERROR, "EVTX record without data")
                continue
            yield RawRecord(position, data.encode("utf-8"))

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
