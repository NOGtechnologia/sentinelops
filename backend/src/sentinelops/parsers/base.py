"""Parser contracts shared by all input formats.

A parser has two responsibilities:

1. ``split`` a byte stream into :class:`RawRecord` objects (streaming, never
   holding the whole file in memory), and
2. ``parse`` one raw record into a :class:`ParsedEvent` or :class:`Malformed`.

Parsers never raise for bad input - every record ends in exactly one status
(spec 5.6). Raw bytes are kept unchanged for the quarantine view.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, BinaryIO, Protocol
from zoneinfo import ZoneInfo

from sentinelops.normalize.quality import DEFAULT_LIMITS, Limits, Malformed
from sentinelops.normalize.timestamps import NormalizedTime, SkewPolicy


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One unparsed record. ``position`` is the 1-based line or record number."""

    position: int
    content: bytes
    #: Byte offset in the input file (for the quarantine view), if known.
    offset: int | None = None

    def text(self) -> str:
        """Lossless, escaped text rendering for display (never interpreted)."""
        return self.content.decode("utf-8", errors="backslashreplace")


@dataclass(frozen=True, slots=True)
class ParsedEvent:
    fingerprint: tuple[Any, ...]
    time: NormalizedTime
    original_time: str
    fields: dict[str, Any]
    original: dict[str, Any] = field(default_factory=dict)


ParseResult = ParsedEvent | Malformed


@dataclass(slots=True)
class ParseContext:
    """Per-stream parsing context. ``reference_utc`` is the ingest time used for
    year inference and skew checks; it is injected for determinism."""

    reference_utc: datetime
    timezone: ZoneInfo = field(default_factory=lambda: ZoneInfo("UTC"))
    limits: Limits = DEFAULT_LIMITS
    skew: SkewPolicy = field(default_factory=SkewPolicy)
    previous_utc: datetime | None = None
    #: Optional default host name for formats that do not carry one.
    default_host: str | None = None


class Parser(Protocol):
    source_type: str

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        """Yield raw records; splitting errors are yielded together with the record."""
        ...

    def parse(self, raw: RawRecord, ctx: ParseContext) -> ParseResult: ...


class Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


def iter_lines(stream: Readable, limits: Limits, chunk_size: int = 1 << 16) -> Iterator[RawRecord]:
    """Split a byte stream into lines (``\\n`` or ``\\r\\n``) without loading it fully.

    Overlong lines are yielded clipped to ``max_line_bytes + 1`` bytes so the
    caller can classify them as OVERSIZED without unbounded memory use.
    """
    position = 0
    offset = 0
    buffer = bytearray()
    overflow = False
    line_start = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            piece = chunk[start:] if newline < 0 else chunk[start:newline]
            if not overflow:
                buffer.extend(piece)
                if len(buffer) > limits.max_line_bytes:
                    del buffer[limits.max_line_bytes + 1 :]
                    overflow = True
            if newline < 0:
                offset += len(chunk) - start
                break
            position += 1
            offset += newline - start + 1
            yield RawRecord(position=position, content=bytes(buffer).rstrip(b"\r"), offset=line_start)
            line_start = offset
            buffer.clear()
            overflow = False
            start = newline + 1
    if buffer:
        position += 1
        yield RawRecord(position=position, content=bytes(buffer).rstrip(b"\r"), offset=line_start)
