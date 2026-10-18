"""Streaming splitter for NDJSON and top-level JSON arrays.

A JSON array file is split into its elements by a small byte scanner that
tracks string/escape state and nesting depth - the file is never loaded as a
whole (spec 5.7).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from sentinelops.normalize.quality import Limits, Malformed
from sentinelops.normalize.schema import MalformedCode
from sentinelops.parsers.base import RawRecord, iter_lines

_WS = frozenset(b" \t\r\n")
_BOM = frozenset(b"\xef\xbb\xbf")
_PREVIEW = 256


def split_json(
    stream: BinaryIO, limits: Limits, chunk_size: int = 1 << 16
) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
    first = b""
    while True:
        byte = stream.read(1)
        if not byte:
            return
        if byte[0] not in _WS and byte[0] not in _BOM:
            first = byte
            break
    if first == b"[":
        yield from _ArraySplitter(limits).run(stream, chunk_size)
        return
    for raw in iter_lines(_Prepend(first, stream), limits):
        if not raw.content.strip():
            continue
        if len(raw.content) > limits.max_line_bytes:
            yield raw, Malformed(MalformedCode.OVERSIZED, f"line exceeds {limits.max_line_bytes} bytes")
            continue
        yield raw


class _Prepend:
    def __init__(self, prefix: bytes, stream: BinaryIO) -> None:
        self._prefix = prefix
        self._stream = stream

    def read(self, size: int = -1) -> bytes:
        if self._prefix:
            data, self._prefix = self._prefix, b""
            if size < 0:
                return data + self._stream.read()
            return data + self._stream.read(max(0, size - len(data)))
        return self._stream.read(size)


@dataclass(slots=True)
class _ArraySplitter:
    limits: Limits
    position: int = 0
    depth: int = 0
    in_string: bool = False
    escape: bool = False
    scalar: bool = False
    oversized: bool = False
    closed: bool = False
    element_start: int = 1
    current: bytearray = field(default_factory=bytearray)

    def _emit(self, error: Malformed | None = None) -> RawRecord | tuple[RawRecord, Malformed]:
        self.position += 1
        content = bytes(self.current[:_PREVIEW] if (self.oversized or error) else self.current)
        raw = RawRecord(self.position, content, self.element_start)
        self.current.clear()
        oversized, self.oversized, self.scalar = self.oversized, False, False
        if oversized:
            return raw, Malformed(
                MalformedCode.OVERSIZED, f"element exceeds {self.limits.max_record_bytes} bytes", raw.offset
            )
        if error is not None:
            return raw, error
        return raw

    def _append(self, value: int) -> None:
        if self.oversized:
            return
        self.current.append(value)
        if len(self.current) > self.limits.max_record_bytes:
            self.oversized = True

    def run(self, stream: BinaryIO, chunk_size: int) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        offset = 1
        while not self.closed:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            for index, value in enumerate(chunk):
                result = self._feed(value, offset + index)
                if result is not None:
                    yield result
                if self.closed:
                    break
            offset += len(chunk)
        if self.current.strip():
            yield self._emit(Malformed(MalformedCode.TRUNCATED, "JSON array element not terminated", self.element_start))
        elif not self.closed:
            self.position += 1
            yield RawRecord(self.position, b"", offset), Malformed(
                MalformedCode.TRUNCATED, "JSON array not closed", offset
            )

    def _feed(self, value: int, pos: int) -> RawRecord | tuple[RawRecord, Malformed] | None:
        char = chr(value)
        if self.in_string:
            self._append(value)
            if self.escape:
                self.escape = False
            elif char == "\\":
                self.escape = True
            elif char == '"':
                self.in_string = False
            return None
        if self.depth == 0 and not self.current:
            if value in _WS or char == ",":
                return None
            if char == "]":
                self.closed = True
                return None
            self.element_start = pos
            self.scalar = char not in "{["
        if self.depth == 0 and self.scalar and char in ",]":
            if char == "]":
                self.closed = True
            return self._emit(
                Malformed(MalformedCode.SCHEMA_VIOLATION, "array element is not an object", self.element_start)
            )
        self._append(value)
        if char == '"':
            self.in_string = True
        elif char in "{[":
            self.depth += 1
        elif char in "}]":
            self.depth -= 1
            if self.depth == 0:
                return self._emit()
        return None
