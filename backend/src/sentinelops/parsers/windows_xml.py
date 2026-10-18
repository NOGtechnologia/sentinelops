"""Windows event XML (``wevtutil qe /f:xml``, Event Viewer "Save as XML").

XML is only ever parsed with :mod:`defusedxml` (no DTDs, no entity expansion).
Records are located with a streaming byte scanner so the original bytes of
each ``<Event>`` element are kept unchanged.
"""

from __future__ import annotations

import io
import re
from collections.abc import Iterator
from typing import BinaryIO
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring

from sentinelops.normalize.quality import Malformed, decode_text
from sentinelops.normalize.schema import MalformedCode, SourceType
from sentinelops.parsers.base import ParseContext, ParseResult, RawRecord, Readable
from sentinelops.parsers.windows_common import WinEvent, to_parsed

_START = re.compile(rb"<Event[\s>]")
_END = b"</Event>"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _utf8_stream(stream: BinaryIO) -> Readable:
    """Transcode UTF-16 exports (Event Viewer default) to UTF-8 on the fly."""
    head = stream.read(2)
    if head in (b"\xff\xfe", b"\xfe\xff"):
        encoding = "utf-16-le" if head == b"\xff\xfe" else "utf-16-be"
        return _Utf8Reader(io.TextIOWrapper(stream, encoding=encoding, errors="replace"))
    return _Prefixed(head, stream)


class _Prefixed:
    def __init__(self, prefix: bytes, stream: BinaryIO) -> None:
        self._prefix = prefix
        self._stream = stream

    def read(self, size: int = -1, /) -> bytes:
        if self._prefix:
            data, self._prefix = self._prefix, b""
            return data
        return self._stream.read(size)


class _Utf8Reader:
    def __init__(self, text: io.TextIOWrapper) -> None:
        self._text = text

    def read(self, size: int = -1, /) -> bytes:
        return self._text.read(size if size > 0 else -1).encode("utf-8")


def split_events(
    stream: BinaryIO, max_record_bytes: int, chunk_size: int = 1 << 16
) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
    source = _utf8_stream(stream)
    buffer = b""
    offset = 0  # offset of buffer[0] in the (UTF-8) stream
    position = 0
    eof = False
    while not eof or buffer:
        if not eof:
            chunk = source.read(chunk_size)
            if chunk:
                buffer += chunk
            else:
                eof = True
        match = _START.search(buffer)
        if match is None:
            # keep a small tail in case a start tag spans two chunks
            keep = 8
            offset += max(0, len(buffer) - keep)
            buffer = buffer[-keep:] if not eof else b""
            continue
        start = match.start()
        end = buffer.find(_END, start)
        if end < 0:
            if len(buffer) - start > max_record_bytes:
                position += 1
                raw = RawRecord(position, buffer[start : start + 256], offset + start)
                yield (
                    raw,
                    Malformed(
                        MalformedCode.OVERSIZED, f"event element exceeds {max_record_bytes} bytes", offset + start
                    ),
                )
                next_start = _START.search(buffer, start + 1)
                cut = next_start.start() if next_start else len(buffer)
                offset += cut
                buffer = buffer[cut:]
                continue
            if eof:
                position += 1
                raw = RawRecord(position, buffer[start:], offset + start)
                yield raw, Malformed(MalformedCode.TRUNCATED, "missing </Event>", offset + start)
                buffer = b""
            continue
        stop = end + len(_END)
        position += 1
        yield RawRecord(position, buffer[start:stop], offset + start)
        offset += stop
        buffer = buffer[stop:]


def element_to_winevent(root: Element) -> WinEvent | Malformed:
    if _local(root.tag) != "Event":
        return Malformed(MalformedCode.SCHEMA_VIOLATION, f"unexpected root element {_local(root.tag)}")
    system = next((c for c in root if _local(c.tag) == "System"), None)
    if system is None:
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "System element missing")
    sysvals: dict[str, Element] = {_local(c.tag): c for c in system}
    event_id_text = (sysvals["EventID"].text or "").strip() if "EventID" in sysvals else ""
    if not event_id_text.isdigit():
        return Malformed(MalformedCode.SCHEMA_VIOLATION, "EventID missing or not numeric")
    provider = sysvals["Provider"].get("Name") if "Provider" in sysvals else None
    time_created = sysvals["TimeCreated"].get("SystemTime") if "TimeCreated" in sysvals else None
    data: dict[str, str] = {}
    for section in root:
        name = _local(section.tag)
        if name == "EventData":
            for index, item in enumerate(section):
                key = item.get("Name") or f"Data{index}"
                data[key] = item.text or ""
        elif name == "UserData":
            for wrapper in section:
                for item in wrapper:
                    data[_local(item.tag)] = item.text or ""
    return WinEvent(
        provider=provider,
        event_id=int(event_id_text),
        channel=_text(sysvals.get("Channel")),
        computer=_text(sysvals.get("Computer")),
        record_id=_text(sysvals.get("EventRecordID")),
        time_created=time_created,
        data=data,
    )


def _text(element: Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    return element.text.strip() or None


def parse_xml_record(content: bytes, ctx: ParseContext) -> WinEvent | Malformed:
    text = decode_text(content, ctx.limits)
    if isinstance(text, Malformed):
        return text
    try:
        root = fromstring(text, forbid_dtd=True)
    except DefusedXmlException as exc:
        return Malformed(MalformedCode.PARSE_ERROR, f"forbidden XML construct: {type(exc).__name__}")
    except ParseError as exc:
        line, column = exc.position
        return Malformed(MalformedCode.PARSE_ERROR, f"XML error: {exc}", column if line == 1 else None)
    return element_to_winevent(root)


class WindowsXmlParser:
    source_type = SourceType.WINDOWS_XML.value

    def split(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[RawRecord | tuple[RawRecord, Malformed]]:
        yield from split_events(stream, ctx.limits.max_record_bytes)

    def parse(self, raw: RawRecord, ctx: ParseContext) -> ParseResult:
        event = parse_xml_record(raw.content, ctx)
        if isinstance(event, Malformed):
            return event
        return to_parsed(event, ctx, ctx.limits)
