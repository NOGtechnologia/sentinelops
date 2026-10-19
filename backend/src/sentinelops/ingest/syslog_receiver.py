"""Optional syslog receiver on UDP and TCP (spec 5.1).

* One UDP datagram is one message. TCP supports both framings of RFC 6587:
  octet counting (``<len> <msg>``) and newline-delimited messages.
* Each message is classified as RFC 5424 (``<PRI>1 ``) or RFC 3164 and
  buffered. A buffer is imported as one ingestion run (channel ``syslog``)
  when it reaches ``batch_size`` messages or ``flush_seconds`` passed - the
  same parser, deduplication and quarantine as file imports.
* Limits: messages above ``max_message_bytes`` are truncated and marked by the
  parser as malformed (``OVERSIZED``) through the normal size checks; when more
  than ``max_buffered`` messages wait, new messages are dropped and counted
  (``dropped``) instead of exhausting memory.
* Newlines inside a message are replaced by spaces (the parsers are line based).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from sentinelops.normalize.quality import Limits

log = logging.getLogger("sentinelops.syslog")
RFC5424 = re.compile(rb"^<\d{1,3}>1 ")
SOURCE_5424 = "syslog_5424"
SOURCE_3164 = "syslog_3164"
#: ``(source_type, data, sha256)`` -> imported; implemented by the caller (database ingestion).
Sink = Callable[[str, bytes, str], Awaitable[None]]


def classify(message: bytes) -> str:
    return SOURCE_5424 if RFC5424.match(message) else SOURCE_3164


def clean(message: bytes, limit: int) -> bytes:
    body = message.rstrip(b"\r\n\x00").replace(b"\r\n", b" ").replace(b"\n", b" ").replace(b"\r", b" ")
    # Keep one byte more than the limit so the parser's size check reports OVERSIZED.
    return body[: limit + 1]


class OctetFramer:
    """Splits a TCP byte stream into messages (RFC 6587 octet counting or LF)."""

    def __init__(self, max_message_bytes: int) -> None:
        self.buffer = b""
        self.limit = max_message_bytes

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer += data
        messages: list[bytes] = []
        while self.buffer:
            match = re.match(rb"^(\d{1,7}) ", self.buffer)
            if match:
                length = int(match.group(1))
                start = match.end()
                if len(self.buffer) - start < length:
                    if length > self.limit * 4:  # absurd length: resynchronise on the next newline
                        self.buffer = self.buffer[start:]
                        continue
                    break
                messages.append(self.buffer[start : start + length])
                self.buffer = self.buffer[start + length :]
                continue
            newline = self.buffer.find(b"\n")
            if newline < 0:
                if len(self.buffer) > self.limit:  # no delimiter in sight: emit what we have
                    messages.append(self.buffer)
                    self.buffer = b""
                break
            messages.append(self.buffer[:newline])
            self.buffer = self.buffer[newline + 1 :]
        return [m for m in messages if m.strip()]

    def finish(self) -> list[bytes]:
        rest, self.buffer = self.buffer, b""
        return [rest] if rest.strip() else []


@dataclass
class SyslogCollector:
    sink: Sink
    batch_size: int = 5000
    flush_seconds: float = 5.0
    max_message_bytes: int = Limits().max_line_bytes
    max_buffered: int = 100_000
    buffers: dict[str, list[bytes]] = field(default_factory=lambda: {SOURCE_3164: [], SOURCE_5424: []})
    dropped: int = 0
    received: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def buffered(self) -> int:
        return sum(len(v) for v in self.buffers.values())

    async def add(self, message: bytes) -> None:
        body = clean(message, self.max_message_bytes)
        if not body.strip():
            return
        if self.buffered() >= self.max_buffered:
            self.dropped += 1
            return
        self.received += 1
        source = classify(body)
        self.buffers[source].append(body)
        if len(self.buffers[source]) >= self.batch_size:
            await self.flush(source)

    async def flush(self, only: str | None = None) -> None:
        async with self._lock:
            for source in sorted(self.buffers):
                if only is not None and source != only:
                    continue
                lines, self.buffers[source] = self.buffers[source], []
                if not lines:
                    continue
                data = b"\n".join(lines) + b"\n"
                try:
                    await self.sink(source, data, hashlib.sha256(data).hexdigest())
                except Exception:  # keep receiving; the failed batch is logged with its size
                    log.exception("syslog batch of %d %s messages could not be imported", len(lines), source)

    async def run_flusher(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.flush_seconds)
            except TimeoutError:
                await self.flush()
        await self.flush()


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector) -> None:
        self.collector = collector
        self.tasks: set[asyncio.Task[None]] = set()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        task = asyncio.ensure_future(self.collector.add(data))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)


async def _handle_tcp(collector: SyslogCollector, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    framer = OctetFramer(collector.max_message_bytes)
    try:
        while data := await reader.read(65536):
            for message in framer.feed(data):
                await collector.add(message)
        for message in framer.finish():
            await collector.add(message)
    finally:
        writer.close()


async def serve(
    collector: SyslogCollector, host: str, port: int, stop: asyncio.Event, ready: asyncio.Event | None = None
) -> None:
    """Run UDP and TCP listeners until ``stop`` is set."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(collector), local_addr=(host, port))
    server = await asyncio.start_server(lambda r, w: _handle_tcp(collector, r, w), host, port)
    log.info("syslog receiver listening on %s:%d (udp+tcp)", host, port)
    if ready is not None:
        ready.set()
    try:
        await collector.run_flusher(stop)
    finally:
        transport.close()
        server.close()
        await server.wait_closed()
