"""Syslog receiver: framing, classification, batching and real UDP/TCP sockets."""

from __future__ import annotations

import asyncio
import socket

import pytest

from sentinelops.ingest.syslog_receiver import (
    SOURCE_3164,
    SOURCE_5424,
    OctetFramer,
    SyslogCollector,
    classify,
    clean,
    serve,
)

LINE_3164 = b"<38>Mar 12 10:01:02 srv-web01 sshd[811]: Failed password for root from 203.0.113.7 port 4711 ssh2"
LINE_5424 = b"<86>1 2026-03-12T09:01:02Z srv-web01 sshd 811 - - Accepted publickey for anna from 192.0.2.5"


class Sink:
    def __init__(self) -> None:
        self.batches: list[tuple[str, bytes, str]] = []
        self.fail = False

    async def __call__(self, source: str, data: bytes, sha256: str) -> None:
        if self.fail:
            raise RuntimeError("database down")
        self.batches.append((source, data, sha256))


def test_classify_and_clean() -> None:
    assert classify(LINE_3164) == SOURCE_3164
    assert classify(LINE_5424) == SOURCE_5424
    assert clean(b"a\nb\r\nc\r\n", 100) == b"a b c"
    assert clean(b"x" * 20, 10) == b"x" * 11  # one byte over the limit -> parser reports OVERSIZED


def test_framer_octet_counting_and_newlines() -> None:
    framer = OctetFramer(1000)
    msg = b"<38>hello world"
    assert framer.feed(f"{len(msg)} ".encode() + msg[:5]) == []
    assert framer.feed(msg[5:] + b"<38>second\n<38>thi") == [msg, b"<38>second"]
    assert framer.feed(b"rd\n\n") == [b"<38>third"]
    assert framer.feed(b"<38>tail") == []
    assert framer.finish() == [b"<38>tail"]
    assert framer.finish() == []


def test_framer_limits() -> None:
    framer = OctetFramer(10)
    assert framer.feed(b"x" * 11) == [b"x" * 11]  # no delimiter and over the limit
    assert framer.feed(b"9999999 <38>abc\n") == [b"<38>abc"]  # absurd length is skipped


async def test_collector_batches_flushes_and_drops() -> None:
    sink = Sink()
    collector = SyslogCollector(sink, batch_size=2, max_buffered=2)
    await collector.add(LINE_3164)
    await collector.add(b"\n")  # empty after cleaning
    await collector.add(LINE_3164 + b" again")
    assert [b[0] for b in sink.batches] == [SOURCE_3164]
    assert sink.batches[0][1].count(b"\n") == 2
    await collector.add(LINE_5424)
    await collector.add(LINE_3164)
    await collector.add(LINE_3164 + b" 3")  # 2 buffered (limit) -> dropped
    assert collector.dropped == 1
    await collector.flush()
    assert sorted(b[0] for b in sink.batches) == [SOURCE_3164, SOURCE_3164, SOURCE_5424]
    assert collector.buffered() == 0
    sink.fail = True
    await collector.add(LINE_5424)
    await collector.flush()  # logged, not raised
    assert collector.buffered() == 0
    assert collector.received == 5


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def test_serve_udp_and_tcp() -> None:
    sink = Sink()
    collector = SyslogCollector(sink, flush_seconds=0.05)
    stop, ready = asyncio.Event(), asyncio.Event()
    port = _free_port()
    task = asyncio.create_task(serve(collector, "127.0.0.1", port, stop, ready))
    await asyncio.wait_for(ready.wait(), 5)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port))
    transport.sendto(LINE_3164)
    transport.close()
    _, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"{len(LINE_5424)} ".encode() + LINE_5424 + LINE_3164 + b" via tcp\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()

    for _ in range(100):
        if collector.received >= 3 and collector.buffered() == 0:
            break
        await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 5)
    data = b"".join(b[1] for b in sink.batches)
    assert LINE_3164 in data
    assert LINE_5424 in data
    assert b"via tcp" in data
    assert collector.received == 3


@pytest.mark.parametrize("message", [b"", b"   ", b"\r\n"])
async def test_blank_messages_ignored(message: bytes) -> None:
    collector = SyslogCollector(Sink())
    await collector.add(message)
    assert collector.received == 0
