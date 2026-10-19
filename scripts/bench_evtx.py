"""EVTX library comparison for ADR-0005 (records/s on a sample file).

Usage:
  uv run --package sentinelops python scripts/bench_evtx.py <file.evtx>        # evtx (pyevtx-rs)
  uvx --from python-evtx python scripts/bench_evtx.py --python-evtx <file.evtx>  # python-evtx, isolated
"""

from __future__ import annotations

import sys
import time


def bench_rust(path: str) -> None:
    from evtx import PyEvtxParser  # noqa: PLC0415 - optional per mode

    for mode in ("records_json", "records"):
        start = time.perf_counter()
        count = sum(1 for _ in getattr(PyEvtxParser(path), mode)())
        elapsed = time.perf_counter() - start
        print(f"evtx {mode:13s} {count:6d} records {elapsed:7.3f}s {count / elapsed:10.0f} rec/s")


def bench_python(path: str) -> None:
    import Evtx.Evtx as evtx  # noqa: N813, PLC0415 - library naming, optional per mode

    start = time.perf_counter()
    with evtx.Evtx(path) as log:
        count = sum(1 for record in log.records() if record.xml())
    elapsed = time.perf_counter() - start
    print(f"python-evtx xml   {count:6d} records {elapsed:7.3f}s {count / elapsed:10.0f} rec/s")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[0] == "--python-evtx":
        bench_python(args[1])
    else:
        bench_rust(args[0])
