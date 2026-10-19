"""Watched drop folder (spec 5.1).

Layout - the directory name is the source type::

    <drop>/windows_xml/export.xml
    <drop>/syslog_3164/auth.log
    <drop>/json@musterfirma_vpn/vpn.ndjson   (``@`` stands for ``:`` - not allowed on Windows)

A file is picked up once its size and modification time did not change
between two scans (the writer has finished). It is moved to
``<drop>/.processing/`` and an ``ingest_file`` job is queued; the job deletes
the file after a successful import. Files in unknown directories are moved to
``<drop>/failed/`` with a ``.error.txt`` next to them. Hidden files and
directories are ignored.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelops.ingest.sources import UnsupportedSourceError, validate_source_type
from sentinelops.normalize.dedupe import stable_hash
from sentinelops.parsers.json_mapped import MappingProfile
from sentinelops.storage import jobs

log = logging.getLogger("sentinelops.drop_folder")
PROCESSING = ".processing"
FAILED = "failed"


def source_type_for(directory: str) -> str:
    return directory.replace("@", ":", 1)


@dataclass(frozen=True)
class FileState:
    size: int
    mtime_ns: int


@dataclass
class DropFolderScanner:
    """Remembers file states between scans; pure decision logic is in :meth:`stable`."""

    root: Path
    timezone: str = "UTC"
    seen: dict[Path, FileState] = field(default_factory=dict)

    def stable(self, current: Mapping[Path, FileState]) -> list[Path]:
        """Files whose state equals the state of the previous scan."""
        ready = sorted(path for path, state in current.items() if self.seen.get(path) == state)
        self.seen = {path: state for path, state in current.items() if path not in ready}
        return ready

    def _list(self) -> dict[Path, FileState]:
        result: dict[Path, FileState] = {}
        if not self.root.is_dir():
            return result
        for directory in sorted(self.root.iterdir()):
            if not directory.is_dir() or directory.name.startswith(".") or directory.name == FAILED:
                continue
            for path in sorted(directory.iterdir()):
                if path.is_file() and not path.name.startswith("."):
                    stat = path.stat()
                    result[path] = FileState(stat.st_size, stat.st_mtime_ns)
        return result

    def _move(self, path: Path, target_dir: Path) -> Path:
        target_dir.mkdir(parents=True, exist_ok=True)
        stat = path.stat()
        target = target_dir / f"{stable_hash('drop', str(path), stat.st_size, stat.st_mtime_ns, length=12)}-{path.name}"
        path.replace(target)
        return target

    def _fail(self, path: Path, reason: str) -> None:
        target = self._move(path, self.root / FAILED)
        target.with_name(target.name + ".error.txt").write_text(reason + "\n", encoding="utf-8")

    async def scan(self, engine: AsyncEngine, profiles: Mapping[str, MappingProfile], now: datetime) -> int:
        """One scan; returns the number of queued files."""
        current = await asyncio.to_thread(self._list)
        queued = 0
        for path in self.stable(current):
            source_type = source_type_for(path.parent.name)
            try:
                validate_source_type(source_type, profiles)
            except UnsupportedSourceError as exc:
                log.warning("drop folder: %s", exc)
                await asyncio.to_thread(self._fail, path, str(exc))
                continue
            moved = await asyncio.to_thread(self._move, path, self.root / PROCESSING)
            async with engine.begin() as conn:
                await jobs.enqueue(
                    conn,
                    "ingest_file",
                    {
                        "path": str(moved),
                        "source_type": source_type,
                        "timezone": self.timezone,
                        "file_name": f"{path.parent.name}/{path.name}",
                        "channel": "drop_folder",
                        "actor": "drop_folder",
                        "delete_after": True,
                    },
                    now,
                    dedupe=False,
                )
            queued += 1
        return queued
