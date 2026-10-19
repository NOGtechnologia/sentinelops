"""Drop folder: a file is taken only after it stopped changing."""

from __future__ import annotations

from pathlib import Path

from sentinelops.ingest.drop_folder import DropFolderScanner, FileState, source_type_for


def test_source_type_from_directory() -> None:
    assert source_type_for("syslog_3164") == "syslog_3164"
    assert source_type_for("json@musterfirma_vpn") == "json:musterfirma_vpn"


def test_stable_requires_two_identical_scans(tmp_path: Path) -> None:
    scanner = DropFolderScanner(tmp_path)
    a, b = tmp_path / "x" / "a.log", tmp_path / "x" / "b.log"
    assert scanner.stable({a: FileState(10, 1)}) == []
    assert scanner.stable({a: FileState(20, 2), b: FileState(5, 1)}) == []  # a still growing
    assert scanner.stable({a: FileState(20, 2), b: FileState(5, 1)}) == [a, b]
    assert scanner.seen == {}  # taken files are forgotten
    assert scanner.stable({}) == []


def test_listing_ignores_hidden_and_failed(tmp_path: Path) -> None:
    for rel in ("syslog_3164/auth.log", "syslog_3164/.partial", ".processing/x.log", "failed/y.log", "top.log"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    listed = DropFolderScanner(tmp_path)._list()
    assert [p.relative_to(tmp_path).as_posix() for p in listed] == ["syslog_3164/auth.log"]
    assert DropFolderScanner(tmp_path / "missing")._list() == {}
