"""CSV exports with protection against formula injection (spec 10).

Spreadsheet programs interpret cells starting with ``= + - @`` (and tab or
carriage return) as formulas. Such cells are prefixed with a single quote, as
recommended by OWASP ("CSV Injection").
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence
from typing import Any

DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    text = str(value)
    if text.startswith(DANGEROUS_PREFIXES):
        return "'" + text
    return text


def to_csv(columns: Sequence[str], rows: Iterable[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow([safe_cell(c) for c in columns])
    for row in rows:
        writer.writerow([safe_cell(row.get(c)) for c in columns])
    return buffer.getvalue()
