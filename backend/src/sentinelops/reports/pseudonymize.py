"""Optional pseudonymisation of case reports (spec 16.2).

Every user, host and IP entity of the case gets a stable placeholder
(``USER_1``, ``HOST_1``, ``IP_1``; numbered in the deterministic entity order
of the case). Both the normalised key and the original spelling are replaced
in every string value of the report - including raw lines and the AI summary.
Dictionary keys (field names) stay unchanged. The mapping is *not* part of the
report; the result is reproducible for the same case.

Pure function, no I/O.
"""

from __future__ import annotations

import re
from typing import Any

_KINDS = {"user": "USER", "host": "HOST", "ip": "IP"}


def build_mapping(entities: list[dict[str, Any]]) -> dict[str, str]:
    """Value (case-folded) -> placeholder, in the order of the entity list."""
    mapping: dict[str, str] = {}
    counters: dict[str, int] = {}
    seen: dict[tuple[str, str], str] = {}
    for entity in sorted(entities, key=lambda e: (str(e.get("type", "")), str(e.get("key", "")))):
        kind = _KINDS.get(str(entity.get("type", "")))
        key = str(entity.get("key") or "")
        if kind is None or not key:
            continue
        token = seen.get((kind, key))
        if token is None:
            counters[kind] = counters.get(kind, 0) + 1
            token = f"{kind}_{counters[kind]}"
            seen[(kind, key)] = token
        for value in (key, str(entity.get("display") or "")):
            if value:
                mapping.setdefault(value.casefold(), token)
    return mapping


def _pattern(mapping: dict[str, str]) -> re.Pattern[str] | None:
    if not mapping:
        return None
    alternatives = "|".join(re.escape(k) for k in sorted(mapping, key=lambda k: (-len(k), k)))
    # Whole tokens only: 192.0.2.5 must not match inside 192.0.2.50, "admin" not inside "administrators".
    # A domain prefix (MUSTERFIRMA\\user) and a mail domain (user@...) are separators.
    return re.compile(rf"(?<![\w.-])(?:{alternatives})(?![\w-]|\.\w)", re.IGNORECASE)


def _walk(value: Any, pattern: re.Pattern[str], mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return pattern.sub(lambda m: mapping[m.group(0).casefold()], value)
    if isinstance(value, list):
        return [_walk(v, pattern, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _walk(v, pattern, mapping) for k, v in value.items()}
    return value


def pseudonymize_report(report: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``report`` with entity values replaced by placeholders."""
    mapping = build_mapping(list(report.get("case", {}).get("entities", [])))
    pattern = _pattern(mapping)
    result: dict[str, Any] = _walk(report, pattern, mapping) if pattern else dict(report)
    result["metadata"] = dict(sorted({**result.get("metadata", {}), "pseudonymized": True}.items()))
    return result
