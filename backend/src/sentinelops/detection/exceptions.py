"""Rule exceptions (spec 6.5): versioned, justified, approved, expiring.

An exception suppresses an alert of the given rule when *every* event of the
alert satisfies all ``match`` conditions (case-insensitive, ``*`` wildcard).
Suppressed alerts are kept (with ``suppressed_by``) for transparency but do
not form cases. Unapproved or expired exceptions have no effect.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date, datetime
from fnmatch import fnmatchcase
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sentinelops.correlation.alerts import Alert
from sentinelops.normalize.schema import CanonicalEvent


class RuleException(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^EXC-\d{4}$")
    version: int = Field(ge=1)
    rule_id: str
    description: str = Field(min_length=10)
    match: dict[str, str] = Field(min_length=1)
    created_by: str
    approved_by: str | None = None
    expires: date

    def active(self, now: datetime) -> bool:
        return self.approved_by is not None and now.date() <= self.expires

    def matches_event(self, event: CanonicalEvent) -> bool:
        for field_name, pattern in self.match.items():
            value = event.get(field_name)
            if value is None:
                return False
            if not fnmatchcase(str(value).casefold(), pattern.casefold()):
                return False
        return True


def load_exceptions(directory: Path) -> list[RuleException]:
    items: list[RuleException] = []
    for path in sorted(directory.glob("*.yaml")):
        for raw in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            items.append(RuleException.model_validate(raw))
    ids = [e.id for e in items]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate exception id")
    return sorted(items, key=lambda e: e.id)


def apply_exceptions(alerts: Iterable[Alert], exceptions: Iterable[RuleException],
                     events_by_id: Mapping[str, CanonicalEvent], now: datetime) -> list[Alert]:
    active = [e for e in exceptions if e.active(now)]
    out: list[Alert] = []
    for alert in alerts:
        for exc in active:
            if exc.rule_id not in (alert.rule_id, "*"):
                continue
            if all(exc.matches_event(events_by_id[eid]) for eid in alert.event_ids):
                alert = alert.with_suppression(exc.id)
                break
        out.append(alert)
    return out
