from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sentinelops.normalize.dedupe import stable_hash
from sentinelops.normalize.schema import CanonicalEvent

T0 = datetime(2026, 3, 12, 2, 0, tzinfo=UTC)

EventFactory = Callable[..., CanonicalEvent]


def make_event(
    seconds: float = 0, original: dict[str, Any] | None = None, event_id: str | None = None, **fields: Any
) -> CanonicalEvent:
    """Canonical event at T0 + seconds; keyword names use ``__`` for dots."""
    data = {k.replace("__", "."): v for k, v in fields.items()}
    data.setdefault("event.outcome", "unknown")
    when = T0 + timedelta(seconds=seconds)
    eid = event_id or stable_hash("test-event", when.isoformat(), sorted(data.items(), key=lambda kv: kv[0]))
    return CanonicalEvent(eid, when, data, dict(original or {}))


@pytest.fixture
def event() -> EventFactory:
    return make_event
