"""End-to-end analysis with the real rule set on a small, hand-made story."""

from __future__ import annotations

from datetime import timedelta
from zoneinfo import ZoneInfo

from sentinelops.correlation.analysis import analyze
from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.exceptions import load_exceptions
from sentinelops.detection.sigma_loader import load_ruleset
from sentinelops.investigation.catalog import catalog_ids, default_catalog
from sentinelops.normalize.schema import CanonicalEvent
from sentinelops.settings import RULES_DIR
from tests.conftest import T0, make_event

BERLIN = ZoneInfo("Europe/Berlin")


def story() -> list[CanonicalEvent]:
    events = [
        make_event(
            i * 4,
            user__name="jonas.becker",
            source__ip="203.0.113.45",
            host__name="srv-gw01",
            event__action="logon-failed",
            event__outcome="failure",
        )
        for i in range(20)
    ]
    events.append(
        make_event(
            100,
            user__name="jonas.becker",
            source__ip="203.0.113.45",
            host__name="srv-gw01",
            event__action="logon",
            event__outcome="success",
            logon__type=10,
        )
    )
    events.append(
        make_event(
            500,
            user__name="jonas.becker",
            user__target__name="jonas.becker",
            group__name="Domain Admins",
            host__name="dc01",
            event__action="user-added-to-group",
            event__outcome="success",
        )
    )
    # unrelated low-severity lockout of another user on the same DC (hub) - separate case
    events.append(
        make_event(
            600,
            user__name="DC01$",
            user__target__name="lena.hoffmann",
            host__name="dc01",
            event__action="account-locked",
            event__outcome="success",
        )
    )
    return events


def test_analyze_builds_explained_cases() -> None:
    cfg = DetectionConfig()
    ruleset = load_ruleset(RULES_DIR, cfg, catalog_ids())
    result = analyze(
        story(),
        ruleset,
        cfg,
        load_exceptions(RULES_DIR / "exceptions"),
        default_catalog(),
        T0 + timedelta(hours=1),
        BERLIN,
    )
    assert len(result.cases) == 2
    main = max(result.cases, key=lambda c: c.priority.score)
    assert main.priority.level == "P1"
    assert {a.rule_id for a in main.alerts} == {"SO-AUTH-001", "SO-AUTH-003", "SO-PRIV-001"}
    assert main.title_de.startswith("Aufnahme in privilegierte Gruppe: jonas.becker")
    assert main.recommendations[0].step_id == "VERIFY_ACCOUNT_ACTIVITY"
    assert main.case_id == main.draft.case_id
    lock = min(result.cases, key=lambda c: c.priority.score)
    assert lock.priority.level == "P4"
    mapping = result.case_of_alert()
    assert all(mapping[a.alert_id] == main.case_id for a in main.alerts)
    assert set(result.events_by_id) == {e.event_id for e in story()}
    assert any(h.key == "dc01" for h in result.hubs)


def test_analyze_is_deterministic_and_order_independent() -> None:
    cfg = DetectionConfig()
    ruleset = load_ruleset(RULES_DIR, cfg, catalog_ids())
    exceptions = load_exceptions(RULES_DIR / "exceptions")
    now = T0 + timedelta(hours=1)
    a = analyze(story(), ruleset, cfg, exceptions, default_catalog(), now, BERLIN)
    b = analyze(list(reversed(story())) + story()[:5], ruleset, cfg, exceptions, default_catalog(), now, BERLIN)
    assert [c.case_id for c in a.cases] == [c.case_id for c in b.cases]
    assert [c.priority for c in a.cases] == [c.priority for c in b.cases]
    assert [a_.alert_id for a_ in a.detection.alerts] == [b_.alert_id for b_ in b.detection.alerts]
