from __future__ import annotations

import random
from dataclasses import replace
from datetime import timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from sentinelops.correlation.alerts import Alert, Entity, alert_id, event_entities, is_external_ip, merge_entities
from sentinelops.correlation.analysis import case_title
from sentinelops.correlation.case_builder import build_cases, case_id_for, detect_hubs
from sentinelops.correlation.priority import Factor, RuleStats, compute_priority, level_for
from sentinelops.correlation.timeline import build_timeline
from sentinelops.detection.config import DetectionConfig
from sentinelops.investigation.catalog import default_catalog
from sentinelops.investigation.recommendations import recommend
from sentinelops.normalize.schema import CanonicalEvent
from tests.conftest import T0, make_event
from tests.unit.test_correlation import meta

CFG = DetectionConfig()
W = timedelta(hours=2)


def alert(
    aid: str,
    start_s: float,
    entities: list[tuple[str, str]],
    *,
    level: str = "high",
    end_s: float | None = None,
    event_ids: tuple[str, ...] = ("e",),
    **kw: object,
) -> Alert:
    base = Alert(
        alert_id=aid,
        rule_id=str(kw.pop("rule_id", "SO-TEST-001")),
        rule_version=1,
        rule_hash="h",
        kind="single",
        title="Test alert",
        title_de="Testalarm",
        level=level,
        maturity=str(kw.pop("maturity", "stable")),
        tactics=tuple(kw.pop("tactics", ("credential-access",))),  # type: ignore[arg-type]  # test helper
        techniques=("T1110",),
        event_ids=event_ids,
        window_start=T0 + timedelta(seconds=start_s),
        window_end=T0 + timedelta(seconds=end_s if end_s is not None else start_s),
        group_key=(),
        entities=tuple(sorted(Entity(t, k, k) for t, k in entities)),
        explanation={},
    )
    return replace(base, **kw)  # type: ignore[arg-type]  # test helper with dynamic kwargs


# --- entities ------------------------------------------------------------------


def test_event_entities_filters_machine_and_builtin_accounts() -> None:
    event = make_event(
        user__name="DC01$",
        user__target__name="Lena",
        host__name="DC01.musterfirma.example",
        source__host="-",
        source__ip="127.0.0.1",
    )
    assert [(e.type, e.key) for e in event_entities(event)] == [("user", "lena"), ("host", "dc01")]
    other = make_event(user__name="SYSTEM", source__ip="::ffff:203.0.113.5", source__host="WS-1")
    assert [(e.type, e.key) for e in event_entities(other)] == [("host", "ws-1"), ("ip", "203.0.113.5")]
    assert event_entities(make_event(source__ip="not-an-ip", host__name="localhost")) == []


def test_merge_entities_keeps_first_display() -> None:
    a = make_event(1, user__name="Erika")
    b = make_event(2, user__name="MUSTERFIRMA\\erika")
    assert merge_entities([a, b]) == (Entity("user", "erika", "Erika"),)


def test_is_external_ip() -> None:
    assert is_external_ip("203.0.113.5")
    assert not is_external_ip("10.0.0.1")
    assert not is_external_ip(None)
    assert not is_external_ip("garbage")


def test_alert_to_dict_and_suppression() -> None:
    a = alert("a1", 0, [("user", "x")], group_key=(("user.name", "x"),))
    data = a.to_dict()
    assert data["group_key"] == {"user.name": "x"}
    assert data["window_start"].endswith("Z")
    suppressed = a.with_suppression("EXC-0001")
    assert suppressed.suppressed
    assert not a.suppressed
    assert alert_id("R", 1, ["e"], T0) == alert_id("R", 1, ["e"], T0)


# --- case building ---------------------------------------------------------------


def test_shared_entity_within_window_forms_one_case() -> None:
    a = alert("a", 0, [("user", "jonas"), ("ip", "203.0.113.5")])
    b = alert("b", 3600, [("user", "jonas"), ("host", "dc01")])
    c = alert("c", 3600 * 10, [("user", "jonas")])
    d = alert("d", 100, [("user", "anna")])
    cases = build_cases([a, b, c, d], ["dc01"], W)
    groups = sorted(tuple(c.alert_ids) for c in cases)
    assert groups == [("a", "b"), ("c",), ("d",)]
    first = next(c for c in cases if c.alert_ids == ("a", "b"))
    assert first.case_id == case_id_for("a")
    assert [e.key for e in first.entities] == ["dc01", "203.0.113.5", "jonas"]


def test_transitive_linking_and_hub_suppression() -> None:
    a = alert("a", 0, [("user", "u1"), ("host", "dc01")])
    b = alert("b", 10, [("user", "u2"), ("host", "dc01")])
    c = alert("c", 20, [("user", "u2"), ("ip", "203.0.113.9")])
    d = alert("d", 30, [("ip", "203.0.113.9")])
    cases = build_cases([a, b, c, d], ["DC01"], W)
    assert sorted(c.alert_ids for c in cases) == [("a",), ("b", "c", "d")]
    no_hub = build_cases([a, b, c, d], [], W)
    assert len(no_hub) == 1


def test_long_windows_chain() -> None:
    a = alert("a", 0, [("user", "x")], end_s=20000)
    b = alert("b", 21000, [("user", "x")])
    assert len(build_cases([a, b], [], W)) == 1


def test_suppressed_alerts_never_form_cases() -> None:
    a = alert("a", 0, [("user", "x")], suppressed_by="EXC-0001")
    assert build_cases([a], [], W) == []


def test_pinned_open_case_is_extended_closed_case_is_not() -> None:
    a = alert("a", 0, [("user", "x")])
    b = alert("b", 60, [("user", "x")])
    c = alert("c", 120, [("user", "x")])
    open_cases = build_cases([a, b, c], [], W, pinned={"a": "CASE-OPEN", "b": "CASE-OPEN"})
    assert [(d.case_id, d.alert_ids) for d in open_cases] == [("CASE-OPEN", ("a", "b", "c"))]
    closed = build_cases(
        [a, b, c], [], W, pinned={"a": "CASE-OLD", "b": "CASE-OLD"}, closed_case_ids=frozenset({"CASE-OLD"})
    )
    by_id = {d.case_id: d for d in closed}
    assert by_id["CASE-OLD"].alert_ids == ("a", "b")
    new = by_id[case_id_for("c")]
    assert new.alert_ids == ("c",)
    assert new.related_case_ids == ("CASE-OLD",)
    only_pinned = build_cases([a], [], W, pinned={"a": "CASE-OLD"})
    assert only_pinned[0].case_id == "CASE-OLD"


def test_earliest_open_case_receives_new_alerts() -> None:
    a = alert("a", 0, [("user", "x")])
    b = alert("b", 60, [("user", "x"), ("user", "y")])
    c = alert("c", 120, [("user", "y")])
    cases = build_cases([a, b, c], [], W, pinned={"a": "CASE-2", "c": "CASE-1"})
    by_id = {d.case_id: d.alert_ids for d in cases}
    assert by_id == {"CASE-2": ("a", "b"), "CASE-1": ("c",)}


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.integers(0, 40000), st.sampled_from(["u1", "u2", "u3", "hub"]), st.sampled_from(["h1", "h2", "hub"])
        ),
        min_size=1,
        max_size=25,
    ),
    st.randoms(),
)
def test_case_building_is_order_independent(spec: list[tuple[int, str, str]], rnd: random.Random) -> None:
    alerts = [alert(f"a{i:02d}", t, [("user", u), ("host", h)]) for i, (t, u, h) in enumerate(spec)]
    shuffled = alerts[:]
    rnd.shuffle(shuffled)
    assert build_cases(alerts, ["hub"], W) == build_cases(shuffled, ["hub"], W)


def test_detect_hubs_uses_successful_activity_only() -> None:
    events = [make_event(i, user__name=f"u{i}", host__name="srv-file01", event__outcome="success") for i in range(5)]
    events += [make_event(i, user__name=f"v{i}", source__ip="203.0.113.66", event__outcome="failure") for i in range(9)]
    events.append(make_event(99, host__name="srv-x", event__outcome="success"))
    events += [make_event(i, user__name=f"w{i}", host__name="dc01", event__outcome="success") for i in range(6)]
    hubs = detect_hubs(events, ["DC01"], min_distinct_users=5)
    assert [(h.key, h.reason) for h in hubs] == [("dc01", "configured"), ("srv-file01", "distinct_users>=5 (5)")]


# --- priority --------------------------------------------------------------------


def scenario2() -> tuple[list[Alert], dict[str, CanonicalEvent]]:
    failures = [
        make_event(
            i,
            event_id=f"f{i}",
            user__name="jonas.becker",
            source__ip="203.0.113.45",
            event__action="logon-failed",
            host__name="srv-gw01",
        )
        for i in range(3)
    ]
    success = make_event(
        200,
        event_id="s1",
        user__name="jonas.becker",
        source__ip="203.0.113.45",
        event__action="logon",
        host__name="srv-gw01",
    )
    group = make_event(
        500,
        event_id="g1",
        user__name="jonas.becker",
        user__target__name="jonas.becker",
        group__name="Domain Admins",
        event__action="user-added-to-group",
        host__name="DC01.musterfirma.example",
    )
    priv = make_event(
        560, event_id="p1", user__name="jonas.becker", event__action="special-privileges-assigned", host__name="dc01"
    )
    events = {e.event_id: e for e in [*failures, success, group, priv]}
    alerts = [
        alert("bf", 0, [("user", "jonas.becker")], event_ids=("f0", "f1", "f2"), tactics=("credential-access",)),
        alert(
            "seq",
            200,
            [("user", "jonas.becker")],
            event_ids=("f0", "s1"),
            success_after_failures=True,
            tactics=("credential-access", "initial-access"),
            explanation={"success_event_id": "s1", "preceding_alert": {"failures_for_group": 3}},
        ),
        alert(
            "grp",
            500,
            [("user", "jonas.becker")],
            level="critical",
            event_ids=("g1",),
            privilege_change=True,
            rule_id="SO-PRIV-001",
            tactics=("persistence", "privilege-escalation"),
        ),
        alert("4672", 560, [("user", "jonas.becker")], event_ids=("p1",), tactics=("privilege-escalation",)),
    ]
    return alerts, events


def test_priority_scenario2_is_p1_with_explained_factors() -> None:
    alerts, events = scenario2()
    result = compute_priority(alerts, events, CFG)
    codes = {f.code: f for f in result.factors}
    assert result.level == "P1"
    assert result.score == 100
    assert codes["max_severity"].contribution == 70
    assert codes["success_after_failures"].label_de.startswith(
        "Erfolgreiche Anmeldung von 203.0.113.45 um 03:03 nach 3"
    )
    assert "s1" in codes["success_after_failures"].evidence
    assert codes["privileged_account"].evidence[0] == "g1"
    assert codes["critical_asset"].label_de == "Kritisches Asset beteiligt: dc01"
    assert codes["attack_tactics"].contribution == 15
    assert result.to_dict()["factors"][0]["code"] == "max_severity"


def test_priority_low_case_and_penalties() -> None:
    lock = make_event(0, event_id="l1", user__target__name="lena", event__action="account-locked", host__name="ws-1")
    low = [alert("lk", 0, [("user", "lena")], level="low", event_ids=("l1",), maturity="experimental")]
    result = compute_priority(low, {"l1": lock}, CFG, {"SO-TEST-001": RuleStats(10, 8)})
    codes = {f.code: f.contribution for f in result.factors}
    assert codes == {"max_severity": 15, "experimental_rule": -10, "false_positive_rate": -15}
    assert result.score == 0
    assert result.level == "P4"
    few = compute_priority(low, {"l1": lock}, CFG, {"SO-TEST-001": RuleStats(2, 2)})
    assert "false_positive_rate" not in {f.code for f in few.factors}
    tiny = compute_priority(low, {"l1": lock}, CFG, {"SO-TEST-001": RuleStats(100, 1)})
    assert "false_positive_rate" not in {f.code for f in tiny.factors}
    assert RuleStats(0, 0).rate == 0.0


def test_priority_requires_alerts_and_missing_events() -> None:
    import pytest

    with pytest.raises(ValueError, match="at least one alert"):
        compute_priority([], {}, CFG)
    lone = [alert("x", 0, [("user", "a")], event_ids=("missing",), success_after_failures=True)]
    result = compute_priority(lone, {}, CFG)
    assert "?" in next(f.label_de for f in result.factors if f.code == "success_after_failures")


def test_levels() -> None:
    assert [level_for(s, CFG) for s in (100, 80, 79, 60, 59, 35, 34, 0)] == [
        "P1",
        "P1",
        "P2",
        "P2",
        "P3",
        "P3",
        "P4",
        "P4",
    ]


AGGRAVATING = st.sampled_from(["privileged", "critical", "change", "tactic", "success"])


@settings(max_examples=80, deadline=None)
@given(st.sampled_from(["informational", "low", "medium", "high", "critical"]), st.sets(AGGRAVATING), AGGRAVATING)
def test_priority_monotone_in_aggravating_factors(level: str, present: set[str], extra: str) -> None:
    def build(flags: set[str]) -> int:
        fields: dict[str, object] = {
            "user__name": "adm-x" if "privileged" in flags else "user",
            "host__name": "dc01" if "critical" in flags else "ws-9",
        }
        ev = make_event(0, event_id="e1", **fields)
        a = alert(
            "a",
            0,
            [("user", "x")],
            level=level,
            event_ids=("e1",),
            privilege_change="change" in flags,
            success_after_failures="success" in flags,
            tactics=("credential-access", "persistence") if "tactic" in flags else ("credential-access",),
        )
        return compute_priority([a], {"e1": ev}, CFG).score

    assert build(present | {extra}) >= build(present)


def test_factor_to_dict() -> None:
    assert Factor("x", 1, "de", "en", ("e",)).to_dict() == {
        "code": "x",
        "contribution": 1,
        "label_de": "de",
        "label_en": "en",
        "evidence": ["e"],
    }


# --- timeline, recommendations, titles ------------------------------------------


def test_timeline_marks_triggers_and_gaps() -> None:
    alerts, events = scenario2()
    items = build_timeline(alerts, events, gap=timedelta(minutes=2))
    kinds = [i.kind for i in items]
    assert kinds[0] == "event"
    assert "gap" in kinds
    assert "alert" in kinds
    first = items[0].to_dict()
    assert first["rules"] == ["SO-TEST-001"]
    assert "user:jonas.becker" in first["lanes"]
    times = [i.time for i in items]
    assert times == sorted(times)


def test_recommendations_from_rule_playbooks() -> None:
    alerts, events = scenario2()
    metas = {
        "SO-TEST-001": replace(meta(), playbooks=("VERIFY_ACCOUNT_ACTIVITY", "DISABLE_ACCOUNT")),
        "SO-PRIV-001": replace(meta("SO-PRIV-001"), playbooks=("REVIEW_GROUP_MEMBERSHIP", "DISABLE_ACCOUNT")),
    }
    steps = recommend(alerts, events, metas, default_catalog())
    assert [s.step_id for s in steps] == ["VERIFY_ACCOUNT_ACTIVITY", "DISABLE_ACCOUNT", "REVIEW_GROUP_MEMBERSHIP"]
    disable = steps[1].to_dict()
    assert disable["action"] is True
    assert disable["reason_rules"] == ["SO-PRIV-001", "SO-TEST-001"]
    assert disable["targets"] == {"user": ["jonas.becker"]}
    assert steps[2].targets == {"user": ["jonas.becker"], "group": ["Domain Admins"]}
    assert recommend(alerts, events, {}, default_catalog()) == []


def test_case_title() -> None:
    one = [alert("a", 0, [("user", "jonas")])]
    assert case_title(one) == ("Test alert: jonas", "Testalarm: jonas")
    many = [
        alert("a", 0, [("user", "u1"), ("user", "u2")]),
        alert("b", 1, [("user", "x")], level="low"),
        alert("c", 2, [("host", "h")], level="low"),
    ]
    assert case_title(many) == ("Test alert: 2 accounts (+2 more alerts)", "Testalarm: 2 Konten (+2 weitere Alarme)")
    host_only = [alert("a", 0, [("host", "srv")]), alert("b", 1, [], level="low")]
    assert case_title(host_only) == ("Test alert: srv (+1 more alert)", "Testalarm: srv (+1 weiterer Alarm)")
    assert case_title([alert("a", 0, [])]) == ("Test alert", "Testalarm")
