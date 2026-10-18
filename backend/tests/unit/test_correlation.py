from __future__ import annotations

from dataclasses import replace

import pytest

from sentinelops.correlation.alerts import Alert
from sentinelops.detection.correlation import (
    BaseMatch,
    evaluate_count,
    evaluate_sequence,
    evaluate_temporal,
    group_key,
    normalise_group_value,
)
from sentinelops.detection.sigma_loader import CorrelationRule, RuleMeta, SequenceRule
from sentinelops.normalize.schema import CanonicalEvent
from tests.conftest import make_event


def meta(rule_id: str = "SO-TEST-001", kind: str = "correlation", name: str = "so_test") -> RuleMeta:
    return RuleMeta(
        rule_id=rule_id,
        version=1,
        name=name,
        uuid="u",
        title="Test",
        title_de="Test",
        description="",
        description_de="",
        level="high",
        maturity="stable",
        tactics=("credential-access",),
        techniques=("T1110",),
        falsepositives=(),
        playbooks=("VERIFY_ACCOUNT_ACTIVITY",),
        author="a",
        source="custom",
        kind=kind,
        file="f.yml",
        yaml_text="x",
        content_hash="h",
    )


def count_rule(**kwargs: object) -> CorrelationRule:
    base = {
        "meta": meta(),
        "type": "event_count",
        "rules": ("r",),
        "group_by": ("user.name",),
        "timespan_seconds": 600,
        "op": "gte",
        "count": 3,
        "value_field": None,
    }
    base.update(kwargs)
    return CorrelationRule(**base)  # type: ignore[arg-type]  # test helper with dynamic kwargs


def bm(event: CanonicalEvent, rule: str = "r") -> BaseMatch:
    return BaseMatch(rule, event, {"matched": []})


def fails(user: str, start: float, n: int, step: float = 10, ip: str = "203.0.113.5") -> list[CanonicalEvent]:
    return [
        make_event(start + i * step, user__name=user, source__ip=ip, event__action="logon-failed") for i in range(n)
    ]


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("user.name", "MUSTERFIRMA\\Erika", "erika"),
        ("user.target.name", "erika@x.example", "erika"),
        ("host.name", "DC01.musterfirma.example", "dc01"),
        ("source.ip", "::ffff:203.0.113.5", "203.0.113.5"),
        ("source.ip", "garbage", "garbage"),
        ("group.name", "Domain Admins", "domain admins"),
        ("user.name", "", None),
        ("user.name", None, None),
    ],
)
def test_normalise_group_value(field: str, value: str | None, expected: str | None) -> None:
    assert normalise_group_value(field, value) == expected


def test_group_key_missing_field() -> None:
    assert group_key(make_event(user__name="a"), ("user.name", "source.ip")) is None
    assert group_key(make_event(user__name="A"), ()) == ()


def test_event_count_burst_contains_all_events() -> None:
    events = fails("jonas", 0, 5) + fails("other", 0, 2) + [make_event(3, source__ip="203.0.113.5")]
    alerts = evaluate_count(count_rule(), [bm(e) for e in events])
    assert len(alerts) == 1
    alert = alerts[0]
    assert set(alert.event_ids) == {e.event_id for e in events[:5]}
    assert alert.group_key == (("user.name", "jonas"),)
    assert alert.explanation["observed"] == 5
    assert alert.thresholds == {"count": 3, "op": "gte", "timespan_seconds": 600}


def test_event_count_long_burst_single_alert_and_gap_splits() -> None:
    # 30 failures, one every 5 minutes: never 3 within 10 minutes? 3 within 10min: t, t+5, t+10 -> yes (<= 600)
    sparse = fails("u", 0, 4, step=400)  # 400 s apart: max 2 in any 600 s window
    assert evaluate_count(count_rule(), [bm(e) for e in sparse]) == []
    two_bursts = fails("u", 0, 3) + fails("u", 5000, 3)
    alerts = evaluate_count(count_rule(), [bm(e) for e in two_bursts])
    assert len(alerts) == 2
    assert alerts[0].alert_id != alerts[1].alert_id


def test_duplicates_never_count_twice() -> None:
    events = fails("u", 0, 2)
    matches = [bm(e) for e in events] + [bm(events[0]), bm(events[1])]
    assert evaluate_count(count_rule(), matches) == []


def test_gt_and_eq_and_unsupported_op() -> None:
    events = [bm(e) for e in fails("u", 0, 3)]
    assert evaluate_count(count_rule(op="gt"), events) == []
    assert len(evaluate_count(count_rule(op="eq"), events)) == 1
    with pytest.raises(ValueError, match="unsupported"):
        evaluate_count(count_rule(op="lt"), events)
    with pytest.raises(ValueError, match="unsupported"):
        evaluate_count(count_rule(count=None), events)


def test_value_count_distinct_users_sliding_window() -> None:
    rule = count_rule(type="value_count", group_by=("source.ip",), value_field="user.name", count=3)
    spray = [make_event(i * 100, user__name=f"user{i % 4}", source__ip="203.0.113.66") for i in range(8)]
    alerts = evaluate_count(rule, [bm(e) for e in spray])
    assert len(alerts) == 1
    assert alerts[0].explanation["observed"] == 4
    assert "distinct user.name" in alerts[0].explanation["condition"]
    assert alerts[0].thresholds["field"] == "user.name"
    # window slides: users leave the window again
    slow = [make_event(i * 400, user__name=f"user{i}", source__ip="203.0.113.66") for i in range(5)]
    assert evaluate_count(rule, [bm(e) for e in slow]) == []


def test_value_count_ignores_missing_values() -> None:
    rule = count_rule(type="value_count", group_by=("source.ip",), value_field="user.name", count=2)
    events = [make_event(i, source__ip="203.0.113.1") for i in range(5)] + [
        make_event(10, source__ip="203.0.113.1", user__name="a")
    ]
    assert evaluate_count(rule, [bm(e) for e in events]) == []
    # missing values leave the sliding window without being counted
    more = [make_event(i * 300, source__ip="203.0.113.1", user__name=None if i % 2 else f"u{i}") for i in range(6)]
    assert evaluate_count(replace(rule, count=3), [bm(e) for e in more]) == []


def test_alert_id_stable_and_order_independent() -> None:
    events = fails("u", 0, 5)
    a = evaluate_count(count_rule(), [bm(e) for e in events])
    b = evaluate_count(count_rule(), [bm(e) for e in reversed(events)])
    assert a == b


def temporal_rule(type_: str = "temporal_ordered") -> CorrelationRule:
    return count_rule(
        type=type_, rules=("created", "deleted"), group_by=("user.target.name",), timespan_seconds=3600, count=2
    )


def test_temporal_ordered() -> None:
    created = make_event(0, user__target__name="tmp", event__action="user-created")
    deleted = make_event(600, user__target__name="TMP", event__action="user-deleted")
    alerts = evaluate_temporal(
        temporal_rule(), {"created": [bm(created, "created")], "deleted": [bm(deleted, "deleted")]}
    )
    assert len(alerts) == 1
    assert [c["rule"] for c in alerts[0].explanation["chain"]] == ["created", "deleted"]
    wrong_order = evaluate_temporal(
        temporal_rule(), {"created": [bm(deleted, "created")], "deleted": [bm(created, "deleted")]}
    )
    assert wrong_order == []


def test_temporal_ordered_expired_and_missing_group() -> None:
    created = make_event(0, user__target__name="tmp")
    deleted = make_event(7200, user__target__name="tmp")
    no_key = make_event(10)
    alerts = evaluate_temporal(
        temporal_rule(),
        {"created": [bm(created, "created"), bm(no_key, "created")], "deleted": [bm(deleted, "deleted")]},
    )
    assert alerts == []


def test_temporal_unordered_and_reset() -> None:
    a = make_event(0, user__target__name="x")
    b = make_event(-30, user__target__name="x")
    c = make_event(100, user__target__name="x")
    alerts = evaluate_temporal(
        temporal_rule("temporal"), {"created": [bm(a, "created"), bm(c, "created")], "deleted": [bm(b, "deleted")]}
    )
    assert len(alerts) == 1  # state is reset after an alert; c alone does not re-trigger


def first_alert(events: list[CanonicalEvent], rule_id: str = "SO-AUTH-001") -> Alert:
    alerts = evaluate_count(replace(count_rule(), meta=meta(rule_id)), [bm(e) for e in events])
    assert len(alerts) == 1
    return alerts[0]


def seq_rule(same: tuple[str, ...] = ("source.ip",)) -> SequenceRule:
    return SequenceRule(
        meta(kind="sequence", rule_id="SO-AUTH-003"), ("so_auth_001",), "success", ("user.name",), 1800, same
    )


def test_sequence_success_from_attacking_ip() -> None:
    failures = fails("jonas", 0, 5)
    first = first_alert(failures)
    success = make_event(200, user__name="jonas", source__ip="203.0.113.5", event__action="logon")
    events = {e.event_id: e for e in [*failures, success]}
    alerts = evaluate_sequence(seq_rule(), [first], [bm(success, "success")], events)
    assert len(alerts) == 1
    assert alerts[0].related_alert_ids == (first.alert_id,)
    assert alerts[0].explanation["preceding_alert"]["failures_for_group"] == 5
    assert "with same source.ip" in alerts[0].explanation["condition"]
    # only the first success per preceding alert and group
    again = make_event(300, user__name="jonas", source__ip="203.0.113.5")
    assert (
        len(
            evaluate_sequence(
                seq_rule(), [first], [bm(success, "success"), bm(again, "success")], events | {again.event_id: again}
            )
        )
        == 1
    )


def test_sequence_rejects_other_ip_late_success_and_missing_fields() -> None:
    failures = fails("jonas", 0, 5)
    first = first_alert(failures)
    events = {e.event_id: e for e in failures}
    own_pc = make_event(200, user__name="jonas", source__ip="127.0.0.1")
    late = make_event(5000, user__name="jonas", source__ip="203.0.113.5")
    no_ip = make_event(200, user__name="jonas")
    no_user = make_event(200, source__ip="203.0.113.5")
    other_user = make_event(200, user__name="anna", source__ip="203.0.113.5")
    for success in (own_pc, late, no_ip, no_user, other_user):
        assert evaluate_sequence(seq_rule(), [first], [bm(success, "success")], events) == []
    # without the "same" constraint the own-PC logon would count
    assert len(evaluate_sequence(seq_rule(()), [first], [bm(own_pc, "success")], events)) == 1


def test_sequence_with_spray_covers_each_user() -> None:
    spray = [make_event(i * 10, user__name=f"u{i}", source__ip="203.0.113.66") for i in range(4)]
    rule = count_rule(type="value_count", group_by=("source.ip",), value_field="user.name", count=3)
    first = evaluate_count(replace(rule, meta=meta("SO-AUTH-002")), [bm(e) for e in spray])[0]
    success = make_event(100, user__name="u2", source__ip="203.0.113.66")
    events = {e.event_id: e for e in spray}
    alerts = evaluate_sequence(seq_rule(), [first], [bm(success, "success")], events)
    assert len(alerts) == 1
    assert set(alerts[0].event_ids) == {spray[2].event_id, success.event_id}
    keyless = make_event(1, source__ip="203.0.113.66")
    events[keyless.event_id] = keyless
    first_with_keyless = replace(first, event_ids=(*first.event_ids, keyless.event_id))
    assert len(evaluate_sequence(seq_rule(), [first_with_keyless], [bm(success, "success")], events)) == 1
