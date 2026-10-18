from __future__ import annotations

from typing import Any

import pytest
from sigma.collection import SigmaCollection

from sentinelops.detection.matcher import (
    CompiledDetection,
    UnsupportedSigmaFeatureError,
    compile_rule_detection,
    compile_value,
)
from tests.conftest import make_event


def compile_yaml(detection: str, extra: str = "") -> CompiledDetection:
    text = f"""
title: test
id: 11111111-1111-4111-8111-111111111111
status: test
logsource: {{product: sentinelops}}
detection:
{detection}
level: low
{extra}
"""
    rule = SigmaCollection.from_yaml(text).rules[0]
    conditions = [c.parse(postprocess=False) for c in rule.detection.parsed_condition]
    return compile_rule_detection(rule.detection.detections, conditions)


def matches(compiled: CompiledDetection, **fields: Any) -> bool:
    return compiled.match(make_event(**fields).get) is not None


def test_plain_string_case_insensitive_and_gate() -> None:
    rule = compile_yaml("  sel:\n    event.action: logon-failed\n  condition: sel")
    assert matches(rule, event__action="LOGON-FAILED")
    assert not matches(rule, event__action="logon")
    assert not matches(rule)
    assert rule.gate == ("event.action", frozenset({"logon-failed"}))


def test_wildcards_and_modifiers() -> None:
    rule = compile_yaml(
        "  sel:\n    process.command_line|contains: 'useradd'\n    user.name|startswith: 'adm-'\n"
        "    host.name|endswith: '01'\n  condition: sel"
    )
    assert matches(rule, process__command_line="/usr/sbin/USERADD -o", user__name="adm-weber", host__name="srv-lnx01")
    assert not matches(rule, process__command_line="/usr/sbin/useradd", user__name="max", host__name="srv-lnx01")
    assert rule.gate is None


def test_single_char_wildcard_and_cased() -> None:
    rule = compile_yaml(
        "  sel:\n    user.name: 'ad?in'\n  cased:\n    host.name|cased: 'DC01'\n  condition: sel and cased"
    )
    assert matches(rule, user__name="ADMIN", host__name="DC01")
    assert not matches(rule, user__name="admin", host__name="dc01")
    assert not matches(rule, user__name="adddmin", host__name="DC01")


def test_cased_wildcard() -> None:
    rule = compile_yaml("  sel:\n    host.name|cased|startswith: 'DC'\n  condition: sel")
    assert matches(rule, host__name="DC01")
    assert not matches(rule, host__name="dc01")


def test_list_values_or_and_all_modifier() -> None:
    any_rule = compile_yaml("  sel:\n    event.action:\n      - a\n      - b\n  condition: sel")
    assert matches(any_rule, event__action="b")
    all_rule = compile_yaml("  sel:\n    message|contains|all:\n      - foo\n      - bar\n  condition: sel")
    assert matches(all_rule, message="xx foo yy bar")
    assert not matches(all_rule, message="xx foo")


def test_list_valued_event_fields() -> None:
    rule = compile_yaml("  sel:\n    event.category: iam\n  condition: sel")
    assert matches(rule, event__category=["authentication", "iam"])
    assert not matches(rule, event__category=["authentication"])


def test_numbers() -> None:
    rule = compile_yaml("  sel:\n    event.code: 4625\n  condition: sel")
    assert rule.gate == ("event.code", frozenset({"4625"}))
    assert matches(rule, event__code="4625")
    assert matches(rule, event__code=4625)
    assert matches(rule, event__code=4625.0)
    assert not matches(rule, event__code="4624")
    assert not matches(rule, event__code="x")
    assert not matches(rule, event__code=True)
    assert not matches(rule, event__code=4624)
    float_rule = compile_yaml("  sel:\n    score: 1.5\n  condition: sel")
    assert float_rule.gate is None
    assert matches(float_rule, score="1.5")


def test_numeric_gate_with_float() -> None:
    rule = compile_yaml("  sel:\n    event.code: 1.5\n  condition: sel")
    assert rule.gate == ("event.code", frozenset({"1.5"}))


def test_null_bool_exists() -> None:
    rule = compile_yaml("  sel:\n    a: null\n    b: true\n    c|exists: true\n    d|exists: false\n  condition: sel")
    assert matches(rule, b=True, c="x")
    assert matches(rule, a="", b="TRUE", c=1)
    assert not matches(rule, a="x", b=True, c="x")
    assert not matches(rule, b=False, c="x")
    assert not matches(rule, b=True, c="x", d="y")
    assert not matches(rule, b=True)


def test_regex_cidr_compare() -> None:
    rule = compile_yaml(
        "  sel:\n    user.name|re|i: '^ADM-[a-z]+$'\n    source.ip|cidr: 203.0.113.0/24\n"
        "    source.port|gte: 1024\n  condition: sel"
    )
    assert matches(rule, user__name="adm-weber", source__ip="203.0.113.5", source__port=50000)
    assert not matches(rule, user__name="adm-weber", source__ip="10.0.0.1", source__port=50000)
    assert not matches(rule, user__name="adm-weber", source__ip="not-ip", source__port=50000)
    assert not matches(rule, user__name="adm-weber", source__ip="2001:db8::1", source__port=50000)
    assert not matches(rule, user__name="adm-weber", source__ip="203.0.113.5", source__port=80)
    assert not matches(rule, user__name="adm-weber", source__ip="203.0.113.5", source__port="x")
    assert not matches(rule, user__name="adm-weber", source__ip="203.0.113.5")
    assert not matches(rule, user__name="xadm-weber", source__ip="203.0.113.5", source__port=50000)


@pytest.mark.parametrize(
    ("modifier", "value", "ok", "nok"),
    [
        ("lt", 5, 4, 5),
        ("lte", 5, 5, 6),
        ("gt", 5, 6, 5),
        ("neq", 5, 4, 5),
    ],
)
def test_compare_operators(modifier: str, value: int, ok: int, nok: int) -> None:
    rule = compile_yaml(f"  sel:\n    n|{modifier}: {value}\n  condition: sel")
    assert matches(rule, n=ok)
    assert not matches(rule, n=nok)
    assert not matches(rule)


def test_regex_flags_multiline_dotall() -> None:
    rule = compile_yaml("  sel:\n    message|re|m|s: '^b.c$'\n  condition: sel")
    assert matches(rule, message="a\nb\nc")
    assert not matches(rule)


def test_fieldref() -> None:
    rule = compile_yaml("  sel:\n    user.name|fieldref: user.target.name\n  condition: sel")
    assert matches(rule, user__name="Erika", user__target__name="erika")
    assert not matches(rule, user__name="max", user__target__name="erika")
    assert not matches(rule, user__name="max")
    starts = compile_yaml("  sel:\n    user.name|fieldref|startswith: user.target.name\n  condition: sel")
    assert matches(starts, user__name="erika.admin", user__target__name="erika")
    assert not matches(starts, user__name="max", user__target__name="erika")
    ends = compile_yaml("  sel:\n    user.name|fieldref|endswith: user.target.name\n  condition: sel")
    assert matches(ends, user__name="adm-erika", user__target__name="erika")


def test_keywords_search_message() -> None:
    rule = compile_yaml("  kw:\n    - 'new user'\n    - 'UID=0,'\n  condition: kw")
    assert matches(rule, message="useradd: NEW USER: name=x")
    assert not matches(rule, message="nothing")
    assert not matches(rule)
    wild = compile_yaml("  kw:\n    - 'GID=*,'\n  condition: kw")
    assert matches(wild, message="new user: name=x, GID=27, home")


def test_windash_expansion() -> None:
    rule = compile_yaml("  sel:\n    process.command_line|windash|contains: '-enc'\n  condition: sel")
    assert matches(rule, process__command_line="powershell /enc AAAA")
    assert not matches(rule, process__command_line="powershell")


def test_conditions_selectors_and_explanation() -> None:
    rule = compile_yaml(
        "  selection_a:\n    event.action: logon\n  selection_b:\n    user.name: x\n"
        "  filter_1:\n    host.name: h1\n  filter_2:\n    host.name: h2\n"
        "  condition: all of selection_* and not 1 of filter_*"
    )
    explanation = rule.match(make_event(event__action="logon", user__name="x", host__name="h3").get)
    assert explanation is not None
    data = explanation.to_dict()
    assert [m["detection"] for m in data["matched"]] == ["selection_a", "selection_b"]
    assert data["matched"][0]["actual"] == "logon"
    assert data["not_matched_filters"] == ["filter_1", "filter_2"]
    assert not matches(rule, event__action="logon", user__name="x", host__name="h1")
    assert not matches(rule, event__action="logon", host__name="h3")


def test_them_and_or_and_multiple_conditions() -> None:
    rule = compile_yaml("  a:\n    x: 1\n  _hidden:\n    y: 2\n  condition: 1 of them")
    assert matches(rule, x=1)
    assert not matches(rule, y=2)
    any_rule = compile_yaml("  a:\n    x: 1\n  b:\n    y: 2\n  condition: any of them")
    assert matches(any_rule, y=2)
    or_rule = compile_yaml("  a:\n    x: 1\n  b:\n    y: 2\n  condition: a or b")
    assert matches(or_rule, y=2)
    assert not matches(or_rule, x=3)
    multi = compile_yaml("  a:\n    x: 1\n  b:\n    y: 2\n  condition:\n    - a\n    - b")
    assert matches(multi, y=2)


def test_or_linked_detection_list_of_maps() -> None:
    rule = compile_yaml("  sel:\n    - user.name: a\n    - host.name: b\n  condition: sel")
    assert matches(rule, host__name="b")
    assert not matches(rule, host__name="c")


def test_rendered_actual_for_lists() -> None:
    rule = compile_yaml("  sel:\n    event.category: iam\n  condition: sel")
    explanation = rule.match(make_event(event__category=["authentication", "iam"]).get)
    assert explanation is not None
    assert explanation.matched[0].actual == "authentication, iam"


def test_unresolved_placeholder_is_rejected() -> None:
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_yaml("  sel:\n    group.name|expand: '%privileged_groups%'\n  condition: sel")


def test_unsupported_value_types() -> None:
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_value(object())
    from sigma.types import SigmaNumber

    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_value(SigmaNumber(5), keyword=True)


def test_invalid_regex_rejected_by_pysigma() -> None:
    from sigma.exceptions import SigmaError

    with pytest.raises(SigmaError):
        compile_yaml("  sel:\n    a|re: '(unclosed'\n  condition: sel")


def test_selector_without_match_rejected() -> None:
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_yaml("  sel:\n    a: 1\n  condition: 1 of nothing_*")


def test_negated_item_and_neq_gate_skipped() -> None:
    from sigma.rule import SigmaDetection, SigmaDetectionItem
    from sigma.types import SigmaString

    item = SigmaDetectionItem("event.action", [], [SigmaString("logon")])
    item.negated = True
    detection = SigmaDetection([item])
    compiled = compile_rule_detection(
        {"sel": detection}, [__import__("sigma.conditions").conditions.ConditionIdentifier(["sel"])]
    )
    assert compiled.gate is None
    assert compiled.match(make_event(event__action="logoff").get) is not None
    assert compiled.match(make_event(event__action="logon").get) is None
