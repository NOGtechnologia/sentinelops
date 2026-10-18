from __future__ import annotations

import re

import pytest
from sigma import conditions as sc
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaRegularExpression, SigmaString

from sentinelops.detection import matcher
from sentinelops.detection.matcher import (
    UnsupportedSigmaFeatureError,
    compile_condition,
    compile_detection,
    compile_rule_detection,
    compile_value,
)
from tests.conftest import make_event
from tests.unit.test_matcher import compile_yaml, matches


def test_cidr_skips_none_items() -> None:
    rule = compile_yaml("  sel:\n    source.ip|cidr: 10.0.0.0/8\n  condition: sel")
    assert matches(rule, source__ip=[None, "10.1.2.3"])


def test_python_regex_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    value = SigmaRegularExpression("^a$")

    def boom(*_: object, **__: object) -> re.Pattern[str]:
        raise re.error("boom")

    monkeypatch.setattr(matcher.re, "compile", boom)
    try:
        compile_value(value)
    except UnsupportedSigmaFeatureError as exc:
        error = str(exc)
    else:  # pragma: no cover - the assertion below reports it
        error = ""
    monkeypatch.undo()
    assert "invalid regular expression" in error


def test_detection_item_without_values() -> None:
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_detection("sel", SigmaDetection([SigmaDetectionItem("a", [], [])]))


def test_detection_cache_reused() -> None:
    rule = compile_yaml("  a:\n    x: 1\n  b:\n    y: 2\n  condition: (a and b) or a")
    assert matches(rule, x=1)


def test_double_negation_names() -> None:
    rule = compile_yaml("  a:\n    x: 1\n  condition: not (not a)")
    assert matches(rule, x=1)
    assert not matches(rule, x=2)


def test_invalid_condition_trees() -> None:
    detections = {"a": compile_detection("a", SigmaDetection([SigmaDetectionItem("x", [], [SigmaString("1")])]))}
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_condition(sc.ConditionIdentifier(["missing"]), detections)
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_condition(object(), detections)
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_rule_detection({}, [])


def test_gate_not_derived_from_wildcards() -> None:
    rule = compile_yaml("  sel:\n    event.action:\n      - logon\n      - 'log*'\n  condition: sel")
    assert rule.gate is None
    assert matches(rule, event__action="logoff")


def test_explanation_without_actual_value() -> None:
    rule = compile_yaml("  sel:\n    a|exists: false\n  condition: sel")
    explanation = rule.match(make_event().get)
    assert explanation is not None
    assert explanation.matched[0].actual == ""
