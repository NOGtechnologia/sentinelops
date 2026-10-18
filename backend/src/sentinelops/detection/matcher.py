"""Deterministic Sigma matcher on canonical events (ADR-0003).

pySigma parses and validates the rules and applies the processing pipeline;
this module compiles the resulting detection objects into small predicate
trees and evaluates them per event. Every positive result carries an
explanation: which detection items matched with which field values, and
which filters did *not* match.

Semantics (documented in docs/detection-catalog.md):

* String comparison is case-insensitive unless the ``cased`` modifier is used;
  ``*`` and ``?`` are wildcards; without wildcards the whole value must match.
* Keyword detections (no field) search the ``message`` field (substring).
* List-valued fields (e.g. ``event.category``) match if any element matches.
* Unsupported value types or condition elements raise
  :class:`UnsupportedSigmaFeatureError` at load time - never silently ignored.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Protocol

from sigma import conditions as sc
from sigma import types as st
from sigma.rule import SigmaDetection, SigmaDetectionItem

EventGetter = Callable[[str], Any]


class UnsupportedSigmaFeatureError(ValueError):
    """A rule uses a Sigma feature the matcher cannot evaluate faithfully."""


@dataclass(frozen=True, slots=True)
class ItemHit:
    detection: str
    field: str | None
    expected: str
    actual: str


@dataclass(frozen=True, slots=True)
class Explanation:
    matched: tuple[ItemHit, ...]
    not_matched_filters: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": [
                {"detection": h.detection, "field": h.field, "expected": h.expected, "actual": h.actual}
                for h in self.matched
            ],
            "not_matched_filters": list(self.not_matched_filters),
        }


# --- value matchers ----------------------------------------------------------


class ValueMatcher(Protocol):
    description: str

    def __call__(self, actual: Any, get: EventGetter) -> bool: ...


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _iter_values(value: Any) -> Iterable[Any]:
    if isinstance(value, (list, tuple)):
        return value
    return (value,)


def sigma_string_regex(value: st.SigmaString, cased: bool, anchored: bool = True) -> re.Pattern[str]:
    parts: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part == st.SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == st.SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise UnsupportedSigmaFeatureError(f"unresolved placeholder in value {value}")
    pattern = "".join(parts)
    if anchored:
        pattern = f"^(?:{pattern})$"
    flags = re.DOTALL if cased else re.DOTALL | re.IGNORECASE
    return re.compile(pattern, flags)


@dataclass(slots=True)
class StringMatcher:
    value: st.SigmaString
    cased: bool
    keyword: bool = False
    description: str = ""
    _plain: str | None = None
    _regex: re.Pattern[str] | None = None

    def __post_init__(self) -> None:
        self.description = str(self.value)
        if self.value.contains_special() or self.keyword:
            self._regex = sigma_string_regex(self.value, self.cased, anchored=not self.keyword)
        else:
            plain = self.value.to_plain()
            self._plain = plain if self.cased else plain.casefold()

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        if actual is None:
            return False
        for item in _iter_values(actual):
            text = _as_text(item)
            if self._plain is not None:
                if (text if self.cased else text.casefold()) == self._plain:
                    return True
            elif self._regex is not None and (self._regex.search(text) if self.keyword else self._regex.match(text)):
                return True
        return False


@dataclass(slots=True)
class NumberMatcher:
    number: int | float
    description: str = ""

    def __post_init__(self) -> None:
        self.description = str(self.number)

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        for item in _iter_values(actual):
            if isinstance(item, bool) or item is None:
                continue
            if isinstance(item, (int, float)):
                if item == self.number:
                    return True
                continue
            text = str(item).strip()
            try:
                if float(text) == self.number:
                    return True
            except ValueError:
                continue
        return False


@dataclass(slots=True)
class NullMatcher:
    description: str = "null"

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        return actual is None or actual in ("", [])


@dataclass(slots=True)
class BoolMatcher:
    value: bool
    description: str = ""

    def __post_init__(self) -> None:
        self.description = _as_text(self.value)

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        return any(
            (item is self.value) or (isinstance(item, str) and item.strip().lower() == _as_text(self.value))
            for item in _iter_values(actual)
        )


@dataclass(slots=True)
class RegexMatcher:
    pattern: re.Pattern[str]
    description: str = ""

    def __post_init__(self) -> None:
        self.description = f"/{self.pattern.pattern}/"

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        if actual is None:
            return False
        return any(self.pattern.search(_as_text(item)) for item in _iter_values(actual))


@dataclass(slots=True)
class CidrMatcher:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    description: str = ""

    def __post_init__(self) -> None:
        self.description = str(self.network)

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        for item in _iter_values(actual):
            if item is None:
                continue
            try:
                address = ipaddress.ip_address(str(item))
            except ValueError:
                continue
            if address.version == self.network.version and address in self.network:
                return True
        return False


_COMPARE: dict[Any, Callable[[float, float], bool]] = {
    st.SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
    st.SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
    st.SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
    st.SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
    st.SigmaCompareExpression.CompareOperators.NEQ: lambda a, b: a != b,
}


@dataclass(slots=True)
class CompareMatcher:
    op: Callable[[float, float], bool]
    number: float
    description: str

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        for item in _iter_values(actual):
            if item is None or isinstance(item, bool):
                continue
            try:
                value = float(item)
            except (TypeError, ValueError):
                continue
            if self.op(value, self.number):
                return True
        return False


@dataclass(slots=True)
class FieldRefMatcher:
    other: str
    starts_with: bool
    ends_with: bool
    description: str = ""

    def __post_init__(self) -> None:
        self.description = f"field({self.other})"

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        reference = get(self.other)
        if actual is None or reference is None:
            return False
        ref = _as_text(reference).casefold()
        for item in _iter_values(actual):
            text = _as_text(item).casefold()
            if (self.starts_with and text.startswith(ref)) or (self.ends_with and text.endswith(ref)):
                return True
            if not self.starts_with and not self.ends_with and text == ref:
                return True
        return False


@dataclass(slots=True)
class ExistsMatcher:
    exists: bool
    description: str = ""

    def __post_init__(self) -> None:
        self.description = "exists" if self.exists else "not exists"

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        present = actual is not None and actual != ""
        return present is self.exists


@dataclass(slots=True)
class AnyOfMatcher:
    matchers: tuple[ValueMatcher, ...]
    description: str = ""

    def __post_init__(self) -> None:
        self.description = " | ".join(m.description for m in self.matchers)

    def __call__(self, actual: Any, get: EventGetter) -> bool:
        return any(m(actual, get) for m in self.matchers)


def compile_value(value: Any, keyword: bool = False) -> ValueMatcher:
    if isinstance(value, st.SigmaCasedString):
        return StringMatcher(value, cased=True, keyword=keyword)
    if isinstance(value, st.SigmaString):
        return StringMatcher(value, cased=False, keyword=keyword)
    if keyword:
        raise UnsupportedSigmaFeatureError(f"keyword value of type {type(value).__name__}")
    if isinstance(value, st.SigmaNumber):
        return NumberMatcher(value.number)
    if isinstance(value, st.SigmaNull):
        return NullMatcher()
    if isinstance(value, st.SigmaBool):
        return BoolMatcher(value.boolean)
    if isinstance(value, st.SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= {
                st.SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
                st.SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
                st.SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
            }[flag]
        try:
            return RegexMatcher(re.compile(value.regexp.original, flags))
        except re.error as exc:
            raise UnsupportedSigmaFeatureError(f"invalid regular expression: {exc}") from exc
    if isinstance(value, st.SigmaCIDRExpression):
        return CidrMatcher(value.network)
    if isinstance(value, st.SigmaCompareExpression):
        op = _COMPARE[value.op]
        return CompareMatcher(op, float(value.number.number), f"{value.op.name.lower()} {value.number.number}")
    if isinstance(value, st.SigmaFieldReference):
        return FieldRefMatcher(value.field, value.starts_with, value.ends_with)
    if isinstance(value, st.SigmaExists):
        return ExistsMatcher(value.exists)
    if isinstance(value, st.SigmaExpansion):
        return AnyOfMatcher(tuple(compile_value(v) for v in value.values))
    raise UnsupportedSigmaFeatureError(f"unsupported Sigma value type {type(value).__name__}")


# --- detections --------------------------------------------------------------


@dataclass(slots=True)
class ItemMatcher:
    detection: str
    field: str | None
    matchers: tuple[ValueMatcher, ...]
    require_all: bool
    negated: bool

    def evaluate(self, get: EventGetter) -> list[ItemHit] | None:
        name = self.field or "message"
        actual = get(name)
        if self.require_all:
            ok = all(m(actual, get) for m in self.matchers)
            used = self.matchers
        else:
            used = tuple(m for m in self.matchers if m(actual, get))[:1]
            ok = bool(used)
        if self.negated:
            ok = not ok
        if not ok:
            return None
        expected = ("not " if self.negated else "") + " & ".join(m.description for m in used or self.matchers)
        rendered = "" if actual is None else _render_actual(actual)
        return [ItemHit(self.detection, self.field, expected, rendered)]


def _render_actual(actual: Any) -> str:
    if isinstance(actual, (list, tuple)):
        return ", ".join(_as_text(a) for a in actual)
    return _as_text(actual)


@dataclass(slots=True)
class DetectionMatcher:
    name: str
    children: tuple[ItemMatcher | DetectionMatcher, ...]
    require_all: bool

    def evaluate(self, get: EventGetter) -> list[ItemHit] | None:
        hits: list[ItemHit] = []
        if self.require_all:
            for child in self.children:
                result = child.evaluate(get)
                if result is None:
                    return None
                hits.extend(result)
            return hits
        for child in self.children:
            result = child.evaluate(get)
            if result is not None:
                return result
        return None


def compile_detection(name: str, detection: SigmaDetection) -> DetectionMatcher:
    children: list[ItemMatcher | DetectionMatcher] = []
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            children.append(compile_detection(name, item))
        elif isinstance(item, SigmaDetectionItem):
            keyword = item.field is None
            values = tuple(compile_value(v, keyword=keyword) for v in item.value)
            if not values:
                raise UnsupportedSigmaFeatureError(f"detection item without values in {name}")
            children.append(
                ItemMatcher(
                    detection=name,
                    field=item.field,
                    matchers=values,
                    require_all=item.value_linking is sc.ConditionAND,
                    negated=bool(getattr(item, "negated", False)),
                )
            )
        else:  # pragma: no cover - pySigma only produces the two types above
            raise UnsupportedSigmaFeatureError(f"unexpected detection element {type(item).__name__}")
    return DetectionMatcher(name, tuple(children), require_all=detection.item_linking is sc.ConditionAND)


# --- condition tree ----------------------------------------------------------


@dataclass(slots=True)
class _Result:
    ok: bool
    hits: list[ItemHit] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)


class CondNode(Protocol):
    def evaluate(self, get: EventGetter, cache: dict[str, list[ItemHit] | None]) -> _Result: ...


@dataclass(slots=True)
class Ref:
    name: str
    detection: DetectionMatcher

    def evaluate(self, get: EventGetter, cache: dict[str, list[ItemHit] | None]) -> _Result:
        if self.name not in cache:
            cache[self.name] = self.detection.evaluate(get)
        hits = cache[self.name]
        return _Result(hits is not None, list(hits or []))


@dataclass(slots=True)
class And:
    args: tuple[CondNode, ...]

    def evaluate(self, get: EventGetter, cache: dict[str, list[ItemHit] | None]) -> _Result:
        out = _Result(True)
        for arg in self.args:
            result = arg.evaluate(get, cache)
            if not result.ok:
                return _Result(False)
            out.hits.extend(result.hits)
            out.excluded.extend(result.excluded)
        return out


@dataclass(slots=True)
class Or:
    args: tuple[CondNode, ...]

    def evaluate(self, get: EventGetter, cache: dict[str, list[ItemHit] | None]) -> _Result:
        for arg in self.args:
            result = arg.evaluate(get, cache)
            if result.ok:
                return result
        return _Result(False)


@dataclass(slots=True)
class Not:
    arg: CondNode
    names: tuple[str, ...]

    def evaluate(self, get: EventGetter, cache: dict[str, list[ItemHit] | None]) -> _Result:
        result = self.arg.evaluate(get, cache)
        if result.ok:
            return _Result(False)
        return _Result(True, excluded=list(self.names))


def _names(node: CondNode) -> tuple[str, ...]:
    if isinstance(node, Ref):
        return (node.name,)
    if isinstance(node, (And, Or)):
        return tuple(n for a in node.args for n in _names(a))
    if isinstance(node, Not):
        return node.names
    return ()


def compile_condition(tree: Any, detections: dict[str, DetectionMatcher]) -> CondNode:
    if isinstance(tree, sc.ConditionIdentifier):
        name = tree.identifier
        if name not in detections:
            raise UnsupportedSigmaFeatureError(f"condition references unknown detection {name!r}")
        return Ref(name, detections[name])
    if isinstance(tree, sc.ConditionSelector):
        quantifier, pattern = str(tree.args[0]), str(tree.args[1])
        if pattern == "them":
            names = sorted(n for n in detections if not n.startswith("_"))
        else:
            names = sorted(n for n in detections if fnmatchcase(n, pattern))
        if not names:
            raise UnsupportedSigmaFeatureError(f"selector {quantifier} of {pattern} matches no detection")
        refs = tuple(Ref(n, detections[n]) for n in names)
        if quantifier == "all":
            return And(refs)
        if quantifier in ("1", "any"):
            return Or(refs)
        raise UnsupportedSigmaFeatureError(f"unsupported quantifier {quantifier!r}")
    if isinstance(tree, sc.ConditionAND):
        return And(tuple(compile_condition(a, detections) for a in tree.args))
    if isinstance(tree, sc.ConditionOR):
        return Or(tuple(compile_condition(a, detections) for a in tree.args))
    if isinstance(tree, sc.ConditionNOT):
        inner = compile_condition(tree.args[0], detections)
        return Not(inner, _names(inner))
    raise UnsupportedSigmaFeatureError(f"unsupported condition element {type(tree).__name__}")


@dataclass(slots=True)
class CompiledDetection:
    condition: CondNode
    #: (field, frozenset of casefolded values): the rule can only match events
    #: whose field has one of these values (used by the engine as an index).
    gate: tuple[str, frozenset[str]] | None

    def match(self, get: EventGetter) -> Explanation | None:
        result = self.condition.evaluate(get, {})
        if not result.ok:
            return None
        return Explanation(tuple(result.hits), tuple(dict.fromkeys(result.excluded)))


GATE_FIELDS = ("event.action", "event.code")


def _flatten_and(node: CondNode) -> list[CondNode]:
    if isinstance(node, And):
        return [n for arg in node.args for n in _flatten_and(arg)]
    return [node]


def _gate(node: CondNode) -> tuple[str, frozenset[str]] | None:
    """Find a mandatory plain equality on a gate field in the top-level AND."""
    for candidate in _flatten_and(node):
        if not isinstance(candidate, Ref) or not candidate.detection.require_all:
            continue
        for child in candidate.detection.children:
            if (
                not isinstance(child, ItemMatcher)
                or child.field not in GATE_FIELDS
                or child.negated
                or child.require_all
            ):
                continue
            values: list[str] = []
            for matcher in child.matchers:
                if isinstance(matcher, StringMatcher) and matcher._plain is not None and not matcher.cased:
                    values.append(matcher._plain)
                elif isinstance(matcher, NumberMatcher):
                    values.append(
                        str(int(matcher.number)) if float(matcher.number).is_integer() else str(matcher.number)
                    )
                else:
                    break
            else:
                return child.field, frozenset(values)
    return None


def compile_rule_detection(detections: dict[str, SigmaDetection], conditions: list[Any]) -> CompiledDetection:
    compiled = {name: compile_detection(name, det) for name, det in detections.items()}
    trees = [compile_condition(c, compiled) for c in conditions]
    if not trees:
        raise UnsupportedSigmaFeatureError("rule without condition")
    root: CondNode = trees[0] if len(trees) == 1 else Or(tuple(trees))
    return CompiledDetection(root, _gate(root))
