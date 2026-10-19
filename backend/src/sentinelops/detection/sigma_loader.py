"""Rule set loading: pySigma parsing + validation + pipeline + metadata checks.

Rule sources (``rules/``):

* ``sigma/custom/*.yml`` - SentinelOps single-event rules (``SO-*``)
* ``sigma/sigmahq/*.yml`` - curated, unmodified SigmaHQ rules (DRL 1.1), with
  SentinelOps metadata in ``sigma/sigmahq/curation.yaml``
* ``correlations/*.yml`` - Sigma correlation rules, helper base rules and the
  documented ``sequence`` extension
* ``baselines/*.yml`` - baseline detector definitions (non-Sigma)
* ``pipelines/*.yml`` - pySigma processing pipelines (field mapping)

Every alerting rule must carry complete metadata; a rule using an unsupported
Sigma feature makes loading fail with a clear message (spec 6.1).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationCondition, SigmaCorrelationRule, SigmaCorrelationType
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.matcher import CompiledDetection, UnsupportedSigmaFeatureError, compile_rule_detection

LEVELS = ("informational", "low", "medium", "high", "critical")
MATURITIES = ("stable", "test", "experimental")
RULE_ID_RE = re.compile(r"^(SO-[A-Z]+-\d{3}|SIGMAHQ-[0-9A-F]{8})$")
TACTICS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "stealth": "TA0005",
    "defense-impairment": "TA0112",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}
TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$")
#: pySigma validators that conflict with documented SentinelOps conventions.
VALIDATOR_EXCLUSIONS = {
    # Helper rules have no tags by design (they never raise alerts).
    "attacktag",
    "notags",
    # Custom rules have a `sentinelops` block; pySigma flags unknown attributes.
    "custom_attributes",
}


class RuleLoadError(ValueError):
    pass


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    version: int
    name: str | None
    uuid: str
    title: str
    title_de: str
    description: str
    description_de: str
    level: str
    maturity: str
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    falsepositives: tuple[str, ...]
    playbooks: tuple[str, ...]
    author: str
    source: str  # custom | sigmahq
    kind: str  # single | correlation | sequence | baseline
    file: str
    yaml_text: str
    content_hash: str
    privilege_change: bool = False
    success_after_failures: bool = False
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "uuid": self.uuid,
            "title": self.title,
            "title_de": self.title_de,
            "description": self.description,
            "description_de": self.description_de,
            "level": self.level,
            "maturity": self.maturity,
            "tactics": list(self.tactics),
            "techniques": list(self.techniques),
            "falsepositives": list(self.falsepositives),
            "playbooks": list(self.playbooks),
            "author": self.author,
            "source": self.source,
            "kind": self.kind,
            "file": self.file,
            "content_hash": self.content_hash,
        }


@dataclass
class BaseRule:
    """A Sigma detection rule (alerting or helper)."""

    name: str
    uuid: str
    detection: CompiledDetection
    meta: RuleMeta | None


@dataclass
class CorrelationRule:
    meta: RuleMeta
    type: str  # event_count | value_count | temporal | temporal_ordered
    rules: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan_seconds: int
    op: str | None
    count: int | None
    value_field: str | None


@dataclass
class SequenceRule:
    meta: RuleMeta
    first_any: tuple[str, ...]
    then: str
    group_by: tuple[str, ...]
    timespan_seconds: int
    #: Fields whose value in the ``then`` event must equal the value in at
    #: least one event of the preceding alert (for the same group).
    same: tuple[str, ...] = ()


@dataclass
class BaselineRule:
    meta: RuleMeta


@dataclass
class RuleSet:
    base_rules: dict[str, BaseRule]
    correlations: list[CorrelationRule]
    sequences: list[SequenceRule]
    baselines: list[BaselineRule]
    pipeline_hash: str
    ruleset_hash: str
    metas: dict[str, RuleMeta] = field(default_factory=dict)

    def alerting_rule_ids(self) -> list[str]:
        return sorted(self.metas)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _timespan_seconds(spec: str) -> int:
    match = re.fullmatch(r"(\d+)([smhd])", spec.strip())
    if match is None:
        raise RuleLoadError(f"invalid timespan {spec!r}")
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def _split_documents(path: Path) -> list[tuple[dict[str, Any], str]]:
    text = path.read_text(encoding="utf-8")
    parts = re.split(r"(?m)^---\s*$", text)
    docs: list[tuple[dict[str, Any], str]] = []
    for part in parts:
        data = yaml.safe_load(part)
        if data is None:
            continue
        if not isinstance(data, dict):
            raise RuleLoadError(f"{path.name}: YAML document is not a mapping")
        docs.append((data, part.strip() + "\n"))
    return docs


def _tags(doc: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in doc.get("tags") or []:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        value = tag.removeprefix("attack.")
        if value in TACTICS:
            tactics.append(value)
        elif TECHNIQUE_RE.match(value):
            techniques.append(value.upper())
    return tuple(tactics), tuple(techniques)


def _meta(
    doc: dict[str, Any],
    extra: dict[str, Any],
    *,
    source: str,
    kind: str,
    file: str,
    yaml_text: str,
    playbook_ids: frozenset[str],
) -> RuleMeta:
    tactics, techniques = _tags(doc)
    rule_id = str(extra.get("rule_id", ""))
    problems: list[str] = []
    if not RULE_ID_RE.match(rule_id):
        problems.append(f"invalid rule_id {rule_id!r}")
    version = extra.get("version")
    if not isinstance(version, int) or version < 1:
        problems.append("version must be a positive integer")
    level = doc.get("level")
    if level not in LEVELS:
        problems.append(f"level must be one of {LEVELS}")
    maturity = doc.get("status")
    if maturity not in MATURITIES:
        problems.append(f"status (maturity) must be one of {MATURITIES}")
    if not tactics:
        problems.append("at least one ATT&CK tactic tag (attack.<tactic>) is required")
    if not techniques:
        problems.append("at least one ATT&CK technique tag (attack.tNNNN) is required")
    playbooks = tuple(extra.get("playbooks") or ())
    if not playbooks:
        problems.append("playbook reference (sentinelops.playbooks) is required")
    unknown = sorted(set(playbooks) - playbook_ids)
    if unknown:
        problems.append(f"unknown playbook steps: {', '.join(unknown)}")
    problems.extend(f"sentinelops.{key} is required" for key in ("title_de", "description_de") if not extra.get(key))
    if problems or not isinstance(version, int):
        raise RuleLoadError(f"{file}: {rule_id or doc.get('title')}: " + "; ".join(problems))
    return RuleMeta(
        rule_id=rule_id,
        version=version,
        name=doc.get("name"),
        uuid=str(doc.get("id")),
        title=str(doc.get("title")),
        title_de=str(extra["title_de"]),
        description=str(doc.get("description", "")),
        description_de=str(extra["description_de"]),
        level=str(level),
        maturity=str(maturity),
        tactics=tactics,
        techniques=techniques,
        falsepositives=tuple(str(f) for f in doc.get("falsepositives") or ()),
        playbooks=playbooks,
        author=str(doc.get("author", "")),
        source=source,
        kind=kind,
        file=file,
        yaml_text=yaml_text,
        content_hash=_sha(yaml_text),
        privilege_change=bool(extra.get("privilege_change", False)),
        success_after_failures=bool(extra.get("success_after_failures", False)),
        references=tuple(str(r) for r in doc.get("references") or ()),
    )


def load_pipeline(rules_dir: Path, config: DetectionConfig) -> tuple[ProcessingPipeline, str]:
    paths = sorted((rules_dir / "pipelines").glob("*.yml"))
    if not paths:
        raise RuleLoadError("no processing pipeline found in rules/pipelines")
    digest = hashlib.sha256()
    parts: list[ProcessingPipeline] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        digest.update(text.encode("utf-8"))
        data = yaml.safe_load(text)
        data["vars"] = config.placeholder_vars()
        parts.append(ProcessingPipeline.from_dict(data))
    pipeline = parts[0]
    for part in parts[1:]:
        pipeline = pipeline + part
    return pipeline, digest.hexdigest()


def validate_sigma(collection: SigmaCollection) -> list[str]:
    """pySigma validation (equivalent of ``sigma check``); returns issue texts."""
    validators = [v for name, v in sorted(core_validators.items()) if name not in VALIDATOR_EXCLUSIONS]
    validator = SigmaValidator(validators)
    detection_rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    issues = validator.validate_rules(iter(detection_rules))
    return sorted(
        {
            f"{type(i).__name__}: {', '.join(getattr(r, 'title', '?') for r in i.rules)} - {i.description}"
            for i in issues
        }
    )


def _iter_rule_files(rules_dir: Path) -> Iterable[tuple[Path, str]]:
    for sub, source in (("sigma/custom", "custom"), ("sigma/sigmahq", "sigmahq"), ("correlations", "custom")):
        for path in sorted((rules_dir / sub).glob("*.yml")):
            yield path, source


def load_ruleset(
    rules_dir: Path, config: DetectionConfig, playbook_ids: frozenset[str], *, strict_validation: bool = True
) -> RuleSet:
    pipeline, pipeline_hash = load_pipeline(rules_dir, config)
    curation_path = rules_dir / "sigma" / "sigmahq" / "curation.yaml"
    curation: dict[str, dict[str, Any]] = (
        yaml.safe_load(curation_path.read_text(encoding="utf-8")) if curation_path.exists() else {}
    )

    sigma_docs: list[tuple[dict[str, Any], str, Path, str]] = []
    extension_docs: list[tuple[dict[str, Any], str, Path]] = []
    hasher = hashlib.sha256(pipeline_hash.encode())
    for path, source in _iter_rule_files(rules_dir):
        for doc, text in _split_documents(path):
            hasher.update(text.encode("utf-8"))
            if "sentinelops_extension" in doc:
                extension_docs.append((doc, text, path))
            else:
                sigma_docs.append((doc, text, path, source))
    for path in sorted((rules_dir / "baselines").glob("*.yml")):
        for doc, text in _split_documents(path):
            hasher.update(text.encode("utf-8"))
            extension_docs.append((doc, text, path))
    hasher.update(config.config_hash().encode())

    try:
        collection = SigmaCollection.from_dicts([d for d, _, _, _ in sigma_docs], collect_errors=True)
    except SigmaError as exc:
        raise RuleLoadError(f"Sigma parse error: {exc}") from exc
    errors = [e for r in collection.rules for e in r.errors]
    if errors:
        raise RuleLoadError("Sigma errors: " + "; ".join(str(e) for e in errors))
    try:
        collection.resolve_rule_references()
    except SigmaError as exc:
        raise RuleLoadError(f"unresolved rule reference: {exc}") from exc
    if strict_validation:
        try:
            issues = validate_sigma(collection)
        except SigmaError as exc:
            raise RuleLoadError(f"Sigma validation failed: {exc}") from exc
        if issues:
            raise RuleLoadError("Sigma validation issues: " + " | ".join(issues))

    by_uuid = {str(d.get("id")): (d, t, p, s) for d, t, p, s in sigma_docs}
    if len(by_uuid) != len(sigma_docs):
        raise RuleLoadError("duplicate Sigma rule id")
    base_rules: dict[str, BaseRule] = {}
    correlations: list[CorrelationRule] = []
    metas: dict[str, RuleMeta] = {}
    for rule in sorted(collection.rules, key=lambda r: str(r.id)):
        doc, text, path, source = by_uuid[str(rule.id)]
        rel = path.relative_to(rules_dir).as_posix()
        if source == "sigmahq":
            extra = curation.get(str(rule.id))
            if extra is None:
                raise RuleLoadError(f"{rel}: SigmaHQ rule {rule.id} missing in curation.yaml")
        else:
            extra = doc.get("sentinelops")
        if isinstance(rule, SigmaCorrelationRule):
            if extra is None:
                raise RuleLoadError(f"{rel}: correlation rule without sentinelops metadata")
            meta = _meta(
                doc, extra, source=source, kind="correlation", file=rel, yaml_text=text, playbook_ids=playbook_ids
            )
            correlations.append(_correlation(rule, meta, config))
            metas[meta.rule_id] = meta
            continue
        if not isinstance(rule, SigmaRule):  # pragma: no cover - pySigma only has these two rule types
            raise RuleLoadError(f"{rel}: unsupported rule type {type(rule).__name__}")
        if getattr(rule, "filters", None):
            raise RuleLoadError(f"{rel}: Sigma meta filters are not supported")
        try:
            pipeline.apply(rule)
            conditions = [c.parse(postprocess=False) for c in rule.detection.parsed_condition]
            compiled = compile_rule_detection(rule.detection.detections, conditions)
        except (UnsupportedSigmaFeatureError, SigmaError) as exc:
            raise RuleLoadError(f"{rel}: {rule.title}: {exc}") from exc
        single: RuleMeta | None = None
        if extra is not None:
            single = _meta(
                doc, extra, source=source, kind="single", file=rel, yaml_text=text, playbook_ids=playbook_ids
            )
            metas[single.rule_id] = single
        key = str(rule.name or rule.id)
        if key in base_rules:
            raise RuleLoadError(f"{rel}: duplicate rule name {key}")
        base_rules[key] = BaseRule(key, str(rule.id), compiled, single)

    sequences: list[SequenceRule] = []
    baselines: list[BaselineRule] = []
    for doc, text, path in extension_docs:
        rel = path.relative_to(rules_dir).as_posix()
        kind = doc["sentinelops_extension"]
        extra = doc.get("sentinelops") or {}
        if kind == "sequence":
            meta = _meta(
                doc, extra, source="custom", kind="sequence", file=rel, yaml_text=text, playbook_ids=playbook_ids
            )
            sequences.append(_sequence(doc, meta, rel, config))
        elif kind == "baseline":
            meta = _meta(
                doc, extra, source="custom", kind="baseline", file=rel, yaml_text=text, playbook_ids=playbook_ids
            )
            baselines.append(BaselineRule(meta))
        else:
            raise RuleLoadError(f"{rel}: unknown extension type {kind!r}")
        metas[meta.rule_id] = meta

    known = set(base_rules) | {c.meta.name for c in correlations if c.meta.name}
    for corr in correlations:
        missing = [r for r in corr.rules if r not in known]
        if missing:
            raise RuleLoadError(f"{corr.meta.file}: unknown referenced rules {missing}")
    corr_names = {c.meta.name for c in correlations}
    for seq in sequences:
        if not set(seq.first_any) <= corr_names:
            raise RuleLoadError(f"{seq.meta.file}: sequence.first_any must reference correlation rules")
        if seq.then not in base_rules:
            raise RuleLoadError(f"{seq.meta.file}: sequence.then must reference a base rule")
    return RuleSet(base_rules, correlations, sequences, baselines, pipeline_hash, hasher.hexdigest(), metas)


def _correlation(rule: SigmaCorrelationRule, meta: RuleMeta, config: DetectionConfig) -> CorrelationRule:
    supported = {
        SigmaCorrelationType.EVENT_COUNT: "event_count",
        SigmaCorrelationType.VALUE_COUNT: "value_count",
        SigmaCorrelationType.TEMPORAL: "temporal",
        SigmaCorrelationType.TEMPORAL_ORDERED: "temporal_ordered",
    }
    ctype = supported.get(rule.type)
    if ctype is None:
        raise RuleLoadError(f"{meta.file}: correlation type {rule.type} is not supported")
    if rule.aliases and rule.aliases.aliases:
        raise RuleLoadError(f"{meta.file}: correlation aliases are not supported")
    condition = rule.condition
    if condition is not None and not isinstance(condition, SigmaCorrelationCondition):
        raise RuleLoadError(f"{meta.file}: extended correlation conditions are not supported")
    override = config.thresholds.get(meta.rule_id)
    count: int | None = None
    op: str | None = None
    value_field: str | None = None
    if condition is not None:
        if not float(condition.count).is_integer():
            raise RuleLoadError(f"{meta.file}: correlation count must be an integer")
        count, op = int(condition.count), condition.op.name.lower()
        if op not in ("gte", "gt", "eq") and ctype in ("event_count", "value_count"):
            raise RuleLoadError(f"{meta.file}: correlation condition {op} is not supported")
        if condition.fieldref is not None and not isinstance(condition.fieldref, str):
            raise RuleLoadError(f"{meta.file}: value_count over several fields is not supported")
        value_field = condition.fieldref
    timespan = rule.timespan.seconds
    if override is not None:
        count = override.count or count
        timespan = override.timespan_seconds or timespan
    names = tuple(
        str(getattr(getattr(ref, "rule", None), "name", None) or getattr(ref, "reference", ref))
        for ref in rule.rules or ()
    )
    return CorrelationRule(
        meta=meta,
        type=ctype,
        rules=names,
        group_by=tuple(rule.group_by or ()),
        timespan_seconds=timespan,
        op=op,
        count=count,
        value_field=value_field,
    )


def _sequence(doc: dict[str, Any], meta: RuleMeta, rel: str, config: DetectionConfig) -> SequenceRule:
    spec = doc.get("sequence")
    if not isinstance(spec, dict):
        raise RuleLoadError(f"{rel}: sequence block missing")
    try:
        first_any = tuple(str(x) for x in spec["first_any"])
        then = str(spec["then"])
        group_by = tuple(str(x) for x in spec.get("group-by") or ())
        same = tuple(str(x) for x in spec.get("same") or ())
        timespan = _timespan_seconds(str(spec["timespan"]))
    except KeyError as exc:
        raise RuleLoadError(f"{rel}: sequence.{exc.args[0]} missing") from exc
    unknown = sorted(set(spec) - {"first_any", "then", "group-by", "same", "timespan"})
    if unknown:
        raise RuleLoadError(f"{rel}: unsupported sequence keys {unknown}")
    override = config.thresholds.get(meta.rule_id)
    if override is not None and override.timespan_seconds:
        timespan = override.timespan_seconds
    return SequenceRule(meta, first_any, then, group_by, timespan, same)
