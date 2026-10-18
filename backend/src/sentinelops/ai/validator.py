"""Deterministic validator for AI output (spec 8.4) - the hallucination guard.

The model must return exactly the JSON schema below. Afterwards every
statement is checked:

1. facts carry >= 1 evidence reference, every reference exists in the package;
2. indicators (IPs, domains, hashes, account and host names) mentioned in a
   statement must occur in the evidence package - unknown ones reject it;
3. recommended steps must come from the playbook catalogue;
4. no claim that a response measure was already carried out unless such an
   execution exists (or the cited evidence shows the event itself, e.g. an
   account lockout);

Rejected statements are kept with a reason for transparency. Invalid JSON or
schema violations discard the whole output.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinelops.ai.evidence import EvidencePackage

REF_RE = re.compile(r"^E[1-9]\d*$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FactOut(_Strict):
    statement: str = Field(min_length=1, max_length=2000)
    evidence: list[str]


class HypothesisOut(_Strict):
    statement: str = Field(min_length=1, max_length=2000)
    confidence: Literal["low", "medium", "high"]
    evidence: list[str]
    would_confirm: str = Field(max_length=2000)


class MissingOut(_Strict):
    item: str = Field(min_length=1, max_length=1000)
    why_relevant: str = Field(max_length=2000)


class StepOut(_Strict):
    playbook_step_id: str
    rationale: str = Field(max_length=2000)
    evidence: list[str]


class AIOutput(_Strict):
    summary: str = Field(max_length=4000)
    facts: list[FactOut] = Field(max_length=50)
    hypotheses: list[HypothesisOut] = Field(max_length=30)
    missing_information: list[MissingOut] = Field(max_length=30)
    recommended_steps: list[StepOut] = Field(max_length=20)


@dataclass(frozen=True)
class Rejection:
    section: str  # summary | facts | hypotheses | recommended_steps | output
    statement: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"section": self.section, "statement": self.statement, "reasons": list(self.reasons)}


@dataclass
class ValidationResult:
    status: str  # valid | partially_valid | invalid
    output: dict[str, Any] | None
    rejected: list[Rejection] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "output": self.output, "rejected": [r.to_dict() for r in self.rejected]}


# --- indicator extraction ----------------------------------------------------

# A trailing sentence period must not hide an address: "... from 198.51.100.77."
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_HASH = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:example|local|corp|lan|com|net|org|de|io|info|biz|ru|cn|xyz|top|eu|uk)\b"
)
_ACCOUNT = re.compile(
    r"(?<![\w.@\\-])(?:"
    r"[A-Za-z0-9_-]+\\[A-Za-z0-9._$-]+"  # DOMAIN\user
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"  # user@domain
    r"|[A-Za-z0-9_-]+\$"  # machine account
    r"|[a-z][a-z0-9]*[._][a-z0-9]+(?:[._][a-z0-9]+)*"  # first.last, svc_backup
    r"|(?:adm|svc|admin)-[A-Za-z0-9._-]+"  # adm-weber
    r"|[A-Za-z]+-[A-Za-z]*\d+[A-Za-z0-9]*"  # srv-gw01, ws-0042, SRV-FILE01
    r"|[A-Za-z]{2,}\d{2,}"  # dc01, vpn01
    r")(?![\w@-])"
)
#: tokens that look like identifiers but are vocabulary of the package itself
_SAFE_TOKEN = re.compile(
    r"^(?:E\d+|P[1-4]|T\d{4}(?:\.\d{3})?|TA\d{4}|SO-[A-Z]+-\d{3}|SIGMAHQ-[0-9A-F]{8}|\d+)$", re.IGNORECASE
)


def _normalise(token: str) -> str:
    return token.strip(".,;:()[]{}'\"").casefold()


def extract_indicators(text: str) -> list[str]:
    found: dict[str, None] = {}
    for regex in (_IPV4, _IPV6, _HASH, _DOMAIN, _ACCOUNT):
        for match in regex.finditer(text):
            token = match.group(0)
            if regex is _IPV6:
                try:
                    ipaddress.ip_address(token)
                except ValueError:
                    continue
            if regex is _IPV4:
                try:
                    ipaddress.ip_address(token)
                except ValueError:
                    continue
            if _SAFE_TOKEN.match(token):
                continue
            found.setdefault(_normalise(token))
    return list(found)


def _package_vocabulary(package: EvidencePackage) -> set[str]:
    vocab: set[str] = set()

    def add(value: Any) -> None:
        if isinstance(value, str):
            text = value.casefold()
            vocab.add(text)
            vocab.update(extract_indicators(value))
            for part in re.split(r"[\\@\s,;]+", text):
                if part:
                    vocab.add(part)
            if "." in text and not _IPV4.fullmatch(text):
                vocab.add(text.split(".", 1)[0])
        elif isinstance(value, dict):
            for v in value.values():
                add(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                add(v)
        else:  # numbers, booleans, None - harmless as vocabulary
            vocab.add(str(value).casefold())

    add(package.to_dict())
    return vocab


# --- action claims -----------------------------------------------------------

#: claim patterns -> (playbook step, event actions that legitimately document it)
ACTION_CLAIMS: tuple[tuple[str, re.Pattern[str], frozenset[str]], ...] = (
    (
        "DISABLE_ACCOUNT",
        re.compile(
            r"\b(konto|account|benutzer|user)\b.{0,60}\b(wurde|ist|wurden|has been|was|is now|were)\b.{0,30}"
            r"\b(gesperrt|deaktiviert|disabled|blocked|locked)\b"
            r"|\b(gesperrt|deaktiviert|disabled)\b.{0,20}\b(wurde|has been)\b",
            re.IGNORECASE,
        ),
        frozenset({"account-locked"}),
    ),
    (
        "ISOLATE_HOST",
        re.compile(
            r"\b(rechner|host|system|gerät|device|computer|server)\b.{0,60}\b(wurde|ist|has been|was|is now)\b.{0,30}"
            r"\b(isoliert|isolated|quarantined|vom netz getrennt)\b",
            re.IGNORECASE,
        ),
        frozenset(),
    ),
    (
        "BLOCK_SOURCE_IP",
        re.compile(
            r"\b(ip|adresse|address|quelle|source)\b.{0,60}\b(wurde|ist|has been|was|is now)\b.{0,30}"
            r"\b(gesperrt|geblockt|blockiert|blocked|banned)\b",
            re.IGNORECASE,
        ),
        frozenset(),
    ),
    (
        "RESET_PASSWORD",
        re.compile(
            r"\b(passwort|password|kennwort)\b.{0,60}\b(wurde|ist|has been|was)\b.{0,30}"
            r"\b(zurückgesetzt|geändert|reset|changed|rotated)\b",
            re.IGNORECASE,
        ),
        frozenset({"password-reset", "password-changed"}),
    ),
)


def _claim_violations(statement: str, evidence_actions: set[str], executed: set[str]) -> list[str]:
    reasons: list[str] = []
    for step_id, pattern, documenting in ACTION_CLAIMS:
        if not pattern.search(statement):
            continue
        if step_id in executed or (documenting & evidence_actions):
            continue
        reasons.append(f"claims measure {step_id} was carried out, but no approved execution exists")
    return reasons


# --- validation --------------------------------------------------------------


def _check_refs(refs: Iterable[str], package_refs: Mapping[str, str]) -> list[str]:
    reasons: list[str] = []
    for ref in refs:
        if not REF_RE.match(ref):
            reasons.append(f"malformed evidence reference {ref!r}")
        elif ref not in package_refs:
            reasons.append(f"unknown evidence reference {ref}")
    return reasons


def validate_output(raw: str, package: EvidencePackage) -> ValidationResult:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        return ValidationResult(
            "invalid", None, [Rejection("output", raw[:500] if isinstance(raw, str) else "", (f"invalid JSON: {exc}",))]
        )
    try:
        parsed = AIOutput.model_validate(data)
    except ValidationError as exc:
        schema_errors = tuple(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10])
        return ValidationResult("invalid", None, [Rejection("output", json.dumps(data)[:500], schema_errors)])

    refs = package.refs
    vocabulary = _package_vocabulary(package)
    executed = {a.get("step_id", "") for a in package.executed_actions if a.get("status") == "executed"}
    catalog = {p["id"] for p in package.playbooks}
    event_actions = {i.ref: str(i.fields.get("event.action", "")) for i in package.items}
    rejected: list[Rejection] = []

    def unknown_indicators(text: str) -> list[str]:
        return [f"unsupported indicator {tok!r}" for tok in extract_indicators(text) if tok not in vocabulary]

    def actions_for(evidence: list[str]) -> set[str]:
        return {event_actions[r] for r in evidence if r in event_actions}

    facts = []
    for fact in parsed.facts:
        reasons = _check_refs(fact.evidence, refs)
        if not fact.evidence:
            reasons.append("fact without evidence")
        reasons += unknown_indicators(fact.statement)
        reasons += _claim_violations(fact.statement, actions_for(fact.evidence), executed)
        if reasons:
            rejected.append(Rejection("facts", fact.statement, tuple(reasons)))
        else:
            facts.append(fact.model_dump())

    hypotheses = []
    for hyp in parsed.hypotheses:
        reasons = _check_refs(hyp.evidence, refs)
        reasons += unknown_indicators(hyp.statement) + unknown_indicators(hyp.would_confirm)
        reasons += _claim_violations(hyp.statement, actions_for(hyp.evidence), executed)
        if reasons:
            rejected.append(Rejection("hypotheses", hyp.statement, tuple(reasons)))
        else:
            hypotheses.append(hyp.model_dump())

    steps = []
    for step in parsed.recommended_steps:
        reasons = _check_refs(step.evidence, refs)
        if step.playbook_step_id not in catalog:
            reasons.append(f"step {step.playbook_step_id!r} is not in the playbook catalogue")
        reasons += unknown_indicators(step.rationale)
        if reasons:
            rejected.append(
                Rejection("recommended_steps", f"{step.playbook_step_id}: {step.rationale}", tuple(reasons))
            )
        else:
            steps.append(step.model_dump())

    missing = []
    for item in parsed.missing_information:
        reasons = unknown_indicators(item.item) + unknown_indicators(item.why_relevant)
        if reasons:
            rejected.append(Rejection("missing_information", item.item, tuple(reasons)))
        else:
            missing.append(item.model_dump())

    summary = parsed.summary
    # The summary speaks about the whole case: events anywhere in the package
    # (e.g. an account lockout) may be described as having happened.
    summary_reasons = unknown_indicators(summary) + _claim_violations(summary, set(event_actions.values()), executed)
    if summary_reasons:
        rejected.append(Rejection("summary", summary, tuple(summary_reasons)))
        summary = ""

    output = {
        "summary": summary,
        "facts": facts,
        "hypotheses": hypotheses,
        "missing_information": missing,
        "recommended_steps": steps,
    }
    return ValidationResult("partially_valid" if rejected else "valid", output, rejected)
