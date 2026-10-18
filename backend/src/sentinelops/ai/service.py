"""Summary generation: evidence package -> (pseudonymise) -> provider -> validator.

Every result is stored with the package hash, provider, model, prompt version,
parameters and the validation result (spec 8.5); reports use the stored
record. Without a provider - or when the provider fails or returns invalid
output - the deterministic template is used and the record says so.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinelops.ai.evidence import EvidencePackage
from sentinelops.ai.injection import InjectionFinding
from sentinelops.ai.prompts import render
from sentinelops.ai.providers import LLMProvider, ProviderError
from sentinelops.ai.pseudonymize import Pseudonymizer
from sentinelops.ai.template import template_output
from sentinelops.ai.validator import ValidationResult, validate_output
from sentinelops.investigation.recommendations import Recommendation
from sentinelops.normalize.schema import format_timestamp


@dataclass
class SummaryRecord:
    case_id: str
    source: str  # template | ai | ai_rejected_template
    provider: str
    model: str
    prompt_version: str
    parameters: dict[str, Any]
    evidence_hash: str
    pseudonymized: bool
    raw_output: str | None
    validation: ValidationResult
    injection_findings: list[InjectionFinding] = field(default_factory=list)
    error: str | None = None
    created_at: str = ""

    @property
    def output(self) -> dict[str, Any]:
        return self.validation.output or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source": self.source,
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "parameters": self.parameters,
            "evidence_hash": self.evidence_hash,
            "pseudonymized": self.pseudonymized,
            "validation_status": self.validation.status,
            "output": self.output,
            "rejected": [r.to_dict() for r in self.validation.rejected],
            "injection_findings": [f.to_dict() for f in self.injection_findings],
            "error": self.error,
            "created_at": self.created_at,
        }


def summarize(
    package: EvidencePackage,
    recommendations: Sequence[Recommendation],
    provider: LLMProvider | None,
    now: datetime,
    injection_findings: Sequence[InjectionFinding] = (),
    pseudonymize: bool = True,
    language: str = "German",
) -> SummaryRecord:
    def record(
        source: str,
        validation: ValidationResult,
        raw_output: str | None = None,
        error: str | None = None,
        pseudonymized: bool = False,
    ) -> SummaryRecord:
        return SummaryRecord(
            case_id=package.case_id,
            source=source,
            provider=provider.name if provider else "none",
            model=provider.model if provider else "template",
            prompt_version=package.prompt_version,
            parameters=provider.parameters() if provider else {},
            evidence_hash=package.package_hash,
            pseudonymized=pseudonymized,
            raw_output=raw_output,
            validation=validation,
            injection_findings=list(injection_findings),
            error=error,
            created_at=format_timestamp(now),
        )

    template_json = json.dumps(template_output(package, recommendations), ensure_ascii=False)
    if provider is None:
        return record("template", validate_output(template_json, package))

    use_pseudonyms = pseudonymize and provider.cloud
    package_dict = package.to_dict()
    mapper = Pseudonymizer()
    if use_pseudonyms:
        package_dict = mapper.pseudonymize_package(package_dict)
    prompt = render(package_dict, language=language)
    try:
        raw = provider.complete(prompt)
    except ProviderError as exc:
        return record(
            "ai_rejected_template",
            validate_output(template_json, package),
            error=str(exc),
            pseudonymized=use_pseudonyms,
        )
    if use_pseudonyms:
        # Unparsable output is left as is; the validator rejects it as invalid JSON.
        with contextlib.suppress(json.JSONDecodeError):
            raw = json.dumps(mapper.revert_output(json.loads(raw)), ensure_ascii=False)
    validation = validate_output(raw, package)
    if validation.status == "invalid" or not validation.output:
        fallback = validate_output(template_json, package)
        fallback.rejected = validation.rejected + fallback.rejected
        fallback.status = "invalid"
        return record("ai_rejected_template", fallback, raw, "AI output discarded (schema)", use_pseudonyms)
    return record("ai", validation, raw, pseudonymized=use_pseudonyms)
