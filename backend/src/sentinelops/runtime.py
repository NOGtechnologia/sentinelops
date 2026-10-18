"""Runtime wiring: settings -> engine, profiles, rule set, exceptions, provider.

One place that loads everything an installation needs, used by the API, the
worker and the CLI.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path
from zoneinfo import ZoneInfo

from sqlalchemy.ext.asyncio import AsyncEngine

from sentinelops.ai.providers import LLMProvider, ProviderConfig, build_provider
from sentinelops.detection.config import DetectionConfig
from sentinelops.detection.exceptions import RuleException, load_exceptions
from sentinelops.detection.sigma_loader import RuleSet, load_ruleset
from sentinelops.investigation.catalog import PlaybookStep, default_catalog
from sentinelops.parsers.json_mapped import MappingProfile, load_profiles
from sentinelops.settings import PROFILES_DIR, RULES_DIR, Settings
from sentinelops.storage.db import make_engine
from sentinelops.worker.analysis import AnalysisContext


class Clock:
    """Injectable time source (CLAUDE.md rule 7). In demo mode the clock is
    frozen at ``SENTINELOPS_DEMO_NOW`` so screenshots and reports are stable."""

    def __init__(self, fixed: datetime | None = None) -> None:
        self.fixed = fixed

    def now(self) -> datetime:
        return self.fixed if self.fixed is not None else datetime.now(UTC)


@dataclass
class Runtime:
    settings: Settings
    rules_dir: Path = RULES_DIR

    @cached_property
    def clock(self) -> Clock:
        if self.settings.demo_mode and self.settings.demo_now:
            return Clock(datetime.fromisoformat(self.settings.demo_now).astimezone(UTC))
        return Clock()

    @cached_property
    def engine(self) -> AsyncEngine:
        return make_engine(self.settings.database_url)

    @cached_property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.settings.display_timezone)

    @cached_property
    def profiles(self) -> dict[str, MappingProfile]:
        return load_profiles(PROFILES_DIR, self.clock.now())

    @cached_property
    def config(self) -> DetectionConfig:
        return DetectionConfig()

    @cached_property
    def catalog(self) -> dict[str, PlaybookStep]:
        return default_catalog()

    @cached_property
    def ruleset(self) -> RuleSet:
        return load_ruleset(self.rules_dir, self.config, frozenset(self.catalog))

    @cached_property
    def file_exceptions(self) -> list[RuleException]:
        return load_exceptions(self.rules_dir / "exceptions")

    @cached_property
    def provider(self) -> LLMProvider | None:
        s = self.settings
        return build_provider(
            ProviderConfig(s.llm_provider, s.llm_base_url, s.llm_model, s.llm_api_key, s.llm_cloud_opt_in)
        )

    @cached_property
    def approval_secret(self) -> bytes:
        secret = self.settings.approval_secret
        if not secret:
            if not self.settings.demo_mode:
                raise RuntimeError("SENTINELOPS_APPROVAL_SECRET must be set (>= 32 characters)")
            # Demo installations derive a fixed secret; clearly not for production.
            secret = hashlib.sha256(b"sentinelops-demo-approval-secret").hexdigest()
        return secret.encode("utf-8")

    def analysis_context(self, exceptions: list[RuleException] | None = None) -> AnalysisContext:
        return AnalysisContext(
            ruleset=self.ruleset,
            config=self.config,
            exceptions=exceptions if exceptions is not None else self.file_exceptions,
            catalog=self.catalog,
            tz=self.tz,
            provider=self.provider,
            pseudonymize=self.settings.llm_pseudonymize,
        )
