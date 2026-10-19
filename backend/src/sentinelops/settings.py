"""Application settings (environment variables prefixed ``SENTINELOPS_``).

Everything that influences detection results is part of :class:`DetectionConfig`
(see ``detection/config.py``) and hashed into reports; runtime settings here
(database URL, auth, AI provider) do not change results.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PRODUCT_NAME = "SentinelOps"
"""Central product name (spec 17.5: renaming must not require code changes;
the UI takes the name from i18n, the backend from here)."""

SOFTWARE_VERSION = "1.0.0"

PACKAGE_DIR = Path(__file__).resolve().parent
PROFILES_DIR = PACKAGE_DIR / "ingest" / "profiles"
PLAYBOOKS_DIR = PACKAGE_DIR / "investigation" / "playbooks"
REPO_ROOT = PACKAGE_DIR.parents[2]
RULES_DIR = Path(os.environ.get("SENTINELOPS_RULES_DIR", str(REPO_ROOT / "rules")))


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    number = int(value)
    if number < 0:
        raise ValueError(f"{name} must not be negative")
    return number


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "SENTINELOPS_DATABASE_URL", "postgresql+asyncpg://sentinelops@localhost:5432/sentinelops"
        )
    )
    demo_mode: bool = field(default_factory=lambda: _bool("SENTINELOPS_DEMO_MODE", False))
    demo_now: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_DEMO_NOW"))
    display_timezone: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_DISPLAY_TZ", "Europe/Berlin"))
    oidc_issuer: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_OIDC_ISSUER"))
    oidc_audience: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_OIDC_AUDIENCE", "sentinelops"))
    oidc_roles_claim: str = field(
        default_factory=lambda: os.environ.get("SENTINELOPS_OIDC_ROLES_CLAIM", "realm_access.roles")
    )
    four_eyes: bool = field(default_factory=lambda: _bool("SENTINELOPS_FOUR_EYES", True))
    approval_secret: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_APPROVAL_SECRET", ""))
    llm_provider: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_LLM_PROVIDER", "none"))
    llm_base_url: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_LLM_BASE_URL"))
    llm_model: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_LLM_MODEL"))
    llm_api_key: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_LLM_API_KEY"))
    llm_cloud_opt_in: bool = field(default_factory=lambda: _bool("SENTINELOPS_LLM_CLOUD_OPT_IN", False))
    llm_pseudonymize: bool = field(default_factory=lambda: _bool("SENTINELOPS_LLM_PSEUDONYMIZE", True))
    drop_folder: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_DROP_FOLDER"))
    syslog_port: int | None = field(
        default_factory=lambda: (
            int(os.environ["SENTINELOPS_SYSLOG_PORT"]) if os.environ.get("SENTINELOPS_SYSLOG_PORT") else None
        )
    )
    drop_folder_timezone: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_DROP_FOLDER_TZ", "UTC"))
    syslog_host: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_SYSLOG_HOST", "0.0.0.0"))  # noqa: S104 - container listener, opt-in via port
    syslog_timezone: str = field(default_factory=lambda: os.environ.get("SENTINELOPS_SYSLOG_TZ", "UTC"))
    static_dir: str | None = field(default_factory=lambda: os.environ.get("SENTINELOPS_STATIC_DIR"))
    #: Retention in days per data type (spec 16.2); 0 keeps data forever.
    retention_events_days: int = field(default_factory=lambda: _int("SENTINELOPS_RETENTION_EVENTS_DAYS", 90))
    retention_raw_days: int = field(default_factory=lambda: _int("SENTINELOPS_RETENTION_RAW_DAYS", 90))
    retention_closed_cases_days: int = field(
        default_factory=lambda: _int("SENTINELOPS_RETENTION_CLOSED_CASES_DAYS", 365)
    )
    retention_jobs_days: int = field(default_factory=lambda: _int("SENTINELOPS_RETENTION_JOBS_DAYS", 30))
