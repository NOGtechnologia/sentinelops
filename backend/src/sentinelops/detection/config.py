"""Detection, case building and priority configuration.

Everything here influences results and is therefore hashed into alerts and
reports (``config_hash``). Defaults correspond to spec sections 6-7.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinelops.normalize.dedupe import stable_hash


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ThresholdOverride(_Model):
    count: int | None = Field(default=None, ge=1)
    timespan_seconds: int | None = Field(default=None, ge=1)


class BaselineConfig(_Model):
    learning_days: int = Field(default=14, ge=1)
    min_active_days: int = Field(default=2, ge=1)
    min_logons: int = Field(default=5, ge=1)
    hour_quantile_low: float = Field(default=0.05, ge=0, le=0.5)
    hour_quantile_high: float = Field(default=0.95, ge=0.5, le=1)
    hour_margin: float = Field(default=1.0, ge=0)
    min_criteria: int = Field(default=2, ge=1, le=4)
    #: Windows logon types that form the profile: interactive (2), unlock (7),
    #: remote interactive (10), cached interactive (11). Events without a
    #: logon type (SSH, VPN) always count.
    logon_types: tuple[int, ...] = (2, 7, 10, 11)
    holidays: tuple[str, ...] = ("2026-01-01", "2026-04-03", "2026-04-06", "2026-05-01", "2026-05-14",
                                 "2026-05-25", "2026-10-03", "2026-12-25", "2026-12-26")


class PriorityWeights(_Model):
    severity: dict[str, int] = Field(
        default_factory=lambda: {"informational": 5, "low": 15, "medium": 35, "high": 55, "critical": 70}
    )
    success_after_failures: int = 15
    privileged_account: int = 10
    critical_asset: int = 10
    privilege_change: int = 10
    per_extra_tactic: int = 5
    max_tactic_bonus: int = 15
    experimental_penalty: int = -10
    max_false_positive_penalty: int = -15
    #: Lower score bounds for P1..P3; below P3 is P4.
    p1: int = 80
    p2: int = 60
    p3: int = 35


class DetectionConfig(_Model):
    version: int = 1
    thresholds: dict[str, ThresholdOverride] = Field(default_factory=dict)
    privileged_groups: tuple[str, ...] = (
        "Domain Admins", "Domänen-Admins", "Enterprise Admins", "Organisations-Admins", "Schema Admins",
        "Schema-Admins", "Administrators", "Administratoren", "Account Operators", "Backup Operators",
        "sudo", "wheel", "admin", "root",
    )
    expected_privileged_accounts: tuple[str, ...] = ("adm-*", "svc_backup", "Administrator", "SYSTEM")
    password_admins: tuple[str, ...] = ("adm-*", "helpdesk-*")
    critical_assets: tuple[str, ...] = ("dc01", "dc02", "srv-sql01", "srv-backup01", "srv-file01")
    #: Entities that never link cases (spec 7.2 "hub suppression"): domain
    #: controllers, access gateways (VPN, RDP gateway), loopback. Extended
    #: automatically by entities seen with >= hub_min_distinct_users users.
    hub_entities: tuple[str, ...] = ("dc01", "dc02", "srv-gw01", "vpn01", "127.0.0.1", "::1")
    hub_min_distinct_users: int = Field(default=25, ge=2)
    case_window_seconds: int = Field(default=7200, ge=60)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    priority: PriorityWeights = Field(default_factory=PriorityWeights)
    high_false_positive_rate: float = Field(default=0.5, ge=0, le=1)

    @property
    def case_window(self) -> timedelta:
        return timedelta(seconds=self.case_window_seconds)

    def placeholder_vars(self) -> dict[str, list[str]]:
        return {
            "privileged_groups": list(self.privileged_groups),
            "expected_privileged_accounts": list(self.expected_privileged_accounts),
            "password_admins": list(self.password_admins),
        }

    def config_hash(self) -> str:
        return stable_hash("detection-config", self.model_dump(mode="json"))

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> DetectionConfig:
        return cls.model_validate(data or {})
