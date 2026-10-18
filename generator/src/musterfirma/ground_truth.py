"""Ground truth schema (validated with Pydantic, exported as JSON Schema).

Records are referenced by *locators* (file + 1-based record position as
counted by the SentinelOps splitters), so the ground truth is independent of
the SentinelOps id scheme and can be resolved after ingestion.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Priority = Literal["P1", "P2", "P3", "P4"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Locator(_Model):
    file: str
    position: int = Field(ge=1)


class FileEntry(_Model):
    path: str
    source_type: str
    timezone: str
    records: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ScenarioEntry(_Model):
    id: str = Field(pattern=r"^S\d{2}$")
    number: int = Field(ge=1, le=10)
    title: str
    expected_rules: list[str] = Field(min_length=1)
    min_priority: Priority
    max_priority: Priority | None = None
    evidence: list[Locator] = Field(min_length=1)
    context: list[Locator] = Field(default_factory=list)


class Label(_Model):
    status: Literal["accepted", "duplicate", "malformed"]
    code: str | None = None
    assessment: Literal["normal", "suspicious"] | None = None
    flag: str | None = None


class LabelSet(_Model):
    """Records not listed are ``accepted`` and ``normal``."""

    exceptions: dict[str, Label] = Field(default_factory=dict)


class Persona(_Model):
    name: str
    display: str
    department: str


class GroundTruth(_Model):
    generator_version: str
    seed: str
    start: str
    end: str
    demo_now: str
    events_per_day: int
    files: list[FileEntry]
    scenarios: list[ScenarioEntry]
    labels: dict[str, LabelSet]
    personas: list[Persona]
    privileged_accounts: list[str]
    hub_hosts: list[str]
    monitoring_accounts: list[str]
