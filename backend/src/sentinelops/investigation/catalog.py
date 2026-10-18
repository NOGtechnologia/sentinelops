"""Playbook step catalogue (``investigation/playbooks/*.yaml``)."""

from __future__ import annotations

from functools import cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sentinelops.settings import PLAYBOOKS_DIR


class PlaybookStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[A-Z][A-Z_]+$")
    priority: int
    action: bool
    title_de: str
    title_en: str
    description_de: str
    description_en: str
    parameters: tuple[str, ...] = ()


def load_catalog(directory: Path = PLAYBOOKS_DIR) -> dict[str, PlaybookStep]:
    steps: dict[str, PlaybookStep] = {}
    for path in sorted(directory.glob("*.yaml")):
        for raw in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            step = PlaybookStep.model_validate(raw)
            if step.id in steps:
                raise ValueError(f"duplicate playbook step {step.id}")
            steps[step.id] = step
    return steps


@cache
def default_catalog() -> dict[str, PlaybookStep]:
    return load_catalog()


def catalog_ids() -> frozenset[str]:
    return frozenset(default_catalog())
