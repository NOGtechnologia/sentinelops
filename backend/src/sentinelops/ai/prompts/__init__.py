"""Versioned prompt templates (``prompt_version`` is stored with every output)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from sentinelops.ai.evidence import PROMPT_VERSION

_DIR = Path(__file__).resolve().parent
_FILES = {"case-summary/1": "case_summary_v1.txt"}


@dataclass(frozen=True)
class Prompt:
    version: str
    instructions: str
    data: str

    @property
    def full_text(self) -> str:
        return f"{self.instructions}\nBEGIN DATA\n{self.data}\nEND DATA\n"


@cache
def template(version: str = PROMPT_VERSION) -> str:
    return (_DIR / _FILES[version]).read_text(encoding="utf-8")


def render(package: dict[str, Any], language: str = "German", version: str = PROMPT_VERSION) -> Prompt:
    """Instructions first, data afterwards and clearly delimited (spec 8.3)."""
    data = json.dumps(package, ensure_ascii=False, sort_keys=True, indent=1)
    # The data block must not be able to close itself early.
    data = data.replace("END DATA", "END_DATA").replace("BEGIN DATA", "BEGIN_DATA")
    return Prompt(version, template(version).format(language=language), data)
