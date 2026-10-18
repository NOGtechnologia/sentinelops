"""Detection of prompt-injection attempts in log data (spec 8.4 item 5).

Log content is attacker controlled. Strings that look like instructions to an
AI (user names, command lines, raw lines ...) are reported as a separate case
hint - the content is never executed or followed, only shown as data.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sentinelops.normalize.schema import CanonicalEvent

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, re.IGNORECASE))
    for name, rx in (
        (
            "ignore_instructions",
            r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|earlier|any)\b.{0,40}"
            r"\b(instructions?|prompts?|rules|evidence|context)\b",
        ),
        ("ignoriere_anweisungen", r"\b(ignorier\w*|vergiss)\b.{0,40}\b(anweisung\w*|regeln|vorgaben|belege)\b"),
        ("role_override", r"\b(you are now|act as|pretend to be|du bist (jetzt|nun))\b"),
        ("ai_addressed", r"\b(ai|ki|llm|chatgpt|assistant|assistent|claude|gpt)\b\s*[:,]"),
        ("system_prompt", r"\b(system prompt|systemprompt|system message|developer message)\b"),
        ("verdict_manipulation", r"\b(mark|classify|treat|report)\b.{0,30}\b(benign|harmless|false positive|safe)\b"),
        (
            "verdict_manipulation_de",
            r"\b(als|ist)\b.{0,20}\b(harmlos|fehlalarm|unbedenklich)\b.{0,20}\b(markier\w*|einstuf\w*|bewert\w*)?",
        ),
        ("chat_markup", r"(<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<<SYS>>|^\s*###\s*(system|instruction))"),
        ("do_not_report", r"\b(do not|don't|never)\b.{0,20}\b(report|alert|escalate|mention)\b"),
    )
)


@dataclass(frozen=True)
class InjectionFinding:
    event_id: str
    field: str
    pattern: str
    excerpt: str

    def to_dict(self) -> dict[str, str]:
        return {"event_id": self.event_id, "field": self.field, "pattern": self.pattern, "excerpt": self.excerpt}


def scan_text(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for name, pattern in PATTERNS:
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 20)
            hits.append((name, text[start : match.end() + 20][:160]))
    return hits


def _strings(prefix: str, value: Any) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(prefix, item)


def scan_events(events: Iterable[CanonicalEvent], raw_text: dict[str, str] | None = None) -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    raw_text = raw_text or {}
    for event in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        sources: list[tuple[str, str]] = []
        for name in sorted(event.fields):
            sources.extend(_strings(name, event.fields[name]))
        for name in sorted(event.original):
            sources.extend(_strings(name, event.original[name]))
        if event.event_id in raw_text:
            sources.append(("raw", raw_text[event.event_id]))
        seen: set[tuple[str, str]] = set()
        for field_name, text in sources:
            for pattern, excerpt in scan_text(text):
                key = (pattern, excerpt)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(InjectionFinding(event.event_id, field_name, pattern, excerpt))
    return findings
