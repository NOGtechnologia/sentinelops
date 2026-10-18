from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta

from pypdf import PdfReader

from sentinelops.reports.aggregate import CaseFacts, build_aggregate
from sentinelops.reports.csv_export import safe_cell, to_csv
from sentinelops.reports.render import (
    ReportInput,
    Safe,
    build_report,
    md_block,
    md_code,
    md_escape,
    render_json,
    render_markdown,
    render_pdf,
)

CREATED = datetime(2026, 3, 12, 10, 30, tzinfo=UTC)
XSS = "<img src=x onerror=alert(1)>"


def report_input(with_ai: bool = True) -> ReportInput:
    return ReportInput(
        case={
            "case_id": "c0ffee",
            "title_de": "Aufnahme in privilegierte Gruppe: jonas.becker",
            "status": "new",
            "assignee": None,
            "window_start": "2026-03-12T02:10:00.000000Z",
            "window_end": "2026-03-12T02:20:00.000000Z",
            "priority": {
                "level": "P1",
                "score": 100,
                "factors": [
                    {
                        "code": "max_severity",
                        "contribution": 70,
                        "label_de": "Höchster Schweregrad: critical",
                        "evidence": ["E5"],
                    },
                    {"code": "experimental_rule", "contribution": -10, "label_de": "experimentell", "evidence": []},
                ],
            },
        },
        alerts=[
            {
                "alert_id": "b",
                "rule_id": "SO-PRIV-001",
                "rule_version": 1,
                "title_de": "Aufnahme in privilegierte Gruppe",
                "level": "critical",
                "event_ids": ["e5"],
                "window_start": "2026-03-12T02:19:07.000000Z",
                "window_end": "2026-03-12T02:19:07.000000Z",
            },
            {
                "alert_id": "a",
                "rule_id": "SO-AUTH-001",
                "rule_version": 1,
                "title_de": "Brute Force",
                "level": "high",
                "event_ids": ["e1", "e2"],
                "window_start": "2026-03-12T02:10:00.000000Z",
                "window_end": "2026-03-12T02:12:00.000000Z",
            },
        ],
        timeline=[
            {
                "kind": "event",
                "time": "2026-03-12T02:10:00.000000Z",
                "action": "logon-failed",
                "outcome": "failure",
                "user": XSS,
                "host": "srv-gw01",
                "source_ip": "203.0.113.45",
                "rules": ["SO-AUTH-001"],
            },
            {
                "kind": "gap",
                "time": "2026-03-12T02:12:00.000000Z",
                "seconds": 400,
                "until": "2026-03-12T02:19:00.000000Z",
            },
            {"kind": "alert", "time": "2026-03-12T02:19:07.000000Z", "rule_id": "SO-PRIV-001", "title_de": "Aufnahme"},
            {
                "kind": "event",
                "time": "2026-03-12T02:19:07.000000Z",
                "action": "x",
                "outcome": "success",
                "user": None,
                "host": None,
                "source_ip": None,
                "rules": [],
            },
        ],
        evidence=[
            {
                "ref": "E1",
                "event_id": "e1",
                "time": "2026-03-12T02:10:00.000000Z",
                "raw": "<Event>```" + XSS + "</Event>\nline2 ü 😀 \x07",
            }
        ],
        recommendations=[
            {
                "step_id": "DISABLE_ACCOUNT",
                "title_de": "Konto sperren",
                "action": True,
                "reason_rules": ["SO-PRIV-001"],
            },
            {
                "step_id": "VERIFY_ACCOUNT_ACTIVITY",
                "title_de": "Kontoaktivität prüfen",
                "action": False,
                "reason_rules": ["SO-AUTH-001"],
            },
        ],
        actions=[
            {
                "action_id": "x1",
                "step_id": "DISABLE_ACCOUNT",
                "parameters": {"user": "jonas.becker"},
                "status": "executed",
                "proposed_by": "analyst",
                "proposed_at": "2026-03-12T09:00:00.000000Z",
                "approval": {
                    "decision": "approved",
                    "approver": "senior",
                    "decided_at": "2026-03-12T09:05:00.000000Z",
                    "reason": "bestätigt",
                },
                "execution": {"details": "SIMULATION (nothing was changed): would disable account jonas.becker"},
            },
            {
                "action_id": "x2",
                "step_id": "BLOCK_SOURCE_IP",
                "parameters": {"ip": "203.0.113.45"},
                "status": "proposed",
                "proposed_by": "ai",
                "proposed_at": "2026-03-12T09:01:00.000000Z",
            },
        ],
        notes=[
            {
                "note_id": "n1",
                "created_at": "2026-03-12T09:10:00.000000Z",
                "author": "analyst",
                "text": "Owner says *not me* | `rm -rf`",
            }
        ],
        metadata={
            "software_version": "1.0.0",
            "events_hash": "e" * 64,
            "ruleset_hash": "r" * 64,
            "config_hash": "c" * 32,
            "prompt_version": "case-summary/1",
        },
        ai_summary={
            "source": "ai",
            "provider": "mock",
            "model": "mock-1",
            "prompt_version": "case-summary/1",
            "validation_status": "partially_valid",
            "output": {
                "summary": "Angriff auf jonas.becker.",
                "facts": [{"statement": "Fehlanmeldungen", "evidence": ["E1"]}],
                "hypotheses": [
                    {
                        "statement": "Passwort erraten",
                        "confidence": "medium",
                        "evidence": [],
                        "would_confirm": "Kontoinhaber",
                    }
                ],
                "missing_information": [{"item": "VPN-Logs", "why_relevant": "weitere Sitzungen"}],
            },
            "rejected": [{"section": "facts", "statement": "198.51.100.1", "reasons": ["unsupported"]}],
        }
        if with_ai
        else {"source": "template", "validation_status": "valid", "output": {"summary": "Vorlage"}},
        injection_findings=[
            {
                "event_id": "e9",
                "field": "user.name",
                "pattern": "ignore_instructions",
                "excerpt": "ignore previous instructions",
            }
        ],
    )


def test_json_and_markdown_are_byte_identical() -> None:
    a = build_report(report_input(), CREATED)
    b = build_report(report_input(), CREATED)
    assert render_json(a) == render_json(b)
    assert render_markdown(a) == render_markdown(b)
    data = json.loads(render_json(a))
    assert data["metadata"]["created_at"] == "2026-03-12T10:30:00.000000Z"
    assert data["metadata"]["report_schema"] == "case-report/1"
    assert [x["rule_id"] for x in data["alerts"]] == ["SO-AUTH-001", "SO-PRIV-001"]
    other = build_report(report_input(), CREATED + timedelta(seconds=1))
    assert render_json(other) != render_json(a)


def test_markdown_escapes_log_data() -> None:
    md = render_markdown(build_report(report_input(), CREATED))
    before_raw = md[: md.index("## Belegauszüge")]
    # outside code spans/blocks the payload never appears unescaped
    assert before_raw.count(XSS) == before_raw.count(f"`{XSS}`")
    assert f"`{XSS}`" in md  # code span: rendered as text, never as HTML
    assert "Owner says \\*not me\\* \\| \\`rm -rf\\`" in md
    assert md_code("a|b") == "`a\\|b`"
    assert "````text" in md  # fence longer than the ``` inside the raw line
    assert "KI-generiert, geprüft gegen Belege" in md
    assert "Verworfene KI-Aussagen" in md
    assert "Prompt-Injection" in md
    assert "| **100** | **Summe → P1** | |" in md


def test_markdown_template_summary() -> None:
    md = render_markdown(build_report(report_input(with_ai=False), CREATED))
    assert "Deterministische Vorlagen-Zusammenfassung" in md


def test_md_helpers() -> None:
    assert md_escape(None) == ""
    assert md_escape(Safe("**x**")) == "**x**"
    assert md_escape("a\nb <c> & *d*") == "a b &lt;c&gt; &amp; \\*d\\*"
    assert md_code("a`b") == "``a`b``"
    assert md_code("`x") == "`` `x ``"
    assert md_code(None) == ""
    assert md_block("x").startswith("```text\n")
    assert md_block(None) == "```text\n\n```"


def test_pdf_text_identical_and_metadata_fixed() -> None:
    report = build_report(report_input(), CREATED)
    first, second = render_pdf(report), render_pdf(report)
    text_a = "".join(p.extract_text() for p in PdfReader(io.BytesIO(first)).pages)
    text_b = "".join(p.extract_text() for p in PdfReader(io.BytesIO(second)).pages)
    assert text_a == text_b
    assert "Fallbericht" in text_a
    assert "Priorität P1" in text_a
    meta = PdfReader(io.BytesIO(first)).metadata
    assert meta is not None
    assert meta.producer == "SentinelOps 1.0.0"
    assert meta.creation_date is not None
    assert meta.creation_date.year == 2026
    no_actions = build_report(
        ReportInput(**{**report_input(with_ai=False).__dict__, "actions": [], "notes": []}), CREATED
    )
    assert render_pdf(no_actions).startswith(b"%PDF")


def test_csv_formula_injection() -> None:
    assert safe_cell("=1+1") == "'=1+1"
    assert safe_cell("+49 30") == "'+49 30"
    assert safe_cell("-cmd") == "'-cmd"
    assert safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert safe_cell("\tx") == "'\tx"
    assert safe_cell("\rx") == "'\rx"
    assert safe_cell("normal") == "normal"
    assert safe_cell(None) == ""
    assert safe_cell(["a", "b"]) == "a, b"
    assert safe_cell(5) == "5"
    text = to_csv(["user", "count"], [{"user": '=HYPERLINK("http://evil.example")', "count": 3}, {"user": "max"}])
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["user", "count"]
    assert rows[1] == ['\'=HYPERLINK("http://evil.example")', "3"]
    assert rows[2] == ["max", ""]


def test_aggregate_report() -> None:
    t = datetime(2026, 3, 10, tzinfo=UTC)
    cases = [
        CaseFacts(
            "a",
            "P1",
            "resolved_true_positive",
            ("SO-AUTH-001", "SO-PRIV-001"),
            t,
            t + timedelta(minutes=10),
            t + timedelta(hours=2),
        ),
        CaseFacts("b", "P4", "resolved_false_positive", ("SO-AUTH-007",), t, None, t + timedelta(minutes=30)),
        CaseFacts("c", "P3", "new", ("SO-AUTH-001",), t + timedelta(days=1), None, None),
        CaseFacts("d", "P2", "new", ("SO-X",), t + timedelta(days=30), None, None),
    ]
    agg = build_aggregate(cases, t, t + timedelta(days=7), CREATED)
    assert agg["cases"] == 3
    assert agg["by_priority"] == {"P1": 1, "P2": 0, "P3": 1, "P4": 1}
    assert agg["top_rules"][0] == {"rule_id": "SO-AUTH-001", "cases": 2}
    assert agg["false_positive_rate"] == {"SO-AUTH-001": 0.0, "SO-AUTH-007": 1.0, "SO-PRIV-001": 0.0}
    assert agg["median_minutes_to_first_action"] == 10.0
    assert agg["median_minutes_to_resolution"] == 75.0
    empty = build_aggregate([], t, t, CREATED)
    assert empty["median_minutes_to_first_action"] is None
