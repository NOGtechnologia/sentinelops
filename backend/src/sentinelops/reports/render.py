"""Case reports as JSON, Markdown and PDF (spec 10).

Pure functions: the input is a plain :class:`ReportInput`; the creation time
is a parameter. Same input => byte-identical JSON and Markdown and a PDF with
identical text and fixed metadata (acceptance test A5).

Log data is hostile: in Markdown every value is escaped (HTML entities and
Markdown control characters) by the template engine's ``finalize`` hook, raw
lines only ever appear inside fenced code blocks with a safe fence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader

from sentinelops.normalize.schema import format_timestamp

REPORT_SCHEMA_VERSION = "case-report/1"
TEMPLATES = Path(__file__).resolve().parent / "templates"
FONTS = Path(__file__).resolve().parent / "fonts"
#: Characters that start inline Markdown constructs (emphasis, code, links,
#: tables, strikethrough). HTML is neutralised separately via entities.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~])")


@dataclass(frozen=True)
class ReportInput:
    case: dict[str, Any]
    alerts: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    recommendations: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    notes: list[dict[str, Any]]
    metadata: dict[str, Any]
    ai_summary: dict[str, Any] | None = None
    injection_findings: list[dict[str, Any]] = field(default_factory=list)


class Safe(str):
    """Marks template output that is already safe Markdown."""

    __slots__ = ()


def md_escape(value: Any) -> str:
    if isinstance(value, Safe):
        return value
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", text)


def md_code(value: Any) -> Safe:
    """Inline code span that can hold any backtick sequence."""
    # "|" would end a GFM table cell even inside a code span.
    text = "" if value is None else str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if not text:
        return Safe("")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return Safe(f"{fence}{pad}{text}{pad}{fence}")


def md_block(value: Any) -> Safe:
    """Fenced code block with a fence longer than any backtick run inside."""
    text = "" if value is None else str(value)
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return Safe(f"{fence}text\n{text}\n{fence}")


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        # Markdown, not HTML: escaping is enforced for every value by finalize=md_escape.
        autoescape=False,  # noqa: S701
        finalize=md_escape,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["code"] = md_code
    env.filters["block"] = md_block
    return env


def build_report(data: ReportInput, created_at: datetime) -> dict[str, Any]:
    """The machine-readable report; key order and list order are stable."""
    metadata = dict(data.metadata)
    metadata["created_at"] = format_timestamp(created_at)
    metadata["report_schema"] = REPORT_SCHEMA_VERSION
    return {
        "metadata": dict(sorted(metadata.items())),
        "case": data.case,
        "priority": data.case.get("priority", {}),
        "alerts": sorted(data.alerts, key=lambda a: (a.get("window_start", ""), a.get("alert_id", ""))),
        "timeline": data.timeline,
        "evidence": sorted(data.evidence, key=lambda e: (e.get("time", ""), e.get("event_id", ""))),
        "ai_summary": data.ai_summary,
        "injection_findings": data.injection_findings,
        "recommendations": data.recommendations,
        "actions": sorted(data.actions, key=lambda a: (a.get("proposed_at", ""), a.get("action_id", ""))),
        "notes": sorted(data.notes, key=lambda n: (n.get("created_at", ""), n.get("note_id", ""))),
    }


def render_json(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def render_markdown(report: dict[str, Any], language: str = "de") -> str:
    template = _environment().get_template(f"case_report.{language}.md.j2")
    return template.render(r=report)


class _ReportPDF(FPDF):
    def __init__(self, title: str, footer_text: str) -> None:
        super().__init__(format="A4")
        self._title = title
        self._footer_text = footer_text

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Inter", size=7)
        self.set_text_color(110, 110, 110)
        self.cell(0, 5, f"{self._footer_text} - Seite {self.page_no()}/{{nb}}", align="C")


def _pdf_text(value: Any) -> str:
    text = "" if value is None else str(value)
    return "".join(ch if ch.isprintable() or ch in "\n\t" else "�" for ch in text)


def render_pdf(report: dict[str, Any]) -> bytes:
    """Readable PDF with fixed metadata; content mirrors the Markdown report."""
    meta = report["metadata"]
    case = report["case"]
    created = datetime.fromisoformat(meta["created_at"].replace("Z", "+00:00"))
    pdf = _ReportPDF(
        str(case.get("title_de", "")), f"SentinelOps {meta.get('software_version', '')} - {case.get('case_id', '')}"
    )
    pdf.add_font("Inter", "", str(FONTS / "Inter-Regular.ttf"))
    pdf.add_font("Inter", "B", str(FONTS / "Inter-Bold.ttf"))
    pdf.add_font("Mono", "", str(FONTS / "JetBrainsMono-Regular.ttf"))
    pdf.add_font("DejaVu", "", str(FONTS / "DejaVuSans.ttf"))
    pdf.set_fallback_fonts(["DejaVu"])
    pdf.set_creation_date(created)
    pdf.set_title(_pdf_text(f"Fallbericht {case.get('case_id', '')}"))
    pdf.set_author("SentinelOps")
    pdf.set_creator("SentinelOps")
    pdf.set_producer(f"SentinelOps {meta.get('software_version', '')}")
    pdf.set_subject(_pdf_text(case.get("title_de", "")))
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    def heading(text: str, size: int = 13) -> None:
        pdf.ln(2)
        pdf.set_font("Inter", "B", size)
        pdf.multi_cell(width, 7, _pdf_text(text))
        pdf.set_font("Inter", "", 9)

    def para(text: Any) -> None:
        pdf.set_font("Inter", "", 9)
        pdf.multi_cell(width, 5, _pdf_text(text))

    def mono(text: Any) -> None:
        pdf.set_font("Mono", "", 7.5)
        pdf.multi_cell(width, 4, _pdf_text(text))
        pdf.set_font("Inter", "", 9)

    heading(f"Fallbericht: {case.get('title_de', '')}", 15)
    para(f"Fall-ID: {case.get('case_id')} | Status: {case.get('status')} | Bearbeiter: {case.get('assignee') or '-'}")
    para(f"Zeitraum (UTC): {case.get('window_start')} bis {case.get('window_end')}")
    priority = report["priority"]
    heading(f"Priorität {priority.get('level')} (Score {priority.get('score')})")
    for factor in priority.get("factors", []):
        evidence = ", ".join(factor.get("evidence", []))
        para(
            f"{factor.get('contribution'):+d}  {factor.get('label_de')}"
            + (f"  [Belege: {evidence}]" if evidence else "")
        )
    summary = report.get("ai_summary") or {}
    output = summary.get("output") or {}
    heading("Zusammenfassung")
    source = summary.get("source", "template")
    para(
        f"Quelle: {source} | Modell: {summary.get('model', '-')} | Validierung: {summary.get('validation_status', '-')}"
        " | KI-generiert, geprüft gegen Belege"
        if source == "ai"
        else f"Quelle: {source} | Validierung: {summary.get('validation_status', '-')}"
    )
    para(output.get("summary", ""))
    if output.get("facts"):
        heading("Bestätigte Fakten", 11)
        for fact in output["facts"]:
            para(f"- {fact['statement']} [{', '.join(fact['evidence'])}]")
    if output.get("hypotheses"):
        heading("Hypothesen (nicht bestätigt)", 11)
        for hyp in output["hypotheses"]:
            para(f"- ({hyp['confidence']}) {hyp['statement']} - würde bestätigt durch: {hyp['would_confirm']}")
    if output.get("missing_information"):
        heading("Fehlende Informationen", 11)
        for item in output["missing_information"]:
            para(f"- {item['item']}: {item['why_relevant']}")
    if report.get("injection_findings"):
        heading("Hinweis: mögliche Prompt-Injection in Logdaten", 11)
        for finding in report["injection_findings"]:
            mono(f"{finding.get('field')}: {finding.get('excerpt')}")
    heading("Alarme")
    for alert in report["alerts"]:
        para(
            f"{alert.get('rule_id')} v{alert.get('rule_version')} - {alert.get('title_de')} ({alert.get('level')}), "
            f"{len(alert.get('event_ids', []))} Ereignisse, {alert.get('window_start')} - {alert.get('window_end')}"
        )
    heading("Empfohlene Schritte")
    for step in report["recommendations"]:
        suffix = " - Maßnahme, freigabepflichtig" if step.get("action") else ""
        para(f"- {step.get('title_de')} ({step.get('step_id')}){suffix}")
    heading("Maßnahmen und Freigaben")
    if not report["actions"]:
        para("Keine Maßnahmen vorgeschlagen.")
    for action in report["actions"]:
        para(
            f"{action.get('step_id')} {action.get('parameters')} - Status {action.get('status')}, vorgeschlagen von "
            f"{action.get('proposed_by')}"
            + (
                f", entschieden von {action['approval']['approver']}: {action['approval']['reason']}"
                if action.get("approval")
                else ""
            )
        )
    heading("Timeline")
    for item in report["timeline"]:
        if item.get("kind") == "event":
            rules = ", ".join(item.get("rules", []))
            para(
                f"{item.get('time')}  {item.get('action')} ({item.get('outcome')})  "
                f"Benutzer={item.get('user') or '-'}  Host={item.get('host') or '-'}  "
                f"IP={item.get('source_ip') or '-'}  [{rules}]"
            )
        elif item.get("kind") == "alert":
            para(f"{item.get('time')}  ALARM {item.get('rule_id')}: {item.get('title_de')}")
        else:
            para(f"{item.get('time')}  ... Lücke von {item.get('seconds')} s")
    heading("Belegauszüge")
    for ev in report["evidence"]:
        para(f"{ev.get('ref', '')} {ev.get('time')} {ev.get('event_id')}")
        mono(ev.get("raw", ""))
    heading("Analystennotizen")
    if not report["notes"]:
        para("Keine Notizen.")
    for note in report["notes"]:
        para(f"{note.get('created_at')} {note.get('author')}: {note.get('text')}")
    heading("Metadaten", 11)
    for key, value in meta.items():
        mono(f"{key}: {value}")
    data: bytes = bytes(pdf.output())
    return data
