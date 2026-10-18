"""Deterministic template summary - used without AI and as fallback (spec 8.1).

Produces the same structure as the AI output, built only from facts that the
detection already established, so it always passes the validator.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sentinelops.ai.evidence import EvidencePackage
from sentinelops.investigation.recommendations import Recommendation


def template_output(package: EvidencePackage, recommendations: Sequence[Recommendation]) -> dict[str, Any]:
    priority = package.priority
    alerts = list(package.alerts)
    users = [e["display"] for e in package.entities if e["type"] == "user"]
    hosts = [e["display"] for e in package.entities if e["type"] == "host"]
    ips = [e["display"] for e in package.entities if e["type"] == "ip"]
    start = min((a["window_start"] for a in alerts), default="")
    end = max((a["window_end"] for a in alerts), default="")
    headline = f"Fall {priority['level']} (Score {priority['score']}): {len(alerts)} Alarm(e)"
    parts = [f"{headline} zwischen {start} und {end} (UTC)."]
    if users:
        parts.append("Beteiligte Konten: " + ", ".join(users[:10]) + ("…" if len(users) > 10 else "") + ".")
    if hosts:
        parts.append("Geräte: " + ", ".join(hosts[:10]) + ("…" if len(hosts) > 10 else "") + ".")
    if ips:
        parts.append("Quell-IPs: " + ", ".join(ips[:10]) + ("…" if len(ips) > 10 else "") + ".")
    facts: list[dict[str, Any]] = []
    for alert in alerts:
        evidence = alert["evidence"][:3]
        if evidence:
            statement = f"Regel {alert['rule_id']} ({alert['title']}) hat mit {alert['event_count']} Ereignis(sen)"
            facts.append({"statement": f"{statement} ausgelöst.", "evidence": evidence})
    facts.extend(
        {
            "statement": f"Prioritätsfaktor ({factor['contribution']:+d}): {factor['label']}",
            "evidence": factor["evidence"][:3],
        }
        for factor in priority["factors"]
        if factor["evidence"]
    )
    missing: list[dict[str, str]] = []
    if package.omitted_events:
        missing.append(
            {
                "item": f"{package.omitted_events} weitere Ereignisse sind nicht im Evidenz-Paket enthalten",
                "why_relevant": "Für eine vollständige Bewertung die Timeline des Falls prüfen.",
            }
        )
    if any(r.step_id == "COLLECT_ADDITIONAL_LOGS" for r in recommendations):
        missing.append(
            {
                "item": "Ergänzende Quellen (VPN-, Firewall-, EDR-Logs) für den Zeitraum des Falls",
                "why_relevant": "Sie zeigen, ob über die gemeldeten Ereignisse hinaus Aktivität stattfand.",
            }
        )
    ref_of = package.ref_for_event()
    steps = [
        {
            "playbook_step_id": r.step_id,
            "rationale": f"Empfohlen durch {', '.join(r.reason_rules)}.",
            "evidence": [ref_of[e] for e in r.evidence if e in ref_of][:3],
        }
        for r in recommendations
    ]
    return {
        "summary": " ".join(parts),
        "facts": facts,
        "hypotheses": [],
        "missing_information": missing,
        "recommended_steps": steps,
    }
