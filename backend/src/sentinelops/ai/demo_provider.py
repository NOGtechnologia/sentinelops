"""Deterministic demo simulator for the AI summary (``SENTINELOPS_LLM_PROVIDER=mock``).

Not a language model. It builds an answer in the exact output schema from the
evidence package only - facts with evidence references, rule-based hypotheses,
missing information - so demos and screenshots show the complete AI view
without a model and without sending data anywhere. The UI labels it as
"demo simulation". Like every provider output it passes through the validator.
"""

from __future__ import annotations

import json
from typing import Any

from sentinelops.ai.prompts import Prompt

#: rule -> (hypothesis, confidence, what would confirm it); all wording without indicators.
HYPOTHESES: dict[str, tuple[str, str, str]] = {
    "SO-AUTH-003": (
        "Das Kennwort des Kontos wurde vermutlich durch systematisches Ausprobieren erraten.",
        "high",
        "Rückfrage beim Kontoinhaber, ob die erfolgreiche Anmeldung von ihm stammt",
    ),
    "SO-PRIV-001": (
        "Die Aufnahme in die privilegierte Gruppe soll dauerhaften administrativen Zugriff sichern.",
        "medium",
        "Abgleich der Gruppenänderung mit einem genehmigten Änderungsticket",
    ),
    "SO-PRIV-002": (
        "Das Konto nutzt Sonderrechte, die ihm nach der Rollenplanung nicht zustehen.",
        "medium",
        "Prüfung der Berechtigungsanforderung für das Konto",
    ),
    "SO-AUTH-002": (
        "Die Quelle testet ein häufig verwendetes Kennwort gegen viele Konten (Password Spraying).",
        "high",
        "Abgleich der Quelladresse mit Threat-Intelligence und Firewall-Logs",
    ),
    "SO-AUTH-006": (
        "Ein kompromittiertes Konto wird für Anmeldungen an weiteren Systemen genutzt.",
        "medium",
        "Prozess- und Netzwerkdaten der Zielsysteme (EDR) zum gleichen Zeitraum",
    ),
    "SO-DEF-001": (
        "Das Löschen des Sicherheitsprotokolls soll vorherige Aktivitäten verschleiern.",
        "medium",
        "Gesicherte Kopien des Protokolls aus der zentralen Log-Sammlung",
    ),
    "SO-ACC-001": (
        "Ein kurzlebiges Konto wurde für eine einzelne Aktion angelegt, um Spuren zu vermeiden.",
        "low",
        "Änderungsticket oder Freigabe für das Anlegen des Kontos",
    ),
    "SO-AUTH-005": (
        "Die ungewöhnliche Anmeldung stammt nicht vom Kontoinhaber.",
        "low",
        "Rückfrage beim Kontoinhaber zu Ort und Uhrzeit der Anmeldung",
    ),
    "SO-AUTH-001": (
        "Ein Skript oder Gerät mit veraltetem Kennwort verursacht die Fehlversuche.",
        "low",
        "Liste der Dienste und Geräte, die mit diesem Konto angemeldet sind",
    ),
    "SO-PRIV-003": (
        "Ein Benutzer versucht, auf dem Linux-System Root-Rechte zu erlangen.",
        "medium",
        "Shell-Historie und sudo-Protokoll des Benutzers",
    ),
    "SO-AUTH-004": (
        "Die gehäuften Kontosperrungen sind Folge eines Angriffs auf mehrere Konten.",
        "low",
        "Quelladressen der vorausgehenden Fehlanmeldungen",
    ),
}


def demo_responder(prompt: Prompt) -> str:
    package: dict[str, Any] = json.loads(prompt.data)
    alerts: list[dict[str, Any]] = package.get("alerts", [])
    priority: dict[str, Any] = package.get("priority", {})
    catalog = {step["id"] for step in package.get("playbook_catalog", [])}

    facts = [
        {
            "statement": f"{alert.get('title_de') or alert['title']} ({alert['rule_id']}): "
            f"{alert['event_count']} Ereignis(se) zwischen {alert['window_start'][11:19]} und "
            f"{alert['window_end'][11:19]} UTC.",
            "evidence": alert["evidence"][:3],
        }
        for alert in alerts
        if alert.get("evidence")
    ]
    hypotheses = []
    seen: set[str] = set()
    for alert in alerts:
        rule_id = alert["rule_id"]
        if rule_id in HYPOTHESES and rule_id not in seen and alert.get("evidence"):
            seen.add(rule_id)
            statement, confidence, confirm = HYPOTHESES[rule_id]
            hypotheses.append(
                {
                    "statement": statement,
                    "confidence": confidence,
                    "evidence": alert["evidence"][:2],
                    "would_confirm": confirm,
                }
            )
    missing = [
        {
            "item": "VPN-, Firewall- und EDR-Daten für den Zeitraum des Falls",
            "why_relevant": "Sie zeigen, ob die Aktivität über die protokollierten Anmeldungen hinausging.",
        }
    ]
    if package.get("omitted_events"):
        missing.append(
            {
                "item": f"{package['omitted_events']} weitere Ereignisse außerhalb des Evidenz-Pakets",
                "why_relevant": "Für ein vollständiges Bild die Timeline des Falls prüfen.",
            }
        )
    first_refs: list[str] = next((a["evidence"][:1] for a in alerts if a.get("evidence")), [])
    steps = (
        [
            {
                "playbook_step_id": "VERIFY_ACCOUNT_ACTIVITY",
                "rationale": "Die Hypothesen lassen sich am schnellsten mit dem Kontoinhaber klären.",
                "evidence": first_refs,
            }
        ]
        if "VERIFY_ACCOUNT_ACTIVITY" in catalog and first_refs
        else []
    )
    summary = (
        f"Priorität {priority.get('level', '?')} (Score {priority.get('score', '?')}): "
        f"{len(alerts)} Alarm(e) aus {len({a['rule_id'] for a in alerts})} Regel(n). "
        + (
            "Die Abfolge deutet auf einen gezielten Angriff hin; die Hypothesen sind nicht bestätigt."
            if len(hypotheses) > 1
            else "Die Einordnung erfordert eine Rückfrage beim Kontoinhaber."
        )
    )
    return json.dumps(
        {
            "summary": summary,
            "facts": facts,
            "hypotheses": hypotheses,
            "missing_information": missing,
            "recommended_steps": steps,
        },
        ensure_ascii=False,
    )
