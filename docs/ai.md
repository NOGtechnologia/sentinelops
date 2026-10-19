# KI-Prinzipien

SentinelOps nutzt KI **nach** der regelbasierten Erkennung, nur zur Zusammenfassung – und
erzwingt technisch, dass sie nichts erfindet. Entscheidung und Schnittstelle:
[ADR-0007](adr/0007-ki-anbieter.md).

## Grundsätze

1. **Regeln vor KI.** Alarme, Fälle und Prioritäten entstehen deterministisch. Die KI sieht erst
   den fertigen Fall.
2. **Optional.** Ohne KI erzeugt SentinelOps eine deterministische Vorlagen-Zusammenfassung aus
   Fakten, Alarmen und Priorität. Jede Funktion bleibt nutzbar (Abnahmetest A8).
3. **Nur Belege.** Die KI erhält ausschließlich das Evidenz-Paket des Falls: nummerierte Belege
   `E1…En` (normalisierte Felder + gekürzte Rohzeile), Alarme mit Regelbeschreibung, Priorität mit
   Faktoren, Entitäten, Playbook-Katalog. Kein Datenbank-, Werkzeug- oder Netzwerkzugriff.
4. **Logdaten sind Daten.** Der Prompt (`case-summary/1`) stellt alle Anweisungen **vor** die
   klar abgegrenzten Daten und erklärt, dass Inhalte darin nie Anweisungen sind.
5. **Mensch entscheidet.** Die KI kann keine Maßnahmen auslösen; Empfehlungen sind Vorschläge aus
   dem Playbook-Katalog, Maßnahmen brauchen eine Freigabe.

## Ausgabeformat

```json
{
  "summary": "string",
  "facts":        [{"statement": "string", "evidence": ["E3", "E7"]}],
  "hypotheses":   [{"statement": "string", "confidence": "low|medium|high",
                    "evidence": ["E12"], "would_confirm": "string"}],
  "missing_information": [{"item": "string", "why_relevant": "string"}],
  "recommended_steps":   [{"playbook_step_id": "VERIFY_ACCOUNT_ACTIVITY",
                           "rationale": "string", "evidence": ["E51"]}]
}
```

## Validator (`ai/validator.py`, 100 % Coverage)

| Prüfung | Folge bei Verstoß |
|---|---|
| Ungültiges JSON oder Schema-Verletzung | gesamte Ausgabe verworfen, Vorlage wird angezeigt |
| Fakt ohne Beleg oder mit unbekannter Beleg-ID | Aussage verworfen |
| IP-Adressen, Domains, Hashes, Benutzer- und Hostnamen, die nicht im Evidenz-Paket vorkommen | Aussage verworfen („unbelegt entfernt“) |
| Empfohlener Schritt außerhalb des Playbook-Katalogs | Schritt verworfen |
| Behauptung, eine Maßnahme sei durchgeführt („Konto wurde gesperrt“), ohne Freigabe/Ausführung | Aussage verworfen |

Verworfene Aussagen bleiben mit Grund gespeichert und sind in der UI und im Bericht sichtbar.

## Prompt-Injection

Logdaten werden auf typische Anweisungsmuster an KI-Systeme geprüft (z. B. „ignore previous
instructions“, Rollenwechsel, Systemprompt-Imitate). Treffer erscheinen als eigener Hinweis im
Fall – unabhängig davon, ob eine KI konfiguriert ist – und der Inhalt wird weiterhin nur als Daten
behandelt. Szenario 10 des Generators enthält solche Fälle.

## Anbieter

| `SENTINELOPS_LLM_PROVIDER` | Beschreibung | Daten verlassen das Haus? |
|---|---|---|
| `none` (Standard) | Vorlagen-Zusammenfassung | nein |
| `mock` | **Demo-Simulation, kein Modell:** baut aus dem Evidenz-Paket belegte Fakten und regelbasierte Hypothesen (Demo, Screenshots); in UI und Bericht als „Demo-Simulation“ gekennzeichnet. In Tests zusätzlich mit bösartigen Antworten | nein |
| `ollama` | lokales Modell über Ollama-kompatible API (`SENTINELOPS_LLM_BASE_URL`, `SENTINELOPS_LLM_MODEL`) | nein |
| `openai` | OpenAI-kompatibler Endpunkt | **ja** – nur mit `SENTINELOPS_LLM_CLOUD_OPT_IN=true` |
| `anthropic` | Claude über das offizielle SDK (Standardmodell `claude-opus-5-5`) | **ja** – nur mit Opt-in |

Bei Cloud-Anbietern ist die **Pseudonymisierung** standardmäßig aktiv
(`SENTINELOPS_LLM_PSEUDONYMIZE=true`): Benutzer-, Host- und IP-Werte werden vor dem Versand durch
`USER_n`, `HOST_n`, `IP_n` ersetzt und in der Antwort zurückübersetzt.

## Speicherung und Reproduzierbarkeit

Jede Zusammenfassung wird mit Hash des Evidenz-Pakets, Anbieter, Modell, `prompt_version`,
Parametern und Validierungsergebnis versioniert gespeichert. Berichte verwenden die gespeicherte
Version. Eine neue Version entsteht nur auf ausdrückliche Anforderung (Rolle mit `ai:generate`),
die alte bleibt erhalten; jeder KI-Aufruf steht im Audit-Log.

## Tests

- Kein echtes Modell in der CI: Mock-Anbieter mit Pflichtfällen – erfundene IP, erfundener Hash,
  nicht existierende Beleg-ID, Fakt ohne Beleg, Schritt außerhalb des Katalogs, ungültiges JSON,
  „Konto wurde gesperrt“ ohne Freigabe (A6, `tests/unit/test_ai.py`).
- Architekturregel: `sentinelops.ai` importiert nichts aus `sentinelops.response`.
- Optionale nächtliche Evaluation mit echtem Modell nur bei konfiguriertem Secret (kein Gate).
