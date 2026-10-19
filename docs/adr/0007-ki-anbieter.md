# ADR-0007: KI-Anbieter-Schnittstelle

## Kontext

Die KI fasst Fälle zusammen (8). Sie darf nichts erfinden, keine Maßnahmen auslösen und muss
optional sein. Betreiber wollen lokale Modelle (Datenschutz) oder Cloud-Modelle (Qualität).

## Entscheidung

- Schmale Schnittstelle `Provider.complete(prompt) -> text`; Anbieter: `none` (Standard, Vorlage),
  `mock` (deterministisch, Tests/CI inkl. bösartiger Varianten), `ollama` (lokal,
  `/api/chat`), `openai` (beliebige OpenAI-kompatible Endpunkte), `anthropic` (offizielles SDK,
  Standardmodell `claude-opus-5-5`, serverseitige Ablehnungs-Fallbacks).
- Cloud-Anbieter nur mit ausdrücklichem Opt-in (`SENTINELOPS_LLM_CLOUD_OPT_IN=true`);
  Pseudonymisierung ist dann standardmäßig aktiv.
- Eingabe ist ausschließlich das **Evidenz-Paket** (E1…En), Anweisungen stehen vor den klar
  abgegrenzten Daten (Prompt `case-summary/1`), Logdaten werden als Daten deklariert.
- Ausgabe: strukturiertes JSON (Fakten mit Belegen, Hypothesen, fehlende Informationen). Der
  **Validator** verwirft Aussagen ohne gültige Belegreferenz, mit Indikatoren, die nicht in den
  Belegen vorkommen, mit unbekannten Regeln/Techniken oder mit Behauptungen ausgeführter
  Maßnahmen; Verworfenes wird protokolliert und angezeigt.
- Architekturregel: `sentinelops.ai` importiert nichts aus `sentinelops.response`
  (`import-linter`).

## Alternativen

- Tool-/Function-Calling mit Datenbankzugriff: widerspricht 8.1 (nur Evidenz-Pakete).
- Frameworks wie LangChain: zusätzliche Angriffsfläche ohne Nutzen für einen Aufruf.

## Konsequenzen

Ohne KI ist jede Funktion nutzbar (A8); KI-Text ist gekennzeichnet und versioniert
(Anbieter, Modell, Prompt-Version, Evidenz-Hash). Details: [KI-Prinzipien](../ai.md).
