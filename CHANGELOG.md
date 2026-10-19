# Changelog

Alle nennenswerten Änderungen dieses Projekts. Format nach
[Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/). Ab dem ersten Release pflegt
release-please diese Datei aus den Conventional Commits.

## [1.0.0] – unveröffentlicht

### Hinzugefügt

- Ingestion: Windows EVTX/XML/JSON, Syslog RFC 3164/5424, journald, JSON mit Mapping-Profilen;
  Upload, Bulk-API mit Ingest-Tokens, Drop-Folder, optionaler Syslog-Empfänger (UDP/TCP).
- Normalisierung auf ein ECS-angelehntes Schema, Zeitnormalisierung (Zeitzonen, Zeitumstellung,
  Jahresableitung, Uhrzeitversatz), Duplikaterkennung, Quarantäne mit Fehlercodes.
- Erkennung: 13 eigene Regeln (Sigma, Korrelationen, Abfolge, Baseline), 3 kuratierte SigmaHQ-Regeln,
  Ausnahmen mit Vier-Augen-Genehmigung, Treffererklärungen.
- Fallbildung mit Hub-Unterdrückung, transparente Priorität P1–P4 mit Belegen, Timeline, Playbooks.
- KI-Zusammenfassung (optional; Ollama, OpenAI-kompatibel, Anthropic; Demo-Simulator) mit
  Evidenz-Paket, Validator gegen unbelegte Aussagen, Prompt-Injection-Erkennung, Pseudonymisierung.
- Maßnahmen mit signierter Freigabe, Vier-Augen-Prinzip und Simulations-Connector.
- Berichte (JSON, Markdown, PDF), reproduzierbar; Sammelbericht; CSV mit Formel-Injection-Schutz;
  optionale Pseudonymisierung.
- Web-Oberfläche (DE/EN, dunkel/hell): Lagebild, Fall-Warteschlange, Falldetail mit Timeline, Belegen,
  Entitätsgraph und Bericht, Ereignissuche, Regeln, Datenqualität, Entitäten, Audit-Log, Administration.
- Betrieb: Docker-Image (non-root, read-only), Compose-Stack mit optionalem Keycloak,
  Aufbewahrungsfristen je Datenart, Audit-Log mit Hash-Kette.
- Qualitätssicherung: `make check`, Playwright-E2E (A4, A7, XSS, axe), Benchmark auf Holdout-Daten,
  Nightly mit Lasttest und Mutationstests.
