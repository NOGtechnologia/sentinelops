# Changelog

Alle nennenswerten Änderungen dieses Projekts. Format nach
[Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionierung nach
[Semantic Versioning](https://semver.org/lang/de/). Ab dem ersten Release pflegt
release-please diese Datei aus den Conventional Commits.

## [1.0.0](https://github.com/NOGtechnologia/sentinelops/compare/v0.9.0...v1.0.0) (2026-10-19)


### Features

* AI integration with validator, response approvals, reports ([e78efa0](https://github.com/NOGtechnologia/sentinelops/commit/e78efa0d301e57be8c2604f61ed770fb6b6fcbe5))
* **ai:** deterministic demo simulator provider (mock), clearly labelled in UI and reports ([0304a84](https://github.com/NOGtechnologia/sentinelops/commit/0304a8439cc2421c8d071d223ffe173756d5dccd))
* **api:** admin views for data sources and effective settings; fix retention case states ([321eb51](https://github.com/NOGtechnologia/sentinelops/commit/321eb51bdc624a61131600b3bcf96db1f5c248aa))
* **api:** FastAPI v1 with OIDC/demo auth, permissions.yaml enforced per route, cases, actions with approvals, reports, ingest, quality, audit; integration tests ([2f82dab](https://github.com/NOGtechnologia/sentinelops/commit/2f82dabadd200159e0bdbbced715a101347ec2de))
* **detection:** rule catalogue V1, rule tests, benchmark, lint and type fixes ([f8d9495](https://github.com/NOGtechnologia/sentinelops/commit/f8d9495d52f855b88ad4495bb7c1645d23155237))
* **ingest:** drop folder and optional syslog receiver (UDP/TCP, RFC 6587 framing) ([f543400](https://github.com/NOGtechnologia/sentinelops/commit/f54340004bd6abcaa0593ad85d9d3143ccd48cfd))
* parsers, normalisation, generator, detection engine and case building (WIP) ([8d547be](https://github.com/NOGtechnologia/sentinelops/commit/8d547bec96dc5aa8c29326909f8604497a62b51f))
* **privacy:** retention per data type and pseudonymized case reports ([aa493f5](https://github.com/NOGtechnologia/sentinelops/commit/aa493f50137931dec34c7bc98c3478c81d1bf28d))
* **storage:** PostgreSQL schema with partitions and append-only audit log, COPY-based ingestion, analysis persistence, job queue, CLI ([b12a9f2](https://github.com/NOGtechnologia/sentinelops/commit/b12a9f2f65bab19fc64d0da742fe03c940d1fb5f))
* **web:** React dashboard with case queue, case detail (overview, timeline, evidence, graph, report), rules, data quality, entities, audit and admin ([83262ea](https://github.com/NOGtechnologia/sentinelops/commit/83262eab0e2710b5a0e13dda9555a3467298212e))


### Bug Fixes

* **api:** dashboard counts only events up to now in the display time zone; typed bulk update ([c13baca](https://github.com/NOGtechnologia/sentinelops/commit/c13baca7076905015d808a7adf1f77bffb4f9181))
* first CI run on main (offline rule validation, Keycloak test, Trivy, E2E isolation) ([#3](https://github.com/NOGtechnologia/sentinelops/issues/3)) ([ff444e1](https://github.com/NOGtechnologia/sentinelops/commit/ff444e1058eabbbfa5ccda8a909c82bbe5f1cb57))

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
