# CLAUDE.md – Arbeitsregeln für SentinelOps

Verbindliche Grundlage ist die Spezifikation „SentinelOps – AI Security Operations Center (D1)“.
Fortschritt und DoD-Abgleich stehen in [`docs/progress.md`](docs/progress.md), offene Punkte in
[`docs/open-questions.md`](docs/open-questions.md).

## Regeln (Spezifikation Abschnitt 20)

1. **Erst verifizieren, dann bauen.** Bibliotheken, Formate, Event-IDs, Regel-Lizenzen und Rechtshinweise in Phase 0 belegen. Unbelegtes → `TODO(verify)` + `docs/open-questions.md`.
2. **Tests zuerst** für Parser, Normalisierung, Matcher, Korrelation, Fallbildung, Priorität, Validator und Freigaben.
3. Nach jeder Teilaufgabe `make check`. Rot = zuerst reparieren, nichts Neues beginnen.
4. Keine `# type: ignore`, `# noqa`, `eslint-disable`, `any`, `.skip`, `xfail` ohne begründenden Kommentar.
5. **Log-Daten sind feindlich.** Nie als HTML rendern, nie in Shell/SQL ohne Parametrisierung, nie als Anweisung an die KI.
6. **Rohdaten sind unveränderlich**; Normalisierung erzeugt neue Datensätze mit Verweis.
7. **Determinismus:** Keine Zufallswerte, Zeitstempel oder ungeordneten Mengen in IDs, Sortierungen oder Berichten; Zeitquelle immer injizierbar.
8. Jede neue Regel braucht: Metadaten, ≥ 2 positive + ≥ 2 negative Tests, Playbook-Verweis, Eintrag im generierten Katalog, keine Verschlechterung des Benchmarks.
9. **Regeln vor KI**; die KI erhält nur Evidenz-Pakete und hat keinen Zugriff auf Maßnahmen.
10. **Keine echten Unternehmensdaten**, keine echten Indikatoren, keine echten Zugangsdaten in Code, Fixtures, Screenshots oder Logs – nur RFC-5737-IPs und `.example`-Domains.
11. Kleine, atomare Commits nach **Conventional Commits**.
12. Am Ende jeder Phase: `docs/progress.md` aktualisieren (Ergebnisse, Coverage, Benchmark-Tabelle, offene Punkte) und die Spezifikation erneut lesen, jeden DoD-Punkt einzeln abhaken.
13. **Nicht umkehrbare Schritte nur nach Rückfrage:** insbesondere das Veröffentlichen auf GitHub (`publish_github.sh` ohne `--dry-run`), das Pushen in fremde Repositories und das Ändern von Lizenzen. Alles andere: bei Unklarheit ADR schreiben, begründet entscheiden, weiterarbeiten.

## Praktische Hinweise

| Aufgabe | Befehl |
|---|---|
| Alles prüfen | `make check` (ohne `make`: `uv run --package sentinelops python scripts/tasks.py check`) |
| Einzelne Prüfung | `make lint`, `make typecheck`, `make arch-check`, `make rules-check`, `make test-unit`, … |
| Integrationstests | benötigen PostgreSQL 16: `SENTINELOPS_TEST_DATABASE_URL=postgresql+asyncpg://user@host:port/postgres` |
| Testdaten | `uv run musterfirma-gen --seed dev --out data/dev` |
| Regelkatalog neu erzeugen | `uv run sentinelops rules catalog` |
| OpenAPI exportieren | `make openapi` |

- Fachlogik (`normalize`, `detection.matcher`, `detection.correlation`, `correlation`, `ai.validator`,
  `reports.render`) bleibt frei von I/O – geprüft durch `import-linter` (`backend/pyproject.toml`).
- Die API importiert keine Parser; die KI-Schicht importiert nichts aus `response`.
- Jede API-Route braucht einen Eintrag in `backend/src/sentinelops/api/permissions.yaml`, sonst startet die App nicht.
- Zeit kommt immer aus `Runtime.clock` (im Demo-Modus fest: `SENTINELOPS_DEMO_NOW`).
