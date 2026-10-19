## Was ändert sich?

<!-- Kurz: Was und warum. Verweis auf Issue (Fixes #...). -->

## Checkliste

- [ ] `make check` ist lokal grün (Lint, Typen, Architektur, Regeln, Tests, Coverage, Benchmark, Build, Security, OpenAPI, Doku).
- [ ] Neue/geänderte Logik hat Tests (Parser, Normalisierung, Matcher, Korrelation, Fallbildung, Priorität, Validator und Freigaben: Tests zuerst).
- [ ] Neue Regeln: Metadaten, ≥ 2 positive + ≥ 2 negative Tests, Playbook-Verweis, Katalog neu erzeugt (`uv run sentinelops rules catalog`), Benchmark nicht verschlechtert.
- [ ] UI-Änderungen: Screenshots neu erzeugt (`pnpm screenshots`), i18n DE/EN vollständig, axe ohne Befunde.
- [ ] API-Änderungen: `make openapi` ausgeführt, keine unbeabsichtigten Breaking Changes.
- [ ] Dokumentation (`docs/`, ggf. ADR) aktualisiert.
- [ ] **Keine echten Daten:** nur RFC-5737-Adressen, `.example`-Domains, keine echten Zugangsdaten oder Indikatoren.
- [ ] Commits folgen Conventional Commits.
