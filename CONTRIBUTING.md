# Mitwirken / Contributing

Danke für Ihr Interesse an SentinelOps! Beiträge sind willkommen – Code, Regeln, Dokumentation,
Fehlermeldungen. Bitte lesen Sie vorab den [Verhaltenskodex](CODE_OF_CONDUCT.md).

> **Keine echten Daten.** In Code, Tests, Regeln, Screenshots und Issues nur synthetische Daten:
> IP-Adressen aus RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) oder privaten
> Netzen, Domains unter `.example`, keine echten Zugangsdaten oder Indikatoren. Die CI prüft das
> (`scripts/check_fixtures.py`, gitleaks).

## Entwicklungsumgebung

Voraussetzungen: Python 3.12 mit [uv](https://docs.astral.sh/uv/), Node.js ≥ 22 mit pnpm 10,
PostgreSQL 16 (z. B. `docker compose -f deploy/docker-compose.dev.yml up -d db`).

```bash
uv sync --all-packages          # Backend, Generator, Werkzeuge
pnpm install                    # Web-App und Playwright
pnpm exec playwright install chromium
```

Wichtige Befehle (unter Windows ohne `make`: `uv run --package sentinelops python scripts/tasks.py <ziel>`):

| Befehl | Zweck |
|---|---|
| `make check` | alle Prüfungen der CI (muss grün sein) |
| `make lint` / `make typecheck` / `make arch-check` | Ruff, mypy strict, ESLint, TypeScript, import-linter |
| `make test-unit` / `make test-integration` | Tests; Integration braucht `SENTINELOPS_TEST_DATABASE_URL` |
| `make test-benchmark` | Erkennungs-Benchmark auf dem Holdout-Datensatz |
| `make e2e` | Playwright (braucht `SENTINELOPS_E2E_ADMIN_URL`, siehe `scripts/e2e_server.py`) |
| `make screenshots` | README-/Doku-Bilder neu erzeugen |
| `make openapi` | OpenAPI-Dokument und TypeScript-Typen neu erzeugen |

Lokal starten: `powershell -File scripts/dev-api.ps1` (Windows) bzw. analog mit
`uv run sentinelops serve` und `pnpm --dir frontend dev`.

## Commits und Pull Requests

- [Conventional Commits](https://www.conventionalcommits.org/de/v1.0.0/): `feat(detection): …`,
  `fix(api): …`, `docs: …`, `test: …`. Kleine, atomare Commits.
- Tests zuerst für Parser, Normalisierung, Matcher, Korrelation, Fallbildung, Priorität, Validator
  und Freigaben.
- Keine `# type: ignore`, `# noqa`, `eslint-disable`, `.skip` ohne begründenden Kommentar.
- Die [PR-Vorlage](.github/PULL_REQUEST_TEMPLATE.md) enthält die Checkliste.
- Architekturentscheidungen als ADR unter `docs/adr/`.

## Eine neue Erkennungsregel beitragen

1. **Regel anlegen** – Sigma-YAML unter `rules/sigma/custom/` (Einzelregel) oder
   `rules/correlations/` (Korrelation). Pflichtmetadaten im Block `sentinelops:`:

   ```yaml
   sentinelops:
     rule_id: SO-AUTH-099        # eindeutig, Schema SO-<BEREICH>-<NNN>
     version: 1                  # bei jeder fachlichen Änderung erhöhen
     title_de: Kurzer deutscher Titel
     description_de: Was erkannt wird und warum.
     playbooks: [VERIFY_ACCOUNT_ACTIVITY]   # Schritte aus backend/src/sentinelops/investigation/playbooks/steps.yaml
   ```

   Außerdem: `level`, `status` (Reifegrad), `tags` mit MITRE-ATT&CK-Taktik und -Technik,
   `falsepositives`. Feldnamen sind die des [kanonischen Schemas](docs/schema.md).
2. **Tests schreiben** – `rules/tests/<regel>.yaml` mit **mindestens 2 positiven** (`expect: alert`)
   und **2 negativen** Fällen (`expect: no_alert`), nur synthetische Events:

   ```yaml
   rule_id: SO-AUTH-099
   cases:
     - name: typischer Treffer
       expect: alert
       start: "2026-03-11T07:02:10Z"
       events:
         - fields: {event.action: account-locked, user.target.name: erika.muster, host.name: dc01}
     - name: ähnliches, aber legitimes Ereignis
       expect: no_alert
       start: "2026-03-11T07:02:10Z"
       events:
         - fields: {event.action: user-enabled, user.target.name: erika.muster}
   ```
3. **Prüfen** – `make rules-check` (Sigma-Validierung mit pySigma und sigma-cli, Metadaten, Tests),
   danach `uv run sentinelops rules catalog` (aktualisiert `docs/detection-catalog.md`) und
   `make test-benchmark`: Precision ≥ 0,90 je Regel, keine Verschlechterung des Benchmarks.
4. **SigmaHQ-Regeln** werden unverändert unter `rules/sigma/sigmahq/` übernommen (DRL 1.1, Herkunft in
   `SOURCE.md`, SentinelOps-Metadaten in `curation.yaml`).

## Fehlalarme melden

Nutzen Sie das Issue-Formular **„Fehlalarm melden“**: Regel-ID und Version, die legitime Aktivität und
ein **synthetisches** Beispiel. In der Oberfläche können Analysten einen Alarm als Fehlalarm markieren
und eine befristete, begründete Ausnahme vorschlagen (Genehmigung durch L2).

## Übersetzungen und Oberfläche

Alle Texte stehen in `frontend/src/i18n/de.json` und `en.json`; `pnpm --dir frontend i18n:check`
prüft Vollständigkeit, ESLint verbietet hart kodierte Texte. Logdaten werden immer als Text
gerendert (kein `dangerouslySetInnerHTML`). Nach UI-Änderungen die Bilder neu erzeugen: Referenz
ist **Linux** (die CI vergleicht pixelgenau, Schriften werden unter Windows/macOS anders geglättet).
Unter Linux genügt `make screenshots`; auf anderen Systemen den PR öffnen – der Workflow
„Screenshots“ lädt die neu gerenderten Bilder als Artefakt `screenshots` hoch, das man nach
`docs/images/` kopiert.

## Lizenz

Mit einem Beitrag stimmen Sie zu, dass er unter der [Apache-2.0-Lizenz](LICENSE) steht.
