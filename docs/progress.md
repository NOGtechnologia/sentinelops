# Fortschritt und Abschluss-Audit

Stand: 2026-10-18 · Abschluss-Audit von Phase 11 (Spezifikation 18, Arbeitsregel 12).
Die Spezifikation wurde Punkt für Punkt gegen die Implementierung geprüft. Jeder Punkt hat
einen Status:

- ✅ **erfüllt und lokal nachgewiesen** (`make check` bzw. `make e2e` auf der Entwicklungsmaschine)
- ☁️ **erfüllt, Nachweis nur in der CI** – die lokale Umgebung hat kein Docker; der Workflow ist
  angelegt, wurde aber noch nicht auf GitHub ausgeführt, weil noch nichts veröffentlicht ist
- ⏳ **offen** – mit Begründung

## Zusammenfassung

| Bereich | Status |
|---|---|
| Abnahmetests A1–A8 | ✅ alle grün (A4/A7-UI über Playwright) |
| `make check` (15.1) | ✅ grün, lokal vollständig ausgeführt |
| Schwellen aus Abschnitt 15 in der CI | ✅ in `ci.yml`, `e2e.yml`, `nightly.yml`, `screenshots.yml` erzwungen |
| Phasen 0–10 | ✅ DoD erfüllt; Container-/ZAP-/Lastnachweise ☁️ |
| Phase 11 | ✅ bis auf die Veröffentlichung, die **nur nach Bestätigung** erfolgt (Regel 13) |

## Kennzahlen

| Messgröße | Wert | Schwelle |
|---|---|---|
| Backend-Coverage gesamt (Zeilen + Branches) | 94,3 % | ≥ 90 % |
| Kernmodule (`normalize/`, `detection/matcher.py`, `detection/correlation.py`, `correlation/`, `ai/validator.py`, `response/approvals.py`) | 100 % Zeilen + Branches | 100 % |
| Frontend-Coverage (Vitest) | 94,1 % Zeilen, 81,4 % Branches (45 Tests) | ≥ 80 % |
| Backend-Tests (Unit, Property, Integration, Vertrag, Abnahme) | 398 Tests + 108 Schemathesis-Subtests grün; 2 begründet übersprungen (Keycloak-Testcontainers ohne Docker) | alle grün |
| Schemathesis-Vertragstests | 2 Rollen × alle Operationen, keine 5xx, schemakonform | keine 5xx |
| E2E (Chromium, lokal) | 31 Tests + Performance-Test grün | alle grün |
| Timeline mit 5.000 Events | 457 ms | < 2 s |
| 50.000 Events inkl. Erkennung + Fallbildung | Test grün; der gesamte `holdout`-Lauf (166.000 Events) braucht 36,8 s | < 60 s |

## Erkennungs-Benchmark (`holdout`, nie zum Abstimmen verwendet)

Datensatz: Seed `holdout`, 165.972 Events (Szenarien + Normalverhalten); zusätzlich reines
Normalverhalten mit ≥ 50.000 Events. Ausgeführt mit `make test-benchmark`; die CI hängt dieselbe
Tabelle an die Job-Zusammenfassung an.

| Metrik | Wert | Schwelle |
|---|---|---|
| Recall je Angriffsszenario | 1,00 (10/10) | ≥ 0,95 |
| Precision je Regel | 1,00 für alle 13 auslösenden Regeln | ≥ 0,90 |
| Fehlalarm-Fälle auf Normalverhalten P1/P2 | 0 | 0 |
| Fehlalarm-Fälle auf Normalverhalten P3/P4 | 0 | ≤ 5 |
| Fehlalarm-Falle (Szenario 9) | P4 | höchstens P4 |
| Szenarien in genau einem Fall | 100 % | 100 % |
| Duplikate ändern Zählungen (A3) | 0 | 0 |
| Regression gegenüber `main` | keine | ≤ 1 Prozentpunkt |

| Szenario | erkannt | Priorität | Regeln |
|---|---|---|---|
| S01 Brute Force auf ein Konto, erfolglos | ✅ | P3 | SO-AUTH-001 |
| S02 Brute Force mit Erfolg und Aufnahme in Domänen-Admins | ✅ | P1 | SO-AUTH-001, SO-AUTH-003, SO-PRIV-001, SO-PRIV-002 |
| S03 Password Spraying von externer IP | ✅ | P3 | SO-AUTH-002 |
| S04 Ungewöhnliche Anmeldung (neues Netz, 03:00 Uhr) | ✅ | P3 | SO-AUTH-005 |
| S05 Laterale Bewegung eines kompromittierten Kontos | ✅ | P1 | SO-ACC-002, SO-AUTH-006 |
| S06 Linux: SSH-Brute-Force, Erfolg, sudo-Missbrauch | ✅ | P1 | SO-AUTH-001, SO-AUTH-003, SO-PRIV-003 |
| S07 Konto angelegt und kurz darauf gelöscht | ✅ | P2 | SO-ACC-001 |
| S08 Sicherheitsprotokoll gelöscht | ✅ | P2 | SIGMAHQ-D99B79D2, SO-DEF-001 |
| S09 Fehlalarm-Falle: viele Tippfehler nach Passwortwechsel | ✅ | P4 | SO-AUTH-007 |
| S10 Prompt-Injection in Benutzername und Kommandozeile | ✅ | P3 | SO-AUTH-001 |

## Abnahmetests Version 1 (Abschnitt 19)

| ID | Test | Status |
|---|---|---|
| A1 | `backend/tests/acceptance/test_acceptance.py::test_a1_failed_logins_grouped` (Szenarien 1/2/3) | ✅ |
| A2 | `test_a2_processing_categories` | ✅ |
| A3 | `test_a3_duplicates_no_double_count` | ✅ |
| A4 | `e2e/a4_false_positive.spec.ts` | ✅ (Chromium lokal; Firefox/WebKit ☁️) |
| A5 | `test_a5_report_reproducible` (zwei frische Datenbanken, JSON/Markdown byte-identisch, PDF-Text identisch) | ✅ |
| A6 | `test_a6_ai_grounding` | ✅ |
| A7 | `test_a7_no_action_without_approval` + `e2e/a7_approval.spec.ts` | ✅ |
| A8 | `test_a8_works_without_llm` | ✅ |

## Phasen – Definition of Done

### Phase 0 – Fundament & Verifikation ✅

- [x] Repo-Gerüst, Makefile (`scripts/tasks.py` als plattformunabhängige Umsetzung), pre-commit, CI, `CLAUDE.md`
- [x] Verifikation pySigma/sigma-cli, EVTX-Bibliotheken, SigmaHQ-Lizenz, Event-IDs, Fixture-Quellen → [data-sources.md](data-sources.md), [ADR-0003](adr/0003-sigma-auswertung.md)
- [x] [threat-model.md](threat-model.md), [privacy.md](privacy.md), [data-sources.md](data-sources.md)
- [x] ADRs 0001–0008 ([Übersicht](adr/index.md))
- [x] Namensprüfung → [open-questions.md](open-questions.md) (Entscheidung offen, siehe unten)

### Phase 1 – Schema, Parser & Ingestion ✅

- [x] 100 % Coverage `normalize/` (durch `scripts/check_coverage.py` erzwungen)
- [x] Golden-File-Tests je Format (`backend/tests/fixtures/golden/`)
- [x] Fuzzing (Hypothesis, beliebige Bytes für alle Parser und Mapping-Profile) ohne Funde; lang im Nightly
- [x] Property „Doppelimport ändert nichts“; A2 grün

### Phase 2 – Testdatengenerator ✅

- [x] Deterministisch (byte-identische Ausgabe bei gleichem Seed, Test), ~50.000 Events/Tag, Ground Truth schema-validiert
- [x] Testdaten enthalten XSS- und Injection-Nutzlasten (`<script>`, `<img onerror>`, `javascript:`) für die XSS-Suite

### Phase 3 – Erkennung ✅

- [x] Regel-Checks 15.3: `sigma check` (sigma-cli) + pySigma-Validierung, ≥ 2 positive/negative Tests je Regel, Metadatenschema, generierter [Katalog](detection-catalog.md) mit Aktualitätsprüfung
- [x] Recall/Precision je Regel auf `holdout` erfüllt (Tabelle oben); A1 grün

### Phase 4 – Fallbildung, Priorität, Timeline, Playbooks ✅

- [x] Alle Benchmark-Schwellen 15.4 erfüllt; A3 grün; Property-Tests Reihenfolgeunabhängigkeit und Monotonie grün
- [x] Verschlechterung gegenüber dem auf `main` committeten Benchmark-Stand um > 1 Prozentpunkt lässt den Lauf scheitern (`backend/tests/benchmark/baseline.json`)

### Phase 5 – API, Auth, Audit ✅

- [x] Schemathesis grün (`backend/tests/contract/`); dabei gefundene 5xx (NUL-Bytes, einzelne Surrogates, riesige Offsets) behoben
- [x] Berechtigungstests für jede Route; Route ohne `permissions.yaml`-Eintrag ⇒ Start schlägt fehl ([permissions.md](permissions.md))
- [x] Audit-Log unveränderlich (Datenbank-Trigger, Test)
- [x] OIDC mit Keycloak: Testcontainers-Test `backend/tests/integration/test_keycloak.py` ☁️ (ohne Docker begründet übersprungen)

### Phase 6 – Frontend ✅

- [x] XSS-Suite grün (`e2e/xss.spec.ts`: kein Skript wird ausgeführt)
- [x] axe auf jeder Seite: 0 „serious/critical“ (`e2e/a11y.spec.ts`)
- [x] Lighthouse-Schwellen ☁️ (`.github/lighthouserc.json`, Job in `e2e.yml`)
- [x] E2E-Kernabläufe und A4 grün; i18n DE/EN ohne fehlende Schlüssel, ESLint verbietet hartkodierte Texte

### Phase 7 – KI-Integration ✅

- [x] 100 % Coverage Validator; alle bösartigen Mock-Fälle abgefangen (A6); ohne KI vollständig nutzbar (A8)
- [x] KI-Ausgabe kann keine Maßnahme auslösen (import-linter-Vertrag + API-Test)

### Phase 8 – Maßnahmen & Freigaben ✅

- [x] „Keine Ausführung ohne gültige Freigabe“ als Unit-, Property-, API- (A7) und E2E-Test

### Phase 9 – Berichte ✅

- [x] A5 grün; CSV-Formel-Injection-Test grün; optionale Pseudonymisierung

### Phase 10 – Leistung & Härtung ✅ / ☁️

- [x] Lasttest-Skript (`scripts/load_test.py`, 1 Mio. Events, ≥ 3.000 Events/s, p95 < 300 ms, Regression > 20 % ⇒ Fehler) ☁️ im Nightly
- [x] Container-Härtung (Non-root, read-only Root-FS, Capabilities gedroppt, gepinnte Digests); Trivy, Hadolint ☁️
- [x] ZAP-Baseline ☁️ (`e2e.yml`, Regeln in `.github/zap-rules.tsv`)
- [x] [ASVS-Checkliste](security/asvs.md), Backup/Restore in [Betrieb](operations.md) mit Test
- [x] Mutationstests (mutmut, Score ≥ 85 %) ☁️ im Nightly

### Phase 11 – GitHub-Vorbereitung & Release ✅ (Veröffentlichung wartet auf Bestätigung)

- [x] Logo, 20 Screenshots (hell/dunkel), Demo-GIF, Social-Preview – alle per `make screenshots` erzeugt; Pixelvergleich `--check` lokal grün; `screenshots.yml` ☁️
- [x] README nach 17.4, Doku-Website (MkDocs Material, `mkdocs build --strict` ohne Warnungen)
- [x] Community-Dateien, Issue-Formulare, PR-Vorlage, CODEOWNERS, Dependabot, Labels, alle Workflows (Actions auf SHA gepinnt)
- [x] `scripts/publish_github.sh --dry-run` erfolgreich
- [x] Frischer Klon + `docker compose up` ☁️ (Compose-Smoke-Test in `e2e.yml`)
- [ ] **Veröffentlichung** – nur nach ausdrücklicher Bestätigung (Regel 13)

## Offene Punkte

1. **Name/Marke „Sentinel“** – Verwechslungsrisiko mit bestehenden Marken, siehe
   [open-questions.md](open-questions.md). Entscheidung vor der Veröffentlichung nötig.
2. **GitHub-Owner** für `publish_github.sh --owner` (ersetzt den Platzhalter `OWNER`).
3. **Erster CI-Lauf auf GitHub:** Alle mit ☁️ markierten Nachweise (Docker/Compose, Keycloak,
   Firefox/WebKit, Lighthouse, ZAP, Trivy, Hadolint, Mutation, 1-Mio.-Lasttest, CodeQL, Scorecard)
   laufen erst nach dem Veröffentlichen. Die visuellen Regressions-Baselines werden einmalig über
   den Workflow „Visual baselines“ unter Linux erzeugt; bis dahin überspringt `e2e/visual.spec.ts`
   begründet.
4. **Rechtliche Verifikation** (`TODO(verify)` in [open-questions.md](open-questions.md)).
5. **Commit-Historie:** 7 frühe Commit-Kopfzeilen sind länger als 100 Zeichen; commitlint prüft
   daher nur neue Commits. Ein Umschreiben der Historie wäre nicht umkehrbar und unterbleibt.
