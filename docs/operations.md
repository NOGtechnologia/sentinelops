# Betrieb

## Schnellstart (Demo)

```bash
git clone https://github.com/<owner>/sentinelops.git && cd sentinelops
cp .env.example .env
docker compose -f deploy/docker-compose.yml --env-file .env up -d --build
```

Danach <http://localhost:8080> öffnen. Im **Demo-Modus** (`SENTINELOPS_DEMO_MODE=true`) lädt der
Stack die Musterfirma-Daten (Seed `dev`), die Uhr steht fest auf `SENTINELOPS_DEMO_NOW`, und die
Anmeldeseite bietet Demo-Benutzer je Rolle an. **Demo-Zugänge funktionieren nur im Demo-Modus.**

## Dienste

| Dienst | Aufgabe | Port |
|---|---|---|
| `api` | FastAPI + ausgelieferte Web-App | 8080 |
| `worker` | Jobs (Ingestion, Analyse, Aufbewahrung), Drop-Folder, optional Syslog | 5514/udp+tcp (optional) |
| `db` | PostgreSQL 16 | intern |
| `keycloak` | OIDC-Anbieter (Realm `sentinelops`) | 8081 |

Alle Container laufen als Nicht-root-Benutzer mit schreibgeschütztem Root-Dateisystem und
entzogenen Capabilities.

## Konfiguration (Umgebungsvariablen)

| Variable | Standard | Bedeutung |
|---|---|---|
| `SENTINELOPS_DATABASE_URL` | – | `postgresql+asyncpg://…` |
| `SENTINELOPS_DEMO_MODE` / `SENTINELOPS_DEMO_NOW` | `false` / – | Demo-Modus, feste Uhrzeit |
| `SENTINELOPS_DISPLAY_TZ` | `Europe/Berlin` | Anzeigezeitzone |
| `SENTINELOPS_OIDC_ISSUER` / `_AUDIENCE` / `_ROLES_CLAIM` | – / `sentinelops` / `realm_access.roles` | OIDC |
| `SENTINELOPS_FOUR_EYES` | `true` | Vier-Augen-Prinzip für Maßnahmen und Ausnahmen |
| `SENTINELOPS_APPROVAL_SECRET` | – (Pflicht außerhalb Demo) | HMAC-Schlüssel für Freigaben |
| `SENTINELOPS_LLM_PROVIDER` | `none` | siehe [KI](ai.md) |
| `SENTINELOPS_LLM_BASE_URL` / `_MODEL` / `_API_KEY` | – | Anbieterzugang |
| `SENTINELOPS_LLM_CLOUD_OPT_IN` / `_PSEUDONYMIZE` | `false` / `true` | Cloud-Freigabe, Pseudonymisierung |
| `SENTINELOPS_DROP_FOLDER` / `_DROP_FOLDER_TZ` | – / `UTC` | überwachter Ordner |
| `SENTINELOPS_SYSLOG_PORT` / `_SYSLOG_HOST` / `_SYSLOG_TZ` | – / `0.0.0.0` / `UTC` | Syslog-Empfänger (aus, wenn kein Port) |
| `SENTINELOPS_RETENTION_EVENTS_DAYS` | `90` | Aufbewahrung Events (0 = unbegrenzt) |
| `SENTINELOPS_RETENTION_RAW_DAYS` | `90` | Aufbewahrung Rohzeilen |
| `SENTINELOPS_RETENTION_CLOSED_CASES_DAYS` | `365` | Aufbewahrung abgeschlossener Fälle |
| `SENTINELOPS_RETENTION_JOBS_DAYS` | `30` | Aufbewahrung erledigter Jobs |
| `SENTINELOPS_RULES_DIR` | `rules/` | Regelverzeichnis |

Die Admin-Ansicht (`GET /api/v1/admin/settings`) zeigt die wirksame Konfiguration ohne Geheimnisse.

## Daten einspielen

- **Upload** in der Oberfläche oder `POST /api/v1/uploads` (Rolle mit `ingest:write`).
- **Bulk-API:** `POST /api/v1/ingest/{source_type}` mit Ingest-Token
  (`Authorization: Bearer soi_…`), NDJSON oder Text, optional `Content-Encoding: gzip`.
  Tokens legt die Administration an; gespeichert wird nur der Hash.
- **Drop-Folder:** Datei in `<ordner>/<quelltyp>/` ablegen, z. B. `syslog_3164/auth.log` oder
  `json@musterfirma_vpn/vpn.ndjson` (`@` steht für `:`). Unbekannte Quelltypen landen mit
  Fehlertext in `<ordner>/failed/`.
- **Syslog:** UDP und TCP (RFC 6587, Octet-Counting oder Zeilenende) auf
  `SENTINELOPS_SYSLOG_PORT` (z. B. 5514). RFC 5424 wird automatisch erkannt, sonst RFC 3164.
  Nachrichten werden in Batches (5.000 oder 5 s) importiert.

Erneuter Import derselben Datei ist idempotent. Fehlerhafte Datensätze stehen in der
Quarantäne (Datenqualität) und können nach Korrektur eines Mapping-Profils neu verarbeitet werden.

## Aufbewahrung

Der Worker reiht täglich einen Aufbewahrungs-Job ein; manuell: `sentinelops retention [--dry-run]`.

- Events werden tageweise (UTC-Partitionen) gelöscht – nie Tage mit Events eines **offenen** Falls.
- Rohzeilen werden frühestens zusammen mit ihrem Event gelöscht.
- Abgeschlossene Fälle (`resolved_*`) werden mit Alarmen, Notizen, KI-Zusammenfassungen,
  Maßnahmen, Freigaben und Berichtsdatensätzen gelöscht, sobald ihre Frist abgelaufen ist **und**
  ihre Events gelöscht sind.
- Jeder Lauf erzeugt einen Audit-Eintrag mit Zählern.
- Das **Audit-Log** wird von der Anwendung nie gelöscht. Für die Archivierung: regelmäßig
  exportieren (`GET /api/v1/audit` als Auditor) und auf unveränderlichem Speicher ablegen; das
  Kürzen erfordert Datenbank-Administration außerhalb der Anwendung.

## Sicherung und Wiederherstellung

```bash
docker compose -f deploy/docker-compose.yml exec db pg_dump -U sentinelops -Fc sentinelops > sentinelops.dump
docker compose -f deploy/docker-compose.yml exec -T db pg_restore -U sentinelops -d sentinelops --clean --if-exists < sentinelops.dump
```

Nach der Wiederherstellung prüft `GET /api/v1/audit?verify=true` die Hash-Kette des Audit-Logs.
Die Regeln liegen im Repository bzw. Image; Laufzeitänderungen (aktiv/inaktiv, Ausnahmen) sind
in der Datenbank gesichert.

Dieser Ablauf ist automatisch getestet (`backend/tests/integration/test_backup_restore.py`):
Sicherung mit `pg_dump -Fc`, Wiederherstellung in eine leere Datenbank, danach identische
Zählerstände, gültige Hash-Kette und weiterhin unveränderliches Audit-Log.

## Migrationen

`sentinelops migrate` (beim Start des `api`-Containers), Rückbau: `sentinelops migrate --down`.
Migrationen werden in der CI hoch und runter getestet.

## Überwachung

- `GET /api/v1/health` (Datenbank erreichbar), `GET /api/v1/version`.
- Datenqualität: Importläufe mit Zählern `accepted`/`duplicate`/`malformed` und Dauer.
- Logs der Container auf stdout (JSON-fähig über Uvicorn-Logkonfiguration).

## Härtung

- TLS terminiert ein vorgeschalteter Reverse-Proxy; HSTS wird von der API gesetzt.
- Strikte CSP, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.
- Rate-Limits für Anmeldung, Upload und Ingest-API; Upload-Limit 512 MiB je Datei.
- `SENTINELOPS_APPROVAL_SECRET` und Datenbankpasswort als Secrets bereitstellen, nie im Image.
- OWASP-ASVS-Level-2-Abdeckung: [ASVS-Checkliste](security/asvs.md).
