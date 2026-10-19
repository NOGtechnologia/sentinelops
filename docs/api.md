# API

REST-API unter `/api/v1`, beschrieben als OpenAPI 3.1: [`api/openapi.json`](api/openapi.json)
(erzeugt mit `make openapi`; die CI prüft Aktualität und Breaking Changes mit `oasdiff`).
Im laufenden System liefert `/api/docs` die interaktive Dokumentation.

## Authentifizierung

| Zugang | Verwendung |
|---|---|
| OIDC-Access-Token (`Authorization: Bearer …`) | Benutzer der Oberfläche; Rollen aus dem Claim `SENTINELOPS_OIDC_ROLES_CLAIM` |
| Demo-Token (`POST /api/v1/auth/demo-login`) | **nur im Demo-Modus** |
| Ingest-Token (`soi_<id>_<secret>`) | ausschließlich `POST /api/v1/ingest/{source_type}`; widerrufbar, gehasht gespeichert |

Zustandsändernde Anfragen mit fremdem `Origin` werden abgelehnt. Jede Route hat einen Eintrag in
`backend/src/sentinelops/api/permissions.yaml`; ohne Eintrag startet die API nicht.

## Rollen und Rechte

Die vollständige, aus `permissions.yaml` generierte Matrix (Rechte je Rolle und Recht je Route)
steht unter [Rollen und Berechtigungen](permissions.md). `ingest:token` ist keiner Rolle zugeordnet:
diese Route akzeptiert ausschließlich Ingest-Tokens.

## Endpunkte (Überblick)

| Bereich | Endpunkte |
|---|---|
| System | `GET /health`, `GET /version`, `GET /auth/config`, `GET /auth/me`, `POST /auth/demo-login` |
| Lagebild | `GET /dashboard` |
| Fälle | `GET /cases`, `PATCH /cases/bulk`, `GET/PATCH /cases/{id}`, `GET /cases/{id}/timeline`, `…/evidence`, `…/graph`, `POST …/notes`, `POST …/merge`, `POST …/split`, `POST /case-merges/{id}/revert` |
| KI | `GET/POST /cases/{id}/ai-summaries` |
| Maßnahmen | `GET/POST /cases/{id}/actions`, `POST /actions/{id}/decision`, `POST /actions/{id}/execute` |
| Berichte | `GET /cases/{id}/report?format=json\|md\|pdf&created_at=…&pseudonymize=true`, `GET /reports/aggregate?format=json\|csv` |
| Alarme | `GET /alerts`, `GET /alerts/{id}`, `POST /alerts/{id}/false-positive` |
| Events | `GET /events`, `GET /events/export.csv`, `GET /events/{id}` |
| Entitäten | `GET /entities` |
| Regeln | `GET /rules`, `GET/PATCH /rules/{id}` |
| Ausnahmen | `GET/POST /exceptions`, `POST /exceptions/{id}/approve` |
| Datenqualität | `GET /quality/summary`, `GET /quality/runs`, `GET /quality/quarantine`, `POST /quality/runs/{id}/reprocess` |
| Ingestion | `POST /uploads` (multipart), `POST /ingest/{source_type}` (Ingest-Token) |
| Audit | `GET /audit?object_id=…&verify=true` |
| Administration | `GET/POST/DELETE /admin/ingest-tokens`, `GET /admin/users`, `GET/POST/DELETE /admin/sources`, `GET /admin/settings`, `POST /admin/analysis` |

## Konventionen

- Zeitangaben ISO 8601 in UTC mit Mikrosekunden (`2026-03-12T09:30:00.000000Z`).
- Listen: `offset`, `limit` (max. 500) und `total`.
- Fehler: `{"detail": "…"}` mit 401/403/404/409/422/429; keine Stacktraces.
- CSV-Exporte sind gegen Formel-Injection geschützt (`=`, `+`, `-`, `@`, Tab, CR am Zellanfang).
- Berichte sind reproduzierbar: `created_at` festlegen ⇒ byte-identisches JSON/Markdown.

## Beispiel: Bulk-Ingestion

```bash
curl -X POST "https://soc.musterfirma.example/api/v1/ingest/json:musterfirma_vpn" \
  -H "Authorization: Bearer $SENTINELOPS_INGEST_TOKEN" \
  -H "Content-Encoding: gzip" --data-binary @vpn.ndjson.gz
```
