# Rollen und Berechtigungen

<!-- generiert aus backend/src/sentinelops/api/permissions.yaml - nicht von Hand bearbeiten -->

## Rechte je Rolle

| Recht | analyst | senior_analyst | detection_engineer | admin | auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| `actions:decide` |  | ✓ |  |  |  |
| `actions:execute` |  | ✓ |  |  |  |
| `actions:propose` | ✓ | ✓ |  |  |  |
| `actions:read` | ✓ | ✓ |  | ✓ | ✓ |
| `admin:manage` |  |  |  | ✓ |  |
| `ai:generate` | ✓ | ✓ |  |  |  |
| `alerts:false_positive` | ✓ | ✓ |  |  |  |
| `alerts:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `analysis:run` |  |  |  | ✓ |  |
| `audit:read` |  |  |  | ✓ | ✓ |
| `cases:merge` |  | ✓ |  |  |  |
| `cases:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `cases:write` | ✓ | ✓ |  |  |  |
| `dashboard:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `entities:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `events:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `exceptions:approve` |  | ✓ |  |  |  |
| `exceptions:propose` | ✓ | ✓ | ✓ |  |  |
| `exceptions:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ingest:token` |  |  |  |  |  |
| `ingest:write` |  |  |  | ✓ |  |
| `quality:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `quality:reprocess` |  |  | ✓ | ✓ |  |
| `reports:export` | ✓ | ✓ |  |  | ✓ |
| `rules:read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `rules:write` |  |  | ✓ |  |  |

## Routen

| Methode und Pfad | Recht |
|---|---|
| `GET /api/v1/health` | `public` |
| `GET /api/v1/version` | `public` |
| `GET /api/v1/auth/config` | `public` |
| `POST /api/v1/auth/demo-login` | `public` |
| `GET /api/v1/auth/me` | `authenticated` |
| `GET /api/v1/dashboard` | `dashboard:read` |
| `GET /api/v1/cases` | `cases:read` |
| `PATCH /api/v1/cases/bulk` | `cases:write` |
| `GET /api/v1/cases/{case_id}` | `cases:read` |
| `PATCH /api/v1/cases/{case_id}` | `cases:write` |
| `GET /api/v1/cases/{case_id}/timeline` | `cases:read` |
| `GET /api/v1/cases/{case_id}/evidence` | `cases:read` |
| `GET /api/v1/cases/{case_id}/graph` | `cases:read` |
| `POST /api/v1/cases/{case_id}/notes` | `cases:write` |
| `POST /api/v1/cases/{case_id}/merge` | `cases:merge` |
| `POST /api/v1/cases/{case_id}/split` | `cases:merge` |
| `POST /api/v1/case-merges/{merge_id}/revert` | `cases:merge` |
| `GET /api/v1/cases/{case_id}/ai-summaries` | `cases:read` |
| `POST /api/v1/cases/{case_id}/ai-summaries` | `ai:generate` |
| `GET /api/v1/cases/{case_id}/actions` | `actions:read` |
| `POST /api/v1/cases/{case_id}/actions` | `actions:propose` |
| `POST /api/v1/actions/{action_id}/decision` | `actions:decide` |
| `POST /api/v1/actions/{action_id}/execute` | `actions:execute` |
| `GET /api/v1/cases/{case_id}/report` | `reports:export` |
| `GET /api/v1/reports/aggregate` | `reports:export` |
| `GET /api/v1/alerts` | `alerts:read` |
| `GET /api/v1/alerts/{alert_id}` | `alerts:read` |
| `POST /api/v1/alerts/{alert_id}/false-positive` | `alerts:false_positive` |
| `GET /api/v1/events` | `events:read` |
| `GET /api/v1/events/export.csv` | `events:read` |
| `GET /api/v1/events/{event_id}` | `events:read` |
| `GET /api/v1/entities` | `entities:read` |
| `GET /api/v1/rules` | `rules:read` |
| `GET /api/v1/rules/{rule_id}` | `rules:read` |
| `PATCH /api/v1/rules/{rule_id}` | `rules:write` |
| `GET /api/v1/exceptions` | `exceptions:read` |
| `POST /api/v1/exceptions` | `exceptions:propose` |
| `POST /api/v1/exceptions/{exception_id}/approve` | `exceptions:approve` |
| `GET /api/v1/quality/summary` | `quality:read` |
| `GET /api/v1/quality/runs` | `quality:read` |
| `GET /api/v1/quality/quarantine` | `quality:read` |
| `POST /api/v1/quality/runs/{run_id}/reprocess` | `quality:reprocess` |
| `POST /api/v1/uploads` | `ingest:write` |
| `POST /api/v1/ingest/{source_type}` | `ingest:token` |
| `GET /api/v1/audit` | `audit:read` |
| `GET /api/v1/admin/ingest-tokens` | `admin:manage` |
| `POST /api/v1/admin/ingest-tokens` | `admin:manage` |
| `DELETE /api/v1/admin/ingest-tokens/{token_id}` | `admin:manage` |
| `GET /api/v1/admin/users` | `admin:manage` |
| `GET /api/v1/admin/sources` | `admin:manage` |
| `POST /api/v1/admin/sources` | `admin:manage` |
| `DELETE /api/v1/admin/sources/{source_id}` | `admin:manage` |
| `GET /api/v1/admin/settings` | `admin:manage` |
| `POST /api/v1/admin/analysis` | `analysis:run` |
