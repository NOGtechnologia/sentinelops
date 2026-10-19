# Local development: API with the demo database and the built web app (Windows, no Docker).
# Usage: powershell -File scripts/dev-api.ps1 [-Port 8000] [-Database sentinelops_dev] [-PgPort 55440]
param(
    [int]$Port = 8000,
    [string]$Database = "sentinelops_dev",
    [int]$PgPort = 55440
)
$root = Split-Path -Parent $PSScriptRoot
$env:SENTINELOPS_DATABASE_URL = "postgresql+asyncpg://sentinelops@localhost:$PgPort/$Database"
$env:SENTINELOPS_DEMO_MODE = "true"
$env:SENTINELOPS_DEMO_NOW = "2026-03-12T10:30:00+01:00"
$env:SENTINELOPS_STATIC_DIR = Join-Path $root "frontend\dist"
$env:SENTINELOPS_APPROVAL_SECRET = "dev-approval-secret-not-for-production-0000"
$env:SENTINELOPS_INPROCESS_WORKER = "true"
Set-Location (Join-Path $root "backend")
uv run sentinelops serve --host 127.0.0.1 --port $Port
