"""Initial schema.

Revision ID: 0001
Revises:
Create Date: 2026-10-18
"""

from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"

TABLES_DOWN = (
    "audit_log",
    "approvals",
    "actions",
    "ai_summaries",
    "notes",
    "case_merges",
    "priority_explanations",
    "case_entities",
    "case_alerts",
    "cases",
    "alert_events",
    "alerts",
    "rule_exceptions",
    "rule_versions",
    "rules",
    "entities",
    "events",
    "raw_records",
    "ingest_runs",
    "sources",
    "role_assignments",
    "users",
    "ingest_tokens",
    "jobs",
    "reports",
    "analysis_state",
)


def _statements(name: str) -> list[str]:
    text = (SQL_DIR / name).read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("--")]
    body = "\n".join(lines)
    # Split on statement ends outside of $$ function bodies.
    parts: list[str] = []
    current: list[str] = []
    in_body = False
    for line in body.splitlines():
        current.append(line)
        if line.count("$$") % 2 == 1:
            in_body = not in_body
        if not in_body and line.rstrip().endswith(";"):
            statement = "\n".join(current).strip()
            if statement:
                parts.append(statement)
            current = []
    return parts


def upgrade() -> None:
    for name in ("0001_initial.sql", "0001_initial_extra.sql"):
        for statement in _statements(name):
            op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log")
    op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
    for table in TABLES_DOWN:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS audit_log_immutable()")
    op.execute("DROP FUNCTION IF EXISTS drop_event_partitions_before(DATE)")
    op.execute("DROP FUNCTION IF EXISTS ensure_event_partition(DATE)")
