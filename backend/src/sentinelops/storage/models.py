"""PostgreSQL data model (spec 12).

The schema itself is created by the Alembic migrations in ``migrations/`` (the
partitioned ``events`` table, triggers and extensions need raw SQL). The
SQLAlchemy tables here describe the same schema for queries.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()

TS = DateTime(timezone=True)

sources = Table(
    "sources",
    metadata,
    Column("source_id", String(64), primary_key=True),
    Column("name", String(200), nullable=False, unique=True),
    Column("source_type", String(64), nullable=False),
    Column("timezone", String(64), nullable=False, server_default="UTC"),
    Column("created_at", TS, nullable=False),
)

ingest_runs = Table(
    "ingest_runs",
    metadata,
    Column("run_id", String(64), primary_key=True),
    Column("source_type", String(64), nullable=False),
    Column("timezone", String(64), nullable=False),
    Column("file_name", String(500), nullable=False),
    Column("file_sha256", String(64), nullable=False, index=True),
    Column("channel", String(32), nullable=False),  # upload | api | drop_folder | syslog | demo
    Column("status", String(32), nullable=False),  # running | completed | skipped_duplicate_file | failed
    Column("accepted", Integer, nullable=False, server_default="0"),
    Column("duplicate", Integer, nullable=False, server_default="0"),
    Column("malformed", Integer, nullable=False, server_default="0"),
    Column("started_at", TS, nullable=False),
    Column("finished_at", TS),
    Column("duration_ms", Integer),
    Column("error", Text),
    Column("created_by", String(200), nullable=False),
)

raw_records = Table(
    "raw_records",
    metadata,
    Column("raw_record_id", String(64), primary_key=True),
    Column("run_id", String(64), ForeignKey("ingest_runs.run_id"), nullable=False, index=True),
    Column("position", Integer, nullable=False),
    Column("byte_offset", BigInteger),
    Column("content", LargeBinary),  # only when the text form would not be lossless
    Column("content_text", Text, nullable=False),
    Column("status", String(16), nullable=False),
    Column("error_code", String(32)),
    Column("error_detail", Text),
    Column("error_position", Integer),
    Column("event_id", String(64)),
    Column("duplicate_of", String(64)),
    Column("created_at", TS, nullable=False),
)

events = Table(
    "events",
    metadata,
    Column("event_id", String(64), primary_key=True),
    Column("ts", TS, primary_key=True),
    Column("day", Date, nullable=False),
    Column("ingested_at", TS, nullable=False),
    Column("source_type", String(64), nullable=False),
    Column("action", String(64)),
    Column("outcome", String(16)),
    Column("code", String(32)),
    Column("user_name", Text),
    Column("user_key", Text),
    Column("target_user", Text),
    Column("host_name", Text),
    Column("host_key", Text),
    Column("source_ip", String(64)),
    Column("raw_record_id", String(64), nullable=False),
    Column("assessment", String(16), nullable=False, server_default="normal"),
    Column("time_quality", String(32)),
    Column("data", JSONB, nullable=False),
)

entities = Table(
    "entities",
    metadata,
    Column("type", String(16), primary_key=True),
    Column("key", Text, primary_key=True),
    Column("display", Text, nullable=False),
    Column("first_seen", TS, nullable=False),
    Column("last_seen", TS, nullable=False),
    Column("privileged", Boolean, nullable=False, server_default="false"),
    Column("critical", Boolean, nullable=False, server_default="false"),
    Column("hub", Boolean, nullable=False, server_default="false"),
    Column("hub_reason", Text),
)

rules = Table(
    "rules",
    metadata,
    Column("rule_id", String(32), primary_key=True),
    Column("current_version", Integer, nullable=False),
    Column("current_hash", String(64), nullable=False),
    Column("title", Text, nullable=False),
    Column("title_de", Text, nullable=False),
    Column("level", String(16), nullable=False),
    Column("maturity", String(16), nullable=False),
    Column("source", String(16), nullable=False),
    Column("kind", String(16), nullable=False),
    Column("active", Boolean, nullable=False, server_default="true"),
    Column("updated_at", TS, nullable=False),
)

rule_versions = Table(
    "rule_versions",
    metadata,
    Column("rule_id", String(32), ForeignKey("rules.rule_id"), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("content_hash", String(64), primary_key=True),
    Column("yaml_text", Text, nullable=False),
    Column("meta", JSONB, nullable=False),
    Column("created_at", TS, nullable=False),
)

rule_exceptions = Table(
    "rule_exceptions",
    metadata,
    Column("exception_id", String(16), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("rule_id", String(32), nullable=False),
    Column("description", Text, nullable=False),
    Column("match", JSONB, nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("approved_by", String(200)),
    Column("expires", Date, nullable=False),
    Column("status", String(16), nullable=False),  # proposed | active | expired | revoked
    Column("created_at", TS, nullable=False),
)

alerts = Table(
    "alerts",
    metadata,
    Column("alert_id", String(64), primary_key=True),
    Column("rule_id", String(32), nullable=False, index=True),
    Column("rule_version", Integer, nullable=False),
    Column("rule_hash", String(64), nullable=False),
    Column("kind", String(16), nullable=False),
    Column("level", String(16), nullable=False),
    Column("maturity", String(16), nullable=False),
    Column("title", Text, nullable=False),
    Column("title_de", Text, nullable=False),
    Column("window_start", TS, nullable=False),
    Column("window_end", TS, nullable=False),
    Column("event_count", Integer, nullable=False),
    Column("data", JSONB, nullable=False),
    Column("suppressed_by", String(16)),
    Column("false_positive", Boolean, nullable=False, server_default="false"),
    Column("false_positive_reason", Text),
    Column("false_positive_by", String(200)),
    Column("created_at", TS, nullable=False),
)

alert_events = Table(
    "alert_events",
    metadata,
    Column("alert_id", String(64), ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", String(64), primary_key=True),
    Column("ts", TS, nullable=False),
)

cases = Table(
    "cases",
    metadata,
    Column("case_id", String(64), primary_key=True),
    Column("title", Text, nullable=False),
    Column("title_de", Text, nullable=False),
    Column("status", String(32), nullable=False),
    Column("priority", String(4), nullable=False),
    Column("score", Integer, nullable=False),
    Column("assignee", String(200)),
    Column("window_start", TS, nullable=False),
    Column("window_end", TS, nullable=False),
    Column("related_case_ids", JSONB, nullable=False),
    Column("tactics", JSONB, nullable=False),
    Column("rule_ids", JSONB, nullable=False),
    Column("recommendations", JSONB, nullable=False),
    Column("injection_findings", JSONB, nullable=False),
    Column("created_at", TS, nullable=False),
    Column("updated_at", TS, nullable=False),
    Column("first_action_at", TS),
    Column("closed_at", TS),
)

case_alerts = Table(
    "case_alerts",
    metadata,
    Column("alert_id", String(64), ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True),
    Column("case_id", String(64), ForeignKey("cases.case_id"), nullable=False, index=True),
    Column("manual", Boolean, nullable=False, server_default="false"),
)

case_entities = Table(
    "case_entities",
    metadata,
    Column("case_id", String(64), ForeignKey("cases.case_id"), primary_key=True),
    Column("type", String(16), primary_key=True),
    Column("key", Text, primary_key=True),
    Column("display", Text, nullable=False),
)

priority_explanations = Table(
    "priority_explanations",
    metadata,
    Column("case_id", String(64), ForeignKey("cases.case_id"), primary_key=True),
    Column("score", Integer, nullable=False),
    Column("level", String(4), nullable=False),
    Column("factors", JSONB, nullable=False),
    Column("computed_at", TS, nullable=False),
)

case_merges = Table(
    "case_merges",
    metadata,
    Column("merge_id", String(64), primary_key=True),
    Column("kind", String(16), nullable=False),  # merge | split
    Column("source_case_id", String(64), nullable=False),
    Column("target_case_id", String(64), nullable=False),
    Column("alert_ids", JSONB, nullable=False),
    Column("actor", String(200), nullable=False),
    Column("created_at", TS, nullable=False),
    Column("reverted_at", TS),
)

notes = Table(
    "notes",
    metadata,
    Column("note_id", String(64), primary_key=True),
    Column("case_id", String(64), ForeignKey("cases.case_id"), nullable=False, index=True),
    Column("author", String(200), nullable=False),
    Column("text", Text, nullable=False),
    Column("created_at", TS, nullable=False),
)

ai_summaries = Table(
    "ai_summaries",
    metadata,
    Column("summary_id", String(64), primary_key=True),
    Column("case_id", String(64), ForeignKey("cases.case_id"), nullable=False, index=True),
    Column("version", Integer, nullable=False),
    Column("evidence_hash", String(64), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("model", String(100), nullable=False),
    Column("prompt_version", String(32), nullable=False),
    Column("validation_status", String(32), nullable=False),
    Column("record", JSONB, nullable=False),
    Column("created_at", TS, nullable=False),
)

actions = Table(
    "actions",
    metadata,
    Column("action_id", String(64), primary_key=True),
    Column("case_id", String(64), ForeignKey("cases.case_id"), nullable=False, index=True),
    Column("step_id", String(64), nullable=False),
    Column("parameters", JSONB, nullable=False),
    Column("proposed_by", String(200), nullable=False),
    Column("proposed_at", TS, nullable=False),
    Column("source", String(16), nullable=False),
    Column("reason", Text, nullable=False),
    Column("status", String(16), nullable=False),
    Column("execution", JSONB),
    Column("updated_at", TS, nullable=False),
)

approvals = Table(
    "approvals",
    metadata,
    Column("action_id", String(64), ForeignKey("actions.action_id"), primary_key=True),
    Column("parameters_hash", String(64), nullable=False),
    Column("decision", String(16), nullable=False),
    Column("approver", String(200), nullable=False),
    Column("reason", Text, nullable=False),
    Column("decided_at", TS, nullable=False),
    Column("signature", String(64), nullable=False),
)

reports = Table(
    "reports",
    metadata,
    Column("report_id", String(64), primary_key=True),
    Column("case_id", String(64), nullable=False, index=True),
    Column("format", String(8), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("metadata", JSONB, nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", TS, nullable=False),
)

users = Table(
    "users",
    metadata,
    Column("subject", String(200), primary_key=True),
    Column("username", String(200), nullable=False),
    Column("display_name", String(200)),
    Column("first_login", TS, nullable=False),
    Column("last_login", TS, nullable=False),
)

role_assignments = Table(
    "role_assignments",
    metadata,
    Column("subject", String(200), ForeignKey("users.subject"), primary_key=True),
    Column("role", String(32), primary_key=True),
)

ingest_tokens = Table(
    "ingest_tokens",
    metadata,
    Column("token_id", String(32), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("created_by", String(200), nullable=False),
    Column("created_at", TS, nullable=False),
    Column("revoked_at", TS),
)

jobs = Table(
    "jobs",
    metadata,
    Column("job_id", BigInteger, primary_key=True, autoincrement=True),
    Column("kind", String(32), nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("status", String(16), nullable=False),  # queued | running | done | failed
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("run_after", TS, nullable=False),
    Column("locked_by", String(100)),
    Column("locked_at", TS),
    Column("created_at", TS, nullable=False),
    Column("finished_at", TS),
    Column("error", Text),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("seq", BigInteger, primary_key=True, autoincrement=True),
    Column("ts", TS, nullable=False),
    Column("actor", String(200), nullable=False),
    Column("action", String(64), nullable=False),
    Column("object_type", String(32), nullable=False),
    Column("object_id", String(200), nullable=False),
    Column("details", JSONB, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("hash", String(64), nullable=False),
)

analysis_state = Table(
    "analysis_state",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("last_run_at", TS),
    Column("ruleset_hash", String(64)),
    Column("config_hash", String(64)),
    Column("learning_users", JSONB),
    Column("hubs", JSONB),
    Column("events_hash", String(64)),
)
