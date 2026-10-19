-- Partitioned events table, extensions, helper functions and triggers (revision 0001).

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE events (
	event_id VARCHAR(64) NOT NULL,
	ts TIMESTAMP WITH TIME ZONE NOT NULL,
	day DATE NOT NULL,
	ingested_at TIMESTAMP WITH TIME ZONE NOT NULL,
	source_type VARCHAR(64) NOT NULL,
	action VARCHAR(64),
	outcome VARCHAR(16),
	code VARCHAR(32),
	user_name TEXT,
	user_key TEXT,
	target_user TEXT,
	host_name TEXT,
	host_key TEXT,
	source_ip VARCHAR(64),
	raw_record_id VARCHAR(64) NOT NULL,
	assessment VARCHAR(16) DEFAULT 'normal' NOT NULL,
	time_quality VARCHAR(32),
	data JSONB NOT NULL,
	PRIMARY KEY (event_id, ts)
) PARTITION BY RANGE (ts);

CREATE INDEX ix_events_ts ON events (ts);
CREATE INDEX ix_events_user_key ON events (user_key);
CREATE INDEX ix_events_host_key ON events (host_key);
CREATE INDEX ix_events_source_ip ON events (source_ip);
CREATE INDEX ix_events_action ON events (action);
CREATE INDEX ix_events_assessment ON events (assessment) WHERE assessment = 'suspicious';

-- Fallback partition: events outside every day partition (e.g. ancient timestamps).
CREATE TABLE events_default PARTITION OF events DEFAULT;

-- One partition per UTC day, created on demand by the ingest layer.
CREATE FUNCTION ensure_event_partition(d DATE) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
	name TEXT := format('events_%s', to_char(d, 'YYYYMMDD'));
BEGIN
	IF to_regclass(name) IS NULL THEN
		EXECUTE format(
			'CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
			-- d::timestamp AT TIME ZONE 'UTC' is UTC midnight independent of the session time zone.
			name, d::timestamp AT TIME ZONE 'UTC', (d + 1)::timestamp AT TIME ZONE 'UTC'
		);
	END IF;
END;
$$;

-- Retention: drop whole day partitions older than the cutoff (spec 12).
CREATE FUNCTION drop_event_partitions_before(cutoff DATE) RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
	part RECORD;
	dropped INTEGER := 0;
BEGIN
	FOR part IN
		SELECT c.relname FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		WHERE p.relname = 'events' AND c.relname ~ '^events_[0-9]{8}$'
		AND to_date(substring(c.relname from 8), 'YYYYMMDD') < cutoff
	LOOP
		EXECUTE format('DROP TABLE %I', part.relname);
		dropped := dropped + 1;
	END LOOP;
	RETURN dropped;
END;
$$;

-- Full text search over raw lines (spec 12): tsvector (word search) instead of
-- pg_trgm - measured 2.4x cheaper to maintain during bulk ingestion (ADR-0006).
-- pg_trgm stays installed for similarity search on entity names.
CREATE INDEX ix_raw_records_fts ON raw_records USING gin (to_tsvector('simple', left(content_text, 4000)));
CREATE INDEX ix_entities_key_trgm ON entities USING gin (key gin_trgm_ops);
CREATE INDEX ix_raw_records_status ON raw_records (status) WHERE status <> 'accepted';
CREATE INDEX ix_alert_events_event_id ON alert_events (event_id);
CREATE INDEX ix_jobs_queue ON jobs (status, run_after) WHERE status = 'queued';
CREATE UNIQUE INDEX ux_ai_summaries_case_version ON ai_summaries (case_id, version);

-- The audit log is append-only: UPDATE, DELETE and TRUNCATE are rejected.
CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	RAISE EXCEPTION 'audit_log is append-only (% not allowed)', TG_OP;
END;
$$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
	FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
	FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

INSERT INTO analysis_state (id) VALUES (1);
