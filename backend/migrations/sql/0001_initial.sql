-- SentinelOps initial schema (revision 0001). Generated once from the SQLAlchemy
-- metadata at this revision and frozen; later revisions change it with explicit
-- migrations. The partitioned events table, extensions, functions and triggers
-- are defined in 0001_initial_extra.sql.

CREATE TABLE alerts (
	alert_id VARCHAR(64) NOT NULL, 
	rule_id VARCHAR(32) NOT NULL, 
	rule_version INTEGER NOT NULL, 
	rule_hash VARCHAR(64) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	level VARCHAR(16) NOT NULL, 
	maturity VARCHAR(16) NOT NULL, 
	title TEXT NOT NULL, 
	title_de TEXT NOT NULL, 
	window_start TIMESTAMP WITH TIME ZONE NOT NULL, 
	window_end TIMESTAMP WITH TIME ZONE NOT NULL, 
	event_count INTEGER NOT NULL, 
	data JSONB NOT NULL, 
	suppressed_by VARCHAR(16), 
	false_positive BOOLEAN DEFAULT 'false' NOT NULL, 
	false_positive_reason TEXT, 
	false_positive_by VARCHAR(200), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (alert_id)
);

CREATE INDEX ix_alerts_rule_id ON alerts (rule_id);

CREATE TABLE analysis_state (
	id SERIAL NOT NULL, 
	last_run_at TIMESTAMP WITH TIME ZONE, 
	ruleset_hash VARCHAR(64), 
	config_hash VARCHAR(64), 
	learning_users JSONB, 
	hubs JSONB, 
	events_hash VARCHAR(64), 
	PRIMARY KEY (id)
);

CREATE TABLE audit_log (
	seq BIGSERIAL NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	actor VARCHAR(200) NOT NULL, 
	action VARCHAR(64) NOT NULL, 
	object_type VARCHAR(32) NOT NULL, 
	object_id VARCHAR(200) NOT NULL, 
	details JSONB NOT NULL, 
	prev_hash VARCHAR(64) NOT NULL, 
	hash VARCHAR(64) NOT NULL, 
	PRIMARY KEY (seq)
);

CREATE TABLE case_merges (
	merge_id VARCHAR(64) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	source_case_id VARCHAR(64) NOT NULL, 
	target_case_id VARCHAR(64) NOT NULL, 
	alert_ids JSONB NOT NULL, 
	actor VARCHAR(200) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	reverted_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (merge_id)
);

CREATE TABLE cases (
	case_id VARCHAR(64) NOT NULL, 
	title TEXT NOT NULL, 
	title_de TEXT NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	priority VARCHAR(4) NOT NULL, 
	score INTEGER NOT NULL, 
	assignee VARCHAR(200), 
	window_start TIMESTAMP WITH TIME ZONE NOT NULL, 
	window_end TIMESTAMP WITH TIME ZONE NOT NULL, 
	related_case_ids JSONB NOT NULL, 
	tactics JSONB NOT NULL, 
	rule_ids JSONB NOT NULL, 
	recommendations JSONB NOT NULL, 
	injection_findings JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	first_action_at TIMESTAMP WITH TIME ZONE, 
	closed_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (case_id)
);

CREATE TABLE entities (
	type VARCHAR(16) NOT NULL, 
	key TEXT NOT NULL, 
	display TEXT NOT NULL, 
	first_seen TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL, 
	privileged BOOLEAN DEFAULT 'false' NOT NULL, 
	critical BOOLEAN DEFAULT 'false' NOT NULL, 
	hub BOOLEAN DEFAULT 'false' NOT NULL, 
	hub_reason TEXT, 
	PRIMARY KEY (type, key)
);

CREATE TABLE ingest_runs (
	run_id VARCHAR(64) NOT NULL, 
	source_type VARCHAR(64) NOT NULL, 
	timezone VARCHAR(64) NOT NULL, 
	file_name VARCHAR(500) NOT NULL, 
	file_sha256 VARCHAR(64) NOT NULL, 
	channel VARCHAR(32) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	accepted INTEGER DEFAULT '0' NOT NULL, 
	duplicate INTEGER DEFAULT '0' NOT NULL, 
	malformed INTEGER DEFAULT '0' NOT NULL, 
	started_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	finished_at TIMESTAMP WITH TIME ZONE, 
	duration_ms INTEGER, 
	error TEXT, 
	created_by VARCHAR(200) NOT NULL, 
	PRIMARY KEY (run_id)
);

CREATE INDEX ix_ingest_runs_file_sha256 ON ingest_runs (file_sha256);

CREATE TABLE ingest_tokens (
	token_id VARCHAR(32) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	token_hash VARCHAR(64) NOT NULL, 
	created_by VARCHAR(200) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (token_id), 
	UNIQUE (token_hash)
);

CREATE TABLE jobs (
	job_id BIGSERIAL NOT NULL, 
	kind VARCHAR(32) NOT NULL, 
	payload JSONB NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	attempts INTEGER DEFAULT '0' NOT NULL, 
	run_after TIMESTAMP WITH TIME ZONE NOT NULL, 
	locked_by VARCHAR(100), 
	locked_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	finished_at TIMESTAMP WITH TIME ZONE, 
	error TEXT, 
	PRIMARY KEY (job_id)
);

CREATE TABLE reports (
	report_id VARCHAR(64) NOT NULL, 
	case_id VARCHAR(64) NOT NULL, 
	format VARCHAR(8) NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	metadata JSONB NOT NULL, 
	created_by VARCHAR(200) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (report_id)
);

CREATE INDEX ix_reports_case_id ON reports (case_id);

CREATE TABLE rule_exceptions (
	exception_id VARCHAR(16) NOT NULL, 
	version INTEGER NOT NULL, 
	rule_id VARCHAR(32) NOT NULL, 
	description TEXT NOT NULL, 
	match JSONB NOT NULL, 
	created_by VARCHAR(200) NOT NULL, 
	approved_by VARCHAR(200), 
	expires DATE NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (exception_id, version)
);

CREATE TABLE rules (
	rule_id VARCHAR(32) NOT NULL, 
	current_version INTEGER NOT NULL, 
	current_hash VARCHAR(64) NOT NULL, 
	title TEXT NOT NULL, 
	title_de TEXT NOT NULL, 
	level VARCHAR(16) NOT NULL, 
	maturity VARCHAR(16) NOT NULL, 
	source VARCHAR(16) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	active BOOLEAN DEFAULT 'true' NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (rule_id)
);

CREATE TABLE sources (
	source_id VARCHAR(64) NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	source_type VARCHAR(64) NOT NULL, 
	timezone VARCHAR(64) DEFAULT 'UTC' NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (source_id), 
	UNIQUE (name)
);

CREATE TABLE users (
	subject VARCHAR(200) NOT NULL, 
	username VARCHAR(200) NOT NULL, 
	display_name VARCHAR(200), 
	first_login TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_login TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (subject)
);

CREATE TABLE actions (
	action_id VARCHAR(64) NOT NULL, 
	case_id VARCHAR(64) NOT NULL, 
	step_id VARCHAR(64) NOT NULL, 
	parameters JSONB NOT NULL, 
	proposed_by VARCHAR(200) NOT NULL, 
	proposed_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	source VARCHAR(16) NOT NULL, 
	reason TEXT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	execution JSONB, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (action_id), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE INDEX ix_actions_case_id ON actions (case_id);

CREATE TABLE ai_summaries (
	summary_id VARCHAR(64) NOT NULL, 
	case_id VARCHAR(64) NOT NULL, 
	version INTEGER NOT NULL, 
	evidence_hash VARCHAR(64) NOT NULL, 
	provider VARCHAR(32) NOT NULL, 
	model VARCHAR(100) NOT NULL, 
	prompt_version VARCHAR(32) NOT NULL, 
	validation_status VARCHAR(32) NOT NULL, 
	record JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (summary_id), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE INDEX ix_ai_summaries_case_id ON ai_summaries (case_id);

CREATE TABLE alert_events (
	alert_id VARCHAR(64) NOT NULL, 
	event_id VARCHAR(64) NOT NULL, 
	ts TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (alert_id, event_id), 
	FOREIGN KEY(alert_id) REFERENCES alerts (alert_id) ON DELETE CASCADE
);

CREATE TABLE case_alerts (
	alert_id VARCHAR(64) NOT NULL, 
	case_id VARCHAR(64) NOT NULL, 
	manual BOOLEAN DEFAULT 'false' NOT NULL, 
	PRIMARY KEY (alert_id), 
	FOREIGN KEY(alert_id) REFERENCES alerts (alert_id) ON DELETE CASCADE, 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE INDEX ix_case_alerts_case_id ON case_alerts (case_id);

CREATE TABLE case_entities (
	case_id VARCHAR(64) NOT NULL, 
	type VARCHAR(16) NOT NULL, 
	key TEXT NOT NULL, 
	display TEXT NOT NULL, 
	PRIMARY KEY (case_id, type, key), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE TABLE notes (
	note_id VARCHAR(64) NOT NULL, 
	case_id VARCHAR(64) NOT NULL, 
	author VARCHAR(200) NOT NULL, 
	text TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (note_id), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE INDEX ix_notes_case_id ON notes (case_id);

CREATE TABLE priority_explanations (
	case_id VARCHAR(64) NOT NULL, 
	score INTEGER NOT NULL, 
	level VARCHAR(4) NOT NULL, 
	factors JSONB NOT NULL, 
	computed_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (case_id), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE TABLE raw_records (
	raw_record_id VARCHAR(64) NOT NULL, 
	run_id VARCHAR(64) NOT NULL, 
	position INTEGER NOT NULL, 
	byte_offset BIGINT, 
	content BYTEA, 
	content_text TEXT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	error_code VARCHAR(32), 
	error_detail TEXT, 
	error_position INTEGER, 
	event_id VARCHAR(64), 
	duplicate_of VARCHAR(64), 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (raw_record_id), 
	FOREIGN KEY(run_id) REFERENCES ingest_runs (run_id)
);

CREATE INDEX ix_raw_records_run_id ON raw_records (run_id);

CREATE TABLE role_assignments (
	subject VARCHAR(200) NOT NULL, 
	role VARCHAR(32) NOT NULL, 
	PRIMARY KEY (subject, role), 
	FOREIGN KEY(subject) REFERENCES users (subject)
);

CREATE TABLE rule_versions (
	rule_id VARCHAR(32) NOT NULL, 
	version INTEGER NOT NULL, 
	content_hash VARCHAR(64) NOT NULL, 
	yaml_text TEXT NOT NULL, 
	meta JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (rule_id, version, content_hash), 
	FOREIGN KEY(rule_id) REFERENCES rules (rule_id)
);

CREATE TABLE approvals (
	action_id VARCHAR(64) NOT NULL, 
	parameters_hash VARCHAR(64) NOT NULL, 
	decision VARCHAR(16) NOT NULL, 
	approver VARCHAR(200) NOT NULL, 
	reason TEXT NOT NULL, 
	decided_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	signature VARCHAR(64) NOT NULL, 
	PRIMARY KEY (action_id), 
	FOREIGN KEY(action_id) REFERENCES actions (action_id)
);
