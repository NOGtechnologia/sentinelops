# SentinelOps - every target delegates to scripts/tasks.py (works on Linux,
# macOS and Windows; see CONTRIBUTING.md).
TASKS = uv run --package sentinelops python scripts/tasks.py

.PHONY: check lint typecheck arch-check rules-check test-unit test-property test-integration \
        test-acceptance test-benchmark test-frontend build openapi openapi-diff security docs-check \
        e2e screenshots nightly demo up down

check:            ## full quality gate (spec 15.1)
	$(TASKS) check
lint typecheck arch-check rules-check test-unit test-property test-integration test-acceptance \
test-benchmark test-frontend build openapi openapi-diff security docs-check e2e screenshots nightly:
	$(TASKS) $@

demo:             ## generate demo data, ingest and analyse (needs a running database)
	uv run --package sentinelops sentinelops demo-load

up:               ## start the demo stack
	docker compose -f deploy/docker-compose.yml --env-file .env up -d --build

down:
	docker compose -f deploy/docker-compose.yml down
