"""Contract tests share the PostgreSQL server fixture of the integration tests."""

from tests.integration.conftest import pg_server

__all__ = ["pg_server"]
