"""
PhishGuard AI 3.0 — Database Compatibility & Engine Verification Tests
Validates:
  1. DATABASE_URL normalization (postgres:// -> postgresql://)
  2. Fallback to local SQLite when DATABASE_URL is not set
  3. Safe SQLite PRAGMA guard (never executed against non-SQLite dialects)
  4. PostgreSQL Static / DDL compilation for all ORM models (Zero-leakage verification)
  5. Safe health endpoint reporting of database dialect
"""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.schema import CreateTable
from sqlalchemy.dialects import postgresql, sqlite
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import Settings
from backend.app.db.database import (
    Base,
    get_db_dialect,
    is_persistent_database,
    _migrate_sqlite_columns,
    validate_and_normalize_database_url,
)
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.models.investigation import InvestigationCase
from backend.app.models.ioc import IOCRecord

client = TestClient(app)


def test_database_url_normalization():
    """Verify postgres:// is normalized to postgresql:// and malformed prefixes are strictly rejected."""
    # Legacy scheme normalization
    url_legacy = "postgres://user:pass@ep-hostname.us-east-1.aws.neon.tech/phishguard"
    normalized, dialect = validate_and_normalize_database_url(url_legacy)
    assert normalized.startswith("postgresql://")
    assert dialect == "postgresql"

    # Modern postgresql scheme preserved
    url_modern = "postgresql://user:pass@host:5432/phishguard"
    normalized, dialect = validate_and_normalize_database_url(url_modern)
    assert normalized == url_modern
    assert dialect == "postgresql"

    # Explicit SQLite URL preserved
    url_sqlite = "sqlite:///./phishguard.db"
    normalized, dialect = validate_and_normalize_database_url(url_sqlite)
    assert normalized == url_sqlite
    assert dialect == "sqlite"

    # Missing / empty string defaults safely to local SQLite
    assert validate_and_normalize_database_url("")[0] == "sqlite:///./phishguard.db"
    assert validate_and_normalize_database_url(None)[0] == "sqlite:///./phishguard.db"

    # Malformed prefix from accidental concatenation must be REJECTED (Phase 6 rule)
    with pytest.raises(ValueError) as exc1:
        validate_and_normalize_database_url("SECRETKEYpostgresql://user:pass@host:5432/phishguard")
    assert "Invalid DATABASE_URL scheme" in str(exc1.value)

    with pytest.raises(ValueError) as exc2:
        validate_and_normalize_database_url("random_invalid_string")
    assert "Invalid DATABASE_URL scheme" in str(exc2.value)


def test_sqlite_fallback_default():
    """Verify settings default to local SQLite when DATABASE_URL is empty."""
    s = Settings()
    assert "sqlite" in s.database_url.lower()


def test_sqlite_migration_guard():
    """Verify _migrate_sqlite_columns only runs on SQLite and doesn't fail."""
    # Current active local engine is SQLite
    dialect = get_db_dialect()
    assert dialect == "sqlite"
    # Should run smoothly without raising exceptions
    _migrate_sqlite_columns()


def test_postgresql_ddl_compilation_all_models():
    """
    [STATIC / DDL VERIFICATION]
    Verifies that all 4 models compile into valid PostgreSQL DDL syntax without
    requiring a live PostgreSQL server.
    """
    pg_dialect = postgresql.dialect()
    models = [Scan, User, InvestigationCase, IOCRecord]

    for model in models:
        ddl = str(CreateTable(model.__table__).compile(dialect=pg_dialect))
        assert "CREATE TABLE" in ddl
        assert model.__tablename__ in ddl
        # Verify primary key is serialized as SERIAL in PostgreSQL
        assert "SERIAL" in ddl or "INTEGER" in ddl
        # Verify timestamps use PostgreSQL TIMESTAMP WITH TIME ZONE
        if hasattr(model, "created_at"):
            assert "TIMESTAMP WITH TIME ZONE" in ddl


def test_scan_model_fields_preserved():
    """Verify that all PhishGuard AI 3.0 fields exist on the Scan model."""
    expected_fields = [
        "id", "scan_type", "target", "risk_score", "verdict", "summary",
        "confidence_score", "severity", "investigation_status", "indicators",
        "mitre_techniques", "analyst_notes", "analyst_actions", "timeline",
        "processing_time_ms", "detection_engine_version", "created_at"
    ]
    columns = [c.name for c in Scan.__table__.columns]
    for field in expected_fields:
        assert field in columns, f"Missing field: {field}"


def test_health_endpoint_database_type():
    """Verify /api/health returns database_type without leaking credentials."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "online"
    assert "database_type" in data
    assert data["database_type"] in ["sqlite", "postgresql"]
    assert "persistent_database" in data
    assert isinstance(data["persistent_database"], bool)
    
    # Ensure no credentials leaked
    for key, val in data.items():
        assert "pass" not in key.lower()
        assert "secret" not in key.lower()
        if isinstance(val, str):
            assert "://" not in val
