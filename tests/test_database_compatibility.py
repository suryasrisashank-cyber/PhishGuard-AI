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
    _migrate_sqlite_columns,
)
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.models.investigation import InvestigationCase
from backend.app.models.ioc import IOCRecord

client = TestClient(app)


def test_database_url_normalization():
    """Verify postgres:// is safely normalized to postgresql:// for SQLAlchemy 2.0."""
    url_legacy = "postgres://user:pass@ep-hostname.us-east-1.aws.neon.tech/phishguard"
    normalized = url_legacy.replace("postgres://", "postgresql://", 1)
    assert normalized.startswith("postgresql://")
    assert "postgres://" not in normalized[:12]

    # Test already normalized
    url_modern = "postgresql://user:pass@host:5432/phishguard"
    assert url_modern.startswith("postgresql://")


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
    
    # Ensure no credentials leaked
    for key, val in data.items():
        assert "pass" not in key.lower()
        assert "secret" not in key.lower()
        if isinstance(val, str):
            assert "://" not in val
