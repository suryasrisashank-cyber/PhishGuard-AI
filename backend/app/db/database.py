import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from ..core.config import settings

logger = logging.getLogger(__name__)

# Resolve database connection URL (support Render PostgreSQL and SQLite)
raw_db_url = (settings.database_url or "sqlite:///./phishguard.db").strip()
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

if raw_db_url.startswith("sqlite"):
    engine = create_engine(
        raw_db_url,
        connect_args={"check_same_thread": False},
    )
else:
    # Conservative production connection pooling suited for cloud PostgreSQL (e.g. Render / Supabase / Neon)
    engine = create_engine(
        raw_db_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_recycle=settings.db_pool_recycle,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db_dialect() -> str:
    """Return the active database dialect name ('postgresql' or 'sqlite')."""
    return engine.dialect.name


def _migrate_sqlite_columns() -> None:
    """
    Safe SQLite migration: adds new PhishGuard AI columns to the existing
    'scans' table without deleting any existing records.
    Only runs when the active database dialect is SQLite.
    PostgreSQL instances use standard metadata bootstrap and migrations.
    """
    if engine.dialect.name != "sqlite":
        return

    new_columns = [
        ("confidence_score", "REAL"),
        ("severity", "VARCHAR DEFAULT 'INFORMATIONAL'"),
        ("investigation_status", "VARCHAR DEFAULT 'NEW'"),
        ("indicators", "TEXT"),
        ("mitre_techniques", "TEXT"),
        ("analyst_notes", "TEXT"),
        ("analyst_actions", "TEXT"),
        ("timeline", "TEXT"),
        ("processing_time_ms", "REAL"),
        ("detection_engine_version", "VARCHAR DEFAULT '2.0.0'"),
    ]

    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA table_info(scans)"))
        existing_columns = {row[1] for row in result}

        for col_name, col_type in new_columns:
            if col_name not in existing_columns:
                try:
                    conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                    logger.info(f"DB Migration: added column '{col_name}' to scans table")
                except Exception as exc:
                    logger.warning(f"DB Migration: could not add column '{col_name}': {exc}")


def init_db() -> None:
    """
    Bootstrap database schema in an idempotent, non-destructive manner.
    Uses SQLAlchemy Base.metadata.create_all() which issues 'CREATE TABLE IF NOT EXISTS'.
    It will NEVER execute DROP TABLE, DROP DATABASE, or TRUNCATE.
    Existing tables and data are strictly preserved.
    """
    from ..models import user, scan, ioc, investigation  # noqa: F401 — registers models with SQLAlchemy metadata

    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_columns()
    logger.info(f"PhishGuard AI database initialized (dialect={engine.dialect.name})")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
