import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from ..core.config import settings

logger = logging.getLogger(__name__)

def validate_and_normalize_database_url(raw_url: str | None) -> tuple[str, str]:
    """
    Validates and normalizes DATABASE_URL according to Phase 6 rules.
    Returns: (clean_url, dialect)

    Supported schemes:
      - postgresql://
      - postgresql+psycopg2://
      - postgres:// (normalized to postgresql://)
      - sqlite:///

    Rules:
    1. If raw_url is missing or empty:
       -> Defaults to local SQLite: 'sqlite:///./phishguard.db' (dialect: 'sqlite')
    2. If raw_url is provided:
       -> Must START with one of the supported schemes.
       -> Do NOT strip arbitrary prefixes (e.g. BAD: SECRETKEYpostgresql://... must raise ValueError).
       -> Normalize postgres:// to postgresql:// for SQLAlchemy 2.0.
       -> If malformed or unsupported scheme, raise ValueError with sanitized error.
       -> Never silently fall back to SQLite when an invalid production DATABASE_URL was provided.
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return "sqlite:///./phishguard.db", "sqlite"

    clean = raw_url.strip()

    # Normalize legacy or alternative driver schemes to standard postgresql://
    if clean.startswith("postgres://"):
        clean = "postgresql://" + clean[len("postgres://"):]
    elif clean.startswith("postgresql+psycopg://"):
        clean = "postgresql://" + clean[len("postgresql+psycopg://"):]

    if clean.startswith("postgresql://") or clean.startswith("postgresql+psycopg2://"):
        return clean, "postgresql"

    if clean.startswith("sqlite:///"):
        return clean, "sqlite"

    # Reject malformed strings without silent fallback to prevent production data loss
    sanitized_prefix = clean[:15]
    raise ValueError(
        f"Invalid DATABASE_URL scheme '{sanitized_prefix}...'. Supported schemes: postgresql://, postgresql+psycopg2://, postgresql+psycopg://, postgres://, sqlite:///"
    )


def create_app_engine(db_url: str):
    """
    Create SQLAlchemy engine with conservative pooling for PostgreSQL or thread-safe config for SQLite.
    Fails loudly on malformed DATABASE_URL to avoid silent data loss in production.
    """
    clean_url, dialect = validate_and_normalize_database_url(db_url)
    if dialect == "sqlite":
        return create_engine(
            clean_url,
            connect_args={"check_same_thread": False},
        )
    else:
        return create_engine(
            clean_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout,
            pool_recycle=settings.db_pool_recycle,
        )


engine = create_app_engine(settings.database_url)
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


def is_persistent_database() -> bool:
    """Return True if connected to persistent PostgreSQL, False if using ephemeral SQLite."""
    return engine.dialect.name == "postgresql"


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
    logger.info(f"PhishGuard AI database initialized (dialect={engine.dialect.name}, persistent={is_persistent_database()})")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
