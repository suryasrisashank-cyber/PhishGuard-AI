import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from ..core.config import settings

logger = logging.getLogger(__name__)

def normalize_database_url(raw_url: str) -> str:
    """
    Sanitize and normalize database connection string:
    1. Strip whitespace.
    2. Extract postgresql:// or postgres:// if prepended by accidental env var concatenation.
    3. Normalize legacy postgres:// to postgresql:// for SQLAlchemy 2.0.
    4. Fall back to local SQLite if scheme is unknown or invalid.
    """
    if not raw_url or not isinstance(raw_url, str):
        return "sqlite:///./phishguard.db"

    clean = raw_url.strip()

    if "postgresql://" in clean:
        clean = clean[clean.find("postgresql://"):]
    elif "postgres://" in clean:
        clean = "postgresql://" + clean[clean.find("postgres://") + len("postgres://"):]

    if not clean.startswith("sqlite") and not clean.startswith("postgresql://"):
        logger.warning(
            f"Unrecognized database scheme in '{clean[:25]}...'. Defaulting to safe SQLite."
        )
        return "sqlite:///./phishguard.db"

    return clean


def create_app_engine(db_url: str):
    """Safely create SQLAlchemy engine with pooling for PostgreSQL or thread-safe config for SQLite."""
    clean_url = normalize_database_url(db_url)
    try:
        if clean_url.startswith("sqlite"):
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
    except Exception as exc:
        logger.error(f"Failed to create database engine for '{clean_url[:25]}...': {exc}. Using SQLite fallback.")
        return create_engine(
            "sqlite:///./phishguard.db",
            connect_args={"check_same_thread": False},
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


def init_db() -> None:
    """
    Bootstrap database schema in an idempotent, non-destructive manner.
    Uses SQLAlchemy Base.metadata.create_all() which issues 'CREATE TABLE IF NOT EXISTS'.
    It will NEVER execute DROP TABLE, DROP DATABASE, or TRUNCATE.
    Existing tables and data are strictly preserved.
    """
    global engine, SessionLocal
    from ..models import user, scan, ioc, investigation  # noqa: F401 — registers models with SQLAlchemy metadata

    try:
        Base.metadata.create_all(bind=engine)
        _migrate_sqlite_columns()
        logger.info(f"PhishGuard AI database initialized (dialect={engine.dialect.name})")
    except Exception as exc:
        logger.error(f"Database init failed on dialect '{engine.dialect.name}': {exc}")
        if engine.dialect.name != "sqlite":
            logger.warning("Falling back to local SQLite database engine...")
            engine = create_engine(
                "sqlite:///./phishguard.db",
                connect_args={"check_same_thread": False},
            )
            SessionLocal.configure(bind=engine)
            Base.metadata.create_all(bind=engine)
            _migrate_sqlite_columns()
            logger.info("PhishGuard AI database initialized with SQLite fallback")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
