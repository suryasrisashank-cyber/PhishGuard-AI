import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from ..core.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _migrate_sqlite_columns() -> None:
    """
    Safe SQLite migration: adds new PhishGuard AI 2.0 columns to the existing
    'scans' table without deleting any existing records.
    SQLite supports ALTER TABLE ... ADD COLUMN but not DROP/MODIFY COLUMN.
    """
    if not settings.database_url.startswith("sqlite"):
        return  # Use Alembic for PostgreSQL/MySQL production databases

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
    from ..models import user, scan, ioc, investigation  # noqa: F401 — registers models with SQLAlchemy metadata

    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_columns()
    logger.info("PhishGuard AI database initialized")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
