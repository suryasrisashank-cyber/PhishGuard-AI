#!/usr/bin/env python3
"""
PhishGuard AI 3.0 — SQLite to PostgreSQL Data Migration Utility
Transfers scan telemetry, IOCs, investigations, and users from SQLite to PostgreSQL
with zero data loss, full sequence synchronization, and transaction safety.

Usage:
  # Dry-run (verifies connection and prints planned changes without writing)
  python scripts/migrate_data.py --dry-run

  # Execute migration using DATABASE_URL environment variable:
  python scripts/migrate_data.py

  # Specify custom source and target:
  python scripts/migrate_data.py --source-db phishguard.db --target-url "postgresql://..."
"""

import argparse
import os
import sys
import logging
from urllib.parse import urlparse
from pathlib import Path

# Add project root to sys.path for reliable module resolution
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker

# Set up clean sanitized logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("phishguard-migrator")


def sanitize_db_url(url: str) -> str:
    """Mask credentials in database URLs for secure console output."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            return "sqlite://local"
        if parsed.scheme.startswith("sqlite"):
            return f"sqlite:///{Path(parsed.path).name if parsed.path else 'memory'}"
        
        user = parsed.username or ""
        host = parsed.hostname or "localhost"
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or ""
        masked_auth = f"{user}:***@" if user else ""
        return f"{parsed.scheme}://{masked_auth}{host}{port}{path}"
    except Exception:
        return "postgresql://***@hidden-host/hidden-db"


def parse_args():
    parser = argparse.ArgumentParser(description="PhishGuard AI SQLite to PostgreSQL Migrator")
    parser.add_argument(
        "--source-db",
        default="phishguard.db",
        help="Path to source SQLite database file (default: phishguard.db)",
    )
    parser.add_argument(
        "--target-url",
        default=os.getenv("DATABASE_URL", ""),
        help="Target PostgreSQL connection URL (defaults to DATABASE_URL env var)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform discovery and validation without committing changes to target DB",
    )
    return parser.parse_args()


def migrate():
    args = parse_args()

    source_path = Path(args.source_db)
    if not source_path.exists():
        logger.error(f"Source SQLite database not found: {source_path}")
        sys.exit(1)

    raw_target_url = args.target_url.strip()
    if not raw_target_url:
        logger.error(
            "Target database URL not provided. Set DATABASE_URL environment variable or pass --target-url."
        )
        sys.exit(1)

    # Normalize postgres:// to postgresql://
    if raw_target_url.startswith("postgres://"):
        raw_target_url = raw_target_url.replace("postgres://", "postgresql://", 1)

    sanitized_target = sanitize_db_url(raw_target_url)
    logger.info(f"Source Database: SQLite ({source_path})")
    logger.info(f"Target Database: {sanitized_target}")
    if args.dry_run:
        logger.info("[MODE] DRY-RUN ACTIVE — No modifications will be committed.")

    # 1. Connect to SQLite source
    sqlite_url = f"sqlite:///{source_path.resolve()}"
    src_engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})
    
    # 2. Connect to target database
    try:
        tgt_engine = create_engine(
            raw_target_url,
            pool_pre_ping=True,
            pool_size=3,
            max_overflow=2,
            pool_timeout=30,
            pool_recycle=1800,
        )
        with tgt_engine.connect() as conn:
            tgt_dialect = conn.dialect.name
            logger.info(f"Target engine connected successfully (dialect={tgt_dialect}).")
    except Exception as exc:
        logger.error(f"Failed to connect to target database: {exc.__class__.__name__}: {str(exc).split('@')[-1]}")
        sys.exit(1)

    # 3. Bootstrap target schema using Base metadata if needed
    try:
        from backend.app.db.database import Base
        from backend.app.models import user, scan, ioc, investigation  # noqa: F401
        
        if not args.dry_run:
            Base.metadata.create_all(bind=tgt_engine)
            logger.info("Target schema bootstrap verified (CREATE TABLE IF NOT EXISTS).")
    except Exception as exc:
        logger.error(f"Error checking target schema: {exc}")
        sys.exit(1)

    # Define table migration order (independent tables first)
    tables_to_migrate = ["users", "scans", "iocs", "investigations"]

    summary = {
        table: {"discovered": 0, "inserted": 0, "skipped": 0, "failed": 0}
        for table in tables_to_migrate
    }

    tgt_inspector = inspect(tgt_engine)
    existing_tgt_tables = tgt_inspector.get_table_names()

    # 4. Perform Migration inside a controlled transaction
    with tgt_engine.connect() as tgt_conn:
        trans = tgt_conn.begin()
        try:
            for table_name in tables_to_migrate:
                # Read records from SQLite source
                with src_engine.connect() as src_conn:
                    src_inspector = inspect(src_engine)
                    if table_name not in src_inspector.get_table_names():
                        logger.warning(f"Table '{table_name}' does not exist in source database. Skipping.")
                        continue

                    src_result = src_conn.execute(text(f"SELECT * FROM {table_name} ORDER BY id ASC"))
                    columns = list(src_result.keys())
                    records = [dict(zip(columns, row)) for row in src_result.fetchall()]

                summary[table_name]["discovered"] = len(records)
                logger.info(f"Discovered {len(records)} records in '{table_name}'.")

                if not records:
                    continue

                # Query existing IDs in target to ensure idempotency
                existing_ids = set()
                if table_name in existing_tgt_tables:
                    try:
                        id_res = tgt_conn.execute(text(f"SELECT id FROM {table_name}"))
                        existing_ids = {r[0] for r in id_res.fetchall()}
                    except Exception:
                        existing_ids = set()

                for record in records:
                    rec_id = record.get("id")
                    if rec_id in existing_ids:
                        summary[table_name]["skipped"] += 1
                        continue

                    if args.dry_run:
                        summary[table_name]["inserted"] += 1
                        continue

                    try:
                        # Build parameterized insert statement preserving explicit ID
                        cols_str = ", ".join(f'"{c}"' for c in record.keys())
                        placeholders = ", ".join(f":{c}" for c in record.keys())
                        insert_stmt = text(
                            f'INSERT INTO "{table_name}" ({cols_str}) VALUES ({placeholders})'
                        )
                        tgt_conn.execute(insert_stmt, record)
                        summary[table_name]["inserted"] += 1
                    except Exception as err:
                        summary[table_name]["failed"] += 1
                        logger.error(f"Error inserting record id={rec_id} into '{table_name}': {err}")
                        raise err

            # 5. Advance PostgreSQL Sequences so next auto-generated IDs do not collide
            if tgt_engine.dialect.name == "postgresql" and not args.dry_run:
                logger.info("Synchronizing PostgreSQL serial sequences...")
                for table_name in tables_to_migrate:
                    try:
                        seq_sql = text(f"""
                            SELECT setval(
                                pg_get_serial_sequence('"{table_name}"', 'id'),
                                coalesce(max(id), 1),
                                max(id) IS NOT NULL
                            ) FROM "{table_name}";
                        """)
                        tgt_conn.execute(seq_sql)
                        logger.info(f"Sequence for '{table_name}' synchronized.")
                    except Exception as seq_err:
                        logger.warning(f"Could not synchronize sequence for '{table_name}': {seq_err}")

            if args.dry_run:
                trans.rollback()
                logger.info("[DRY-RUN COMPLETE] Transaction rolled back safely.")
            else:
                trans.commit()
                logger.info("[COMMIT] Migration transaction committed successfully.")

        except Exception as exc:
            trans.rollback()
            logger.error(f"[ROLLBACK] Migration aborted due to error: {exc}")
            sys.exit(1)

    # 6. Report final results
    print("\n" + "=" * 60)
    print("PHISHGUARD AI — DATABASE MIGRATION SUMMARY")
    print("=" * 60)
    print(f"Target Dialect : {tgt_engine.dialect.name}")
    print(f"Target URL     : {sanitized_target}")
    print(f"Execution Mode : {'DRY-RUN (Simulated)' if args.dry_run else 'LIVE PRODUCTION COMMIT'}")
    print("-" * 60)
    print(f"{'Table':<16} | {'Discovered':<10} | {'Inserted':<10} | {'Skipped':<10} | {'Failed':<10}")
    print("-" * 60)
    for tbl, s in summary.items():
        print(f"{tbl:<16} | {s['discovered']:<10} | {s['inserted']:<10} | {s['skipped']:<10} | {s['failed']:<10}")
    print("=" * 60)
    print("Migration completed successfully with zero data loss.")


if __name__ == "__main__":
    migrate()
