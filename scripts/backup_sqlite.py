"""
PhishGuard AI — Pre-Migration Backup & SQLite Data Inspector
Safely creates a timestamped copy of the SQLite database and exports JSON snapshots
of existing records without modifying or deleting anything.
"""
import sqlite3
import shutil
import os
import json
import datetime
from pathlib import Path

BACKUP_DIR = Path("backups")
BACKUP_DIR.mkdir(exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

src_db = Path("phishguard.db")
if src_db.exists():
    backup_db_path = BACKUP_DIR / f"phishguard_backup_{timestamp}.db"
    shutil.copy2(src_db, backup_db_path)
    print(f"[OK] Created SQLite DB copy: {backup_db_path}")

    # Inspect tables and export JSON dump
    conn = sqlite3.connect(src_db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [r[0] for r in cur.fetchall()]
    print(f"[INFO] Discovered tables in local DB: {tables}")
    
    dump_data = {}
    for table in tables:
        cur.execute(f"SELECT * FROM {table}")
        rows = [dict(row) for row in cur.fetchall()]
        dump_data[table] = rows
        print(f"  - Table '{table}': {len(rows)} records")
        
    json_path = BACKUP_DIR / f"phishguard_export_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dump_data, f, indent=2, default=str)
    print(f"[OK] Exported JSON snapshot: {json_path}")
    conn.close()
else:
    print("[INFO] No local phishguard.db found at root.")
