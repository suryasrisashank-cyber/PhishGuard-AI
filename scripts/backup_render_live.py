"""
PhishGuard AI — Live Render Production Snapshot Exporter
Fetches and saves all current records from the live Render API.
"""
import urllib.request
import json
from pathlib import Path

BACKUP_DIR = Path("backups")
BACKUP_DIR.mkdir(exist_ok=True)

BASE_URL = "https://phishguard-backend-880i.onrender.com"

endpoints = {
    "scans": "/api/scans",
    "iocs": "/api/iocs",
    "investigations": "/api/investigations",
    "alerts": "/api/alerts",
    "campaigns": "/api/campaigns",
    "stats": "/api/dashboard/stats",
}

snapshot = {}

for name, path in endpoints.items():
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-Snapshot/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            data = json.loads(res.read().decode("utf-8"))
            snapshot[name] = data
            print(f"[OK] Fetched {name}: {type(data)} with content")
    except Exception as e:
        print(f"[WARN] Could not fetch {name}: {e}")
        snapshot[name] = None

# Also fetch detail for scan #1 if present
try:
    url = f"{BASE_URL}/api/scans/1"
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-Snapshot/1.0"})
    with urllib.request.urlopen(req, timeout=15) as res:
        snapshot["scan_detail_1"] = json.loads(res.read().decode("utf-8"))
        print("[OK] Fetched detailed scan #1")
except Exception as e:
    print(f"[WARN] Could not fetch scan #1 detail: {e}")

out_file = BACKUP_DIR / "render_live_snapshot.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(snapshot, f, indent=2)
print(f"[DONE] Saved live Render snapshot to {out_file}")
