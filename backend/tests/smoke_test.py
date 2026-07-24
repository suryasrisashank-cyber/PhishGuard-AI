import sys
import requests

BASE = "http://127.0.0.1:8000"

endpoints = [
    ("/health", 200),
    ("/docs", 200),
    ("/api/dashboard/stats", 200),
    ("/api/dashboard/recent", 200),
]

failed = []
for path, expected in endpoints:
    url = BASE + path
    try:
        r = requests.get(url, timeout=5)
        if r.status_code != expected:
            failed.append((path, r.status_code, r.text[:200]))
        else:
            print(f"OK: {path} -> {r.status_code}")
    except Exception as e:
        failed.append((path, "EXC", str(e)))

if failed:
    print("Smoke tests failed for:")
    for f in failed:
        print(f)
    sys.exit(2)

print("All smoke checks passed.")
