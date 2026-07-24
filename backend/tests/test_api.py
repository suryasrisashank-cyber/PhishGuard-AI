import requests
import time

BASE = "http://127.0.0.1:8000"


def test_health():
    r = requests.get(BASE + "/health", timeout=5)
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_scan_and_list_and_dashboard():
    # create a unique target
    target = "https://example.com/test-scan"
    payload = {"scan_type": "url", "target": target}
    r = requests.post(BASE + "/api/scans/url", json=payload, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data["target"] == target

    # list scans
    r2 = requests.get(BASE + "/api/scans", timeout=5)
    assert r2.status_code == 200
    scans = r2.json()
    assert any(s for s in scans if s.get("target") == target)

    # dashboard stats should reflect at least 1 scan
    r3 = requests.get(BASE + "/api/dashboard/stats", timeout=5)
    assert r3.status_code == 200
    stats = r3.json()
    assert stats["total_scans"] >= 1
