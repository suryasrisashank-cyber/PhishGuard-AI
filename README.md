# PhishGuard AI 3.0 — Real-World SOC Platform

**Defensive SOC Investigation & Threat Intelligence Platform with Real Security Tool Integrations**

$$\text{DETECT} \longrightarrow \text{INVESTIGATE} \longrightarrow \text{ENRICH} \longrightarrow \text{CLASSIFY} \longrightarrow \text{RESPOND} \longrightarrow \text{REPORT} \longrightarrow \text{SIEM}$$

PhishGuard AI 3.0 is a realistic, defensive Security Operations Center (SOC) investigation platform engineered for Tier-1/Tier-2 analyst workflows, forensic artifact analysis, indicator correlation, and SIEM event indexing.

It serves as the **orchestration and investigation layer** connecting detection modalities (URLs, websites, emails, binary files, PCAP network captures) with threat intelligence feeds, MITRE ATT&CK techniques, and Splunk Enterprise/Cloud.

---

## 🚨 Core Architectural Principles

1. **Defensive Security Only**: Focused entirely on phishing triage, threat detection, indicator extraction, static forensic inspection, and incident containment. No offensive exploitation or campaign generation.
2. **Real Integrations Only — No Mock Telemetry**:
   - Every security tool is classified at runtime as one of: `CONNECTED`, `AVAILABLE`, `NOT CONFIGURED`, `UNAVAILABLE`, or `ERROR`.
   - If an API key or local binary is absent, the system displays `NOT CONFIGURED` or `UNAVAILABLE` rather than fabricating responses.
   - Endpoint `GET /api/system/integrations` provides an unauthenticated, zero-secret diagnostic health check across all 11 security integrations.
3. **Cost-Aware & Accessible**:
   - Works fully out of the box using built-in deterministic heuristic engines, free public feeds (abuse.ch URLhaus, DNS, RDAP/WHOIS), and Python-native offline PCAP analysis (`scapy`).
   - Paid APIs (VirusTotal, AbuseIPDB, AlienVault OTX) and enterprise SIEMs (Splunk) are optional plugins that activate seamlessly when credentials are provided.

---

## 🏛️ System Architecture

```text
                                  PHISHGUARD AI (v3.0)
                                           |
       +-----------------------------------+-----------------------------------+
       |                                   |                                   |
 DETECTION ENGINES                  THREAT ENRICHMENT                      SIEM INTEGRATION
       |                                   |                                   |
 +-----+-----+-----+-----+           +-----+-----+-----+-----+                 |
 |     |     |     |     |           |     |     |     |     |                 |
URL  Email Web  File  PCAP          VT   OTX AbuseIPDB DNS URLhaus           Splunk HEC
 |     |     |     |     |           |     |     |     |     |                 |
 +-----+-----+-----+-----+-----------+-----+-----+-----+-----+-----------------+
                                           |
                                 Normalized IOC Engine
                               (Domain, IP, URL, Hash)
                                           |
                                 Cross-Scan Correlation
                                           |
                                Heuristic Risk Engine
                                           |
                           Confidence Score + Severity Matrix
                                           |
                                 MITRE ATT&CK Mapping
                                           |
                             SOC Case Management Workflow
                        (NEW → TRIAGED → INVESTIGATING → CONTAINED)
                                           |
                            Burp Suite Finding Attachment
                                           |
                             Executive & Technical Reports
```

---

## 🛠️ Real Security Tools Integrated

| Tool / Provider | Integration Method | Role in SOC Workflow | Default Runtime Status |
|---|---|---|---|
| **Splunk Enterprise / Cloud** | HTTP Event Collector (HEC) | Centralized security event indexing, alert correlation, and SPL queries. | `NOT CONFIGURED` (Until HEC URL/Token configured) |
| **VirusTotal** | REST API v3 | Multi-engine URL, domain, IP, and file hash reputation analysis. | `NOT CONFIGURED` (Optional API key) |
| **AbuseIPDB** | REST API v2 | IP address abuse confidence scoring and attack history reports. | `NOT CONFIGURED` (Optional API key) |
| **AlienVault OTX** | Direct REST API | Community threat pulse correlation and targeted malware families. | `NOT CONFIGURED` (Optional API key) |
| **URLhaus (abuse.ch)** | Official Public API | Real-time malicious URL and malware hosting infrastructure lookup. | `CONNECTED` (Free public feed) |
| **DNS Engine (`dnspython`)** | Native DNS Resolver | Passive A, AAAA, MX, TXT (SPF/DMARC), and NS record queries. | `CONNECTED` (Active) |
| **RDAP / WHOIS** | `python-whois` | Domain registrar, lifecycle age, and young domain (<30 days) detection. | `AVAILABLE` (Active) |
| **YARA (`yara-python`)** | Static Rule Compiler | Offline binary signature matching and rule compilation. | `UNAVAILABLE` (If package/rules uninstalled) |
| **tshark (Wireshark CLI)** | Subprocess / CLI | Fast packet capture dissecting and deep protocol parsing. | `UNAVAILABLE` (If Wireshark CLI not on PATH) |
| **PyShark** | Python Wrapper | Programmatic packet dissections backed by tshark. | `UNAVAILABLE` (Requires tshark binary) |
| **Scapy** | Pure Python Engine | Defensive offline PCAP parsing (conversations, DNS, HTTP, ports). | `AVAILABLE` (Installed & active) |
| **Burp Suite** | External Tool Evidence | Manual authorized web testing. Findings attached to investigation cases. | Documented external tool |

---

## 🔒 Security Hardening & Strict SSRF Guard

Server-side URL fetching is protected by multi-layer SSRF validation (`_validate_safe_url_for_fetch`):
- **Loopback Blocking**: `127.0.0.1`, `localhost`, `::1`, `0.0.0.0`.
- **Private Subnets (RFC 1918)**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **Link-Local & Cloud Metadata**: `169.254.169.254` (AWS, GCP, Azure metadata), `169.254.0.0/16`.
- **Internal Suffixes**: `.local`, `.internal`, `.lan`, `.corp`.
- **Protocol Whitelist**: Only `http://` and `https://` permitted; `file://`, `gopher://`, `ftp://` strictly rejected.
- **Pre-Resolution Verification**: Validates resolved IP addresses before initiating HTTP socket requests.

---

## 🚀 Quickstart & Installation

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.11 and 3.14)
- Node.js 18+ & npm

### 2. Backend Setup
```bash
# Clone the repository
git clone https://github.com/suryasrisashank-cyber/PhishGuard-AI.git
cd PhishGuard-AI

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Run FastAPI backend
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Frontend Setup
```bash
cd frontend

# Install node dependencies
npm install

# Start Vite development server
npm run dev
```
Frontend runs at `http://localhost:5173` (or `3000`), proxying to backend at `http://localhost:8000`.

---

## ⚙️ Environment Configuration (`.env`)

```ini
# Database
DATABASE_URL=sqlite:///./phishguard.db

# Frontend API URL
VITE_API_URL=http://127.0.0.1:8000/api

# Security
SECRET_KEY=change-me-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Splunk SIEM (HTTP Event Collector)
SPLUNK_HOST=https://splunk.internal:8088
SPLUNK_HEC_URL=https://splunk.internal:8088
SPLUNK_HEC_TOKEN=your-splunk-hec-token
SPLUNK_INDEX=phishguard
SPLUNK_SOURCETYPE=phishguard:scan
SPLUNK_VERIFY_TLS=true

# Threat Intelligence Providers (Optional)
VIRUS_TOTAL_API_KEY=your-virustotal-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
OTX_API_KEY=your-otx-api-key

# Local Forensics
YARA_RULES_PATH=./rules/phishing.yar
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
```

---

## 📊 Splunk Integration & Verified SPL Searches

PhishGuard normalizes and dispatches security telemetry to Splunk HEC using structured sourcetypes:
- `phishguard:scan` — Detection results across all modalities
- `phishguard:alert` — High & Critical security alerts
- `phishguard:ioc` — Discovered indicators of compromise
- `phishguard:investigation` — Case lifecycle transitions and analyst notes
- `phishguard:pcap` — Network conversation and packet telemetry
- `phishguard:file` — Static binary hashes and string evidence

### Example SPL Queries:

**Critical Phishing Detections:**
```spl
index=phishguard sourcetype="phishguard:scan" severity="CRITICAL"
```

**High-Risk Target Domain Aggregation:**
```spl
index=phishguard sourcetype="phishguard:scan" risk_score>=75 | stats count by target, severity | sort - count
```

**MITRE ATT&CK Technique Distribution:**
```spl
index=phishguard sourcetype="phishguard:scan" | stats count by mitre_techniques{}
```

**Detection Velocity Over Time:**
```spl
index=phishguard sourcetype="phishguard:scan" | timechart span=1h count by verdict
```

**Correlated Malicious Network Indicators:**
```spl
index=phishguard sourcetype="phishguard:pcap" | stats count by destination_ip, protocol
```

---

## 🧪 Automated Testing

PhishGuard includes a complete 38-test automated verification suite covering unit detection, SSRF defenses, integration status reports, and case workflows:

```bash
# Run complete test suite
python -m pytest -v

# Run with quiet summary
python -m pytest -q
```
**Results:** `38 passed in ~14s` with zero failures.

---

## 🎙️ 10 Key Talking Points for SOC Analyst Interviews

1. **Defensive Engineering Over Black-Box Hype**: "I built PhishGuard to give Tier-1/Tier-2 analysts deterministic evidence, separating Risk Score ($0-100$) from Confidence Score ($0-100$) so every block action is explainable to leadership."
2. **Strict SSRF Architecture**: "Any automated URL/website fetch presents a server-side request forgery risk. I implemented pre-resolution IP validation blocking loopbacks, RFC 1918 private subnets, and AWS/Azure cloud metadata endpoints (`169.254.169.254`)."
3. **Graceful Integration Degradation**: "In enterprise environments, APIs go down or API quotas exhaust. PhishGuard's integration service classifies every tool at runtime (`CONNECTED`, `AVAILABLE`, `NOT CONFIGURED`, `UNAVAILABLE`, `ERROR`), ensuring zero crash states and zero fabricated responses."
4. **Real Splunk HEC Pipeline**: "Rather than simulating SIEM logs, PhishGuard formats normalized JSON payloads with standard sourcetypes (`phishguard:scan`, `phishguard:alert`) and dispatches them via HTTP Event Collector to Splunk."
5. **Multi-Source Threat Intelligence**: "I created an extensible provider abstraction coordinating free feeds like abuse.ch URLhaus and authoritative DNS/WHOIS alongside commercial APIs like VirusTotal, AbuseIPDB, and AlienVault OTX."
6. **Cross-Entity IOC Correlation**: "Scans do not live in isolation. When an IOC is cataloged, the platform correlates it across historical URLs, emails, file samples, and open investigation cases."
7. **Defensive Static File Inspection**: "The file analyzer computes cryptographic digests (SHA-256, SHA-1, MD5) and extracts static callout strings without executing arbitrary binaries on the host."
8. **Offline PCAP Network Telemetry**: "Using Scapy and tshark bindings, analysts can inspect packet captures offline to extract DNS queries, unencrypted HTTP hosts, and anomalous port connections."
9. **Real MITRE ATT&CK Mapping**: "Techniques like `T1566.002` (Spearphishing Link) or `T1071.004` (DNS) are mapped strictly when technical evidentiary rules fire — never randomly assigned."
10. **Burp Suite Separation of Concerns**: "I treated Burp Suite as an external manual authorized tool. Instead of faking scanner results, analysts attach verified Burp findings directly to investigation cases as corroborating evidence."