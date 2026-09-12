# PhishGuard AI 2.1

**AI-Powered Phishing Detection & Threat Intelligence SOC Investigation Platform**

PhishGuard AI 2.1 is an enterprise-grade Security Operations Center (SOC) investigation platform designed for Tier-1/Tier-2 analyst incident triage, automated enrichment, heuristic forensics, and incident reporting.

$$\text{DETECT} \longrightarrow \text{INVESTIGATE} \longrightarrow \text{ENRICH} \longrightarrow \text{CLASSIFY} \longrightarrow \text{RESPOND} \longrightarrow \text{REPORT}$$

---

## Why This Project is SOC-Relevant

In a real Security Operations Center, analysts do not rely on opaque "black box" machine learning models that cannot explain why a URL was blocked. Every containment action requires verifiable technical evidence, reproducible risk scoring, and alignment with threat intelligence frameworks.

PhishGuard AI 2.1 was engineered around this operational reality:

| SOC Phase | Operational Implementation |
|---|---|
| **1. DETECT** | 10-stage deterministic pipeline executing deep URL normalization, entropy scoring, brand impersonation detection, and homoglyph analysis. |
| **2. INVESTIGATE** | 3-column Investigation Dossier (`/investigation/:id`) separating case metadata, forensic evidence breakdown, and risk metrics. |
| **3. ENRICH** | Passive DNS lookups (A, MX, TXT records) and authoritative WHOIS data without exposing internal infrastructure. |
| **4. CLASSIFY** | Independent **Risk Score** ($0-100$) and **Confidence Score** ($0-100$), coupled with a 5-tier Severity Matrix and strict evidence-based MITRE ATT&CK technique mapping. |
| **5. RESPOND** | Actionable, non-destructive SOC playbooks (blocking recommendations, SIEM search queries, credential rotation notices). |
| **6. REPORT** | Automated executive incident summaries, structured IOC export (JSON), and remediation checklists. |

---

## Key Features

### 1. Interactive 3D Threat Telemetry
- **Global Threat Activity Globe**: Interactive 3D Three.js rotating sphere with latitude coordinate rings, telemetry threat nodes, connection arcs, mouse drag rotation, and node hover detection.
- **Graceful WebGL Fallback**: Automatically falls back to lightweight SVG/CSS topology visualizer if WebGL is unsupported or disabled.

### 2. Heuristic Detection Engine (v2.1)
- **Shannon Entropy Analysis**: Flags algorithmically generated domains (DGA) with entropy $> 3.5$.
- **Punycode & Homoglyph Detection**: Identifies `xn--` prefixes and Cyrillic/Unicode lookalike characters.
- **Brand Impersonation Knowledge Base**: 25+ major targets (PayPal, Microsoft, Google, Apple, Amazon, Chase, Wells Fargo, etc.) flagged when appearing outside official assets.
- **SSRF Defense Guard**: Validates public IP destinations; automatically blocks access to localhost, `127.0.0.1`, private IP subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local metadata endpoints (`169.254.169.254`).

### 3. Categorized Evidence Panel
Every check emits a typed `IndicatorItem` with impact points, rule weight, and technical evidence:
- **DOMAIN**: Entropy, brand matching, TLD reputation, punycode.
- **NETWORK**: Resolved IPs, non-standard port bindings, DNS records.
- **URL**: Length, deep percent-encoding, open redirect query parameters.
- **CONTENT**: Password fields, external form destinations, hidden iframes.
- **EMAIL**: Urgency triggers, credential harvesting language, SPF/DKIM/DMARC headers.
- **AUTHENTICATION**: Sender / Reply-To domain mismatches.
- **THREAT INTELLIGENCE**: Authoritative WHOIS registrar and passive DNS.

### 4. AI Security Explanation Layer
- Translates complex technical evidence into plain-English SOC briefings.
- **Integrity Rule**: Derived strictly from deterministic scanner findings — never invents unverified reputation or threat intelligence.
- Transparently labeled as **"AI-assisted explanation"**.

### 5. SOC Case Management Workflow
- Case progression: `NEW` $\to$ `INVESTIGATING` $\to$ `CONFIRMED_THREAT` $\to$ `RESPONDING` $\to$ `RESOLVED` (or `FALSE_POSITIVE`).
- Persistent case status transitions and analyst notes stored in SQLite.
- IOC management table with type filtering, searching, copying, and JSON export.

### 6. User Experience & Aesthetics
- Dark SOC theme (`#020617`) with optional light theme toggle.
- Global Command Palette accessible anywhere via **`Ctrl + K`**.
- Accessible keyboard shortcuts and `prefers-reduced-motion` compliance.

---

## Quick Start

### 1. Backend (FastAPI + SQLite)
Ensure the Python virtualenv is active:
```powershell
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Health: `http://127.0.0.1:8000/health`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 2. Frontend (React 18 + Vite 5 + Tailwind CSS)
From the `frontend/` directory (run via `cmd /c` on Windows):
```cmd
cd frontend
cmd /c npm run dev
```
- Web Application: `http://localhost:3000`

---

## Running Tests

Run the backend automated test suite:
```powershell
.venv\Scripts\python.exe -m pytest backend/tests/test_api.py -v
```
*(All 9 integration tests pass, covering URL scans, email heuristics, status patching, reports, AI explanations, and SSRF guards).*

Build the production frontend bundle:
```cmd
cd frontend
cmd /c npm run build
```
*(Built with Vite code-splitting and dedicated Three.js, motion, and charts chunks).*

---

## Environment Variables

Create `.env` in `backend/`:
```env
# Optional Threat Intelligence API Keys (shown as "not configured" when omitted)
VIRUS_TOTAL_API_KEY=""
ABUSEIPDB_API_KEY=""

# Security
SECRET_KEY="change-me-in-production"
LOG_LEVEL="INFO"
```

Create `.env` in `frontend/`:
```env
VITE_API_URL="http://127.0.0.1:8000/api"
VITE_DEMO_MODE="false"
```

---

## Security Considerations & Guardrails

1. **SSRF Defense**: The website scanner strictly enforces `_validate_safe_url_for_fetch()`, resolving domains and rejecting requests to loopback addresses (`127.0.0.1`), private networks (`10.0.0.0/8`, `192.168.0.0/16`), and cloud metadata APIs (`169.254.169.254`).
2. **Deterministic Truth**: The platform never fabricates AI confidence, reputation, or threat intelligence.
3. **No Destructive Actions**: Response recommendations provide actionable guidance for firewall and SIEM operators without auto-executing destructive commands.

---

## Known Limitations

- **Screenshot Analysis**: Uses heuristic metadata and pixel statistics only; does not perform optical character recognition (OCR) or computer vision classification.
- **PDF Export**: Incident reports provide complete JSON export and print-ready previews; automated PDF binary generation is marked as `"Coming Soon"`.