"""
PhishGuard AI 3.0 — FastAPI Application Entry Point
Defensive SOC Investigation & Threat Intelligence Orchestration Platform
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.routers import (
    auth,
    scans,
    dashboard,
    ml,
    threat_intelligence,
    screenshots,
    reports,
    ai_explain,
    system,
    splunk,
    iocs,
    investigations,
    alerts,
    campaigns,
)
from .db.database import init_db, get_db_dialect
from .utils.logger import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


# Ensure database tables exist on module import (required for TestClient and worker processes)
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("PhishGuard AI 3.0 database & services initialized")
    yield


app = FastAPI(
    title="PhishGuard AI 3.0 — Real-World SOC Platform",
    version="3.0.0",
    description=(
        "Defensive SOC investigation & threat-intelligence platform. "
        "Integrates with Splunk SIEM, VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, "
        "DNS/RDAP, YARA, Scapy PCAP analysis, and MITRE ATT&CK."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

from .core.config import settings

# Construct CORS origins dynamically: local defaults + production Vercel frontend + custom origins
default_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://phish-guard-ai-suryasrisashank-cybers-projects.vercel.app",
    "https://phish-guard-ai-git-main-suryasrisashank-cybers-projects.vercel.app",
]
custom_origins = [
    o.strip()
    for o in (settings.frontend_origins or "").split(",")
    if o.strip()
]
allowed_origins = list(dict.fromkeys(default_origins + custom_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?:\/\/([a-zA-Z0-9-.]+\.vercel\.app|localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all SOC routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(system.router, prefix="/api/system", tags=["System & Integrations"])
app.include_router(threat_intelligence.router, prefix="/api/threats", tags=["Threat Intelligence"])
app.include_router(splunk.router, prefix="/api/splunk", tags=["Splunk SIEM"])
app.include_router(iocs.router, prefix="/api/iocs", tags=["IOC Engine"])
app.include_router(investigations.router, prefix="/api/investigations", tags=["Investigations"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["SOC Alerts"])
app.include_router(campaigns.router, prefix="/api/campaigns", tags=["Threat Campaigns"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(ai_explain.router, prefix="/api/ai", tags=["AI Explanation"])
app.include_router(screenshots.router, prefix="/api/screenshots", tags=["Screenshots"])
app.include_router(ml.router, prefix="/api/ml", tags=["Machine Learning"])


@app.get("/")
def home() -> dict:
    return {
        "service": "PhishGuard AI",
        "version": "3.0.0",
        "role": "Defensive SOC Investigation & Threat Intelligence Platform",
        "workflow": "Detect → Investigate → Enrich → Classify → Respond → Report",
        "status": "online",
        "docs": "/docs",
        "health": "/health",
        "integrations_status": "/api/system/integrations",
    }


@app.get("/health")
@app.get("/api/health")
def health() -> dict:
    return {
        "status": "healthy",
        "service": "phishguard-ai",
        "version": "3.0.0",
        "environment": settings.environment,
        "database": "online",
        "database_type": get_db_dialect(),
    }
