"""
PhishGuard AI 2.0 — FastAPI Application Entry Point
"""
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.routers import auth, scans, dashboard, ml, threat_intelligence, screenshots, reports, ai_explain
from .db.database import init_db
from .utils.logger import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PhishGuard AI 2.1",
    version="2.1.0",
    description=(
        "AI-Assisted Phishing Detection & Threat Intelligence Platform. "
        "Detect → Investigate → Enrich → Classify → Respond → Report. "
        "Uses heuristic analysis — not ML inference unless explicitly documented."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://73e94b289a7d59.lhr.life",
        "https://f8213bfef6cd14.lhr.life",
        "https://mega-checklist-baghdad-stack.trycloudflare.com",
        "https://came-africa-tried-electrical.trycloudflare.com",
    ],
    allow_origin_regex=r"^https?://([a-zA-Z0-9-]+\.(trycloudflare\.com|lhr\.life|loca\.lt)|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(ml.router, prefix="/api/ml", tags=["Machine Learning"])
app.include_router(threat_intelligence.router, prefix="/api/threats", tags=["Threat Intelligence"])
app.include_router(screenshots.router, prefix="/api/screenshots", tags=["Screenshots"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(ai_explain.router, prefix="/api/ai", tags=["AI Explanation"])


@app.on_event("startup")
def startup_event() -> None:
    init_db()
    logger.info("PhishGuard AI 2.0 started successfully")


@app.get("/")
def home() -> dict:
    return {
        "message": "PhishGuard AI 2.1 is running",
        "status": "online",
        "version": "2.0.0",
        "workflow": "Detect -> Investigate -> Enrich -> Classify -> Respond -> Report",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "phishguard-ai-2.1",
        "version": "2.0.0",
    }
