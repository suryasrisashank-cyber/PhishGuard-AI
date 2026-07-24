from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.routers import auth, scans, dashboard, ml, threat_intelligence, screenshots
from .db.database import init_db
from .utils.logger import setup_logging

setup_logging()

app = FastAPI(
    title="PhishGuard AI Pro",
    version="1.0.0",
    description="AI-powered phishing detection platform for URLs, emails, websites, screenshots, and threat intelligence.",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(ml.router, prefix="/api/ml", tags=["Machine Learning"])
app.include_router(
    threat_intelligence.router,
    prefix="/api/threats",
    tags=["Threat Intelligence"]
)
app.include_router(
    screenshots.router,
    prefix="/api/screenshots",
    tags=["Screenshots"]
)


@app.on_event("startup")
def startup_event() -> None:
    init_db()


# Root endpoint (Added for Render)
@app.get("/")
def home():
    return {
        "message": "PhishGuard AI Pro is running 🚀",
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "phishguard-ai-pro"
    }