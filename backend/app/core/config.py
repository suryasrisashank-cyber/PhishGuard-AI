import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


def is_cloud_environment() -> bool:
    """Detect whether backend is running in a cloud platform or container."""
    cloud_env_indicators = [
        "RENDER",
        "RAILWAY_ENVIRONMENT",
        "FLY_APP_NAME",
        "HEROKU",
        "K_SERVICE",          # Google Cloud Run
        "DYNO",               # Heroku
        "VERCEL",
        "AWS_EXECUTION_ENV",
    ]
    if any(os.getenv(k) for k in cloud_env_indicators):
        return True
    if os.getenv("IS_CLOUD_DEPLOYMENT", "").lower() in ("true", "1", "yes"):
        return True
    if os.getenv("ENVIRONMENT", "").lower() == "production" and not os.getenv("IS_LOCAL_LAB"):
        return True
    return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Environment & Deployment
    environment: str = "production"
    is_cloud_deployment: bool = False
    frontend_origins: str = ""

    # Security & Auth
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Database
    database_url: str = "sqlite:///./phishguard.db"
    db_pool_size: int = 3
    db_max_overflow: int = 2
    db_pool_timeout: int = 30
    db_pool_recycle: int = 1800

    # Threat Intelligence Providers (Real external APIs)
    virus_total_api_key: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    # SIEM / Splunk Integration (HTTP Event Collector)
    splunk_host: str = ""
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    splunk_index: str = "phishguard"
    splunk_sourcetype: str = "phishguard:scan"
    splunk_verify_tls: bool = True

    # Local Tool Paths & Rule Repositories
    yara_rules_path: str = ""
    tshark_path: str = ""

    # AI Explanation Integration (Optional, non-authoritative)
    gemini_api_key: str = ""
    openai_api_key: str = ""

    # Application & Logging
    log_level: str = "INFO"


@lru_cache()
def get_settings() -> Settings:
    s = Settings()
    if is_cloud_environment():
        s.is_cloud_deployment = True
    return s


settings = get_settings()
