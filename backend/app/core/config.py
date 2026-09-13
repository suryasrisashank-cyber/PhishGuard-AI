from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Security & Auth
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Database
    database_url: str = "sqlite:///./phishguard.db"

    # Threat Intelligence Providers (Real external APIs)
    virus_total_api_key: str = ""
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
    return Settings()


settings = get_settings()
