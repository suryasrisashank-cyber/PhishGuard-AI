from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Security
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Database
    database_url: str = "sqlite:///./phishguard.db"

    # Threat intelligence providers (optional — clearly labeled as "not configured" when absent)
    virus_total_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Application
    log_level: str = "INFO"
    openai_api_key: str = ""  # Reserved for future AI integration

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
