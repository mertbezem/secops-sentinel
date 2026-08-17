
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SecOps Sentinel SIEM"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment & Database
    ENV: str = Field(default="development", validation_alias=AliasChoices("ENV", "ENVIRONMENT"))
    DATABASE_URL: str = "sqlite:///./secops_sentinel.db"
    
    # CORS Config
    ALLOWED_ORIGINS: list[str] | str = Field(
        default=["*"], validation_alias=AliasChoices("ALLOWED_ORIGINS", "CORS_ORIGINS")
    )
    
    # Ingestion Batching
    INGEST_BATCH_SIZE: int = 5000
    
    # JWT & Auth Security
    SECRET_KEY: str = Field(
        default="secops-sentinel-ultra-secure-jwt-secret-key-change-in-production-2026",
        validation_alias=AliasChoices("SECRET_KEY", "JWT_SECRET")
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 Hours
    
    # Email & Alerting Config
    EMAIL_ALERTS_ENABLED: bool = Field(
        default=False, validation_alias=AliasChoices("EMAIL_ALERTS_ENABLED", "SMTP_ENABLED")
    )
    SMTP_HOST: str = Field(
        default="smtp.gmail.com", validation_alias=AliasChoices("SMTP_HOST", "MAIL_HOST")
    )
    SMTP_PORT: int = Field(
        default=587, validation_alias=AliasChoices("SMTP_PORT", "MAIL_PORT")
    )
    SMTP_USER: str = Field(
        default="", validation_alias=AliasChoices("SMTP_USER", "MAIL_USER", "SMTP_USERNAME")
    )
    SMTP_PASSWORD: str = Field(
        default="", validation_alias=AliasChoices("SMTP_PASSWORD", "MAIL_PASSWORD")
    )
    SMTP_TLS: bool = Field(
        default=True, validation_alias=AliasChoices("SMTP_TLS", "MAIL_TLS", "SMTP_USE_TLS")
    )
    SMTP_SSL: bool = Field(
        default=False, validation_alias=AliasChoices("SMTP_SSL", "MAIL_SSL", "SMTP_USE_SSL")
    )
    ALERT_EMAIL_FROM: str = Field(
        default="secops-sentinel@security.local", validation_alias=AliasChoices("ALERT_EMAIL_FROM", "MAIL_FROM")
    )
    ALERT_EMAIL_TO: str = Field(
        default="soc-team@security.local", validation_alias=AliasChoices("ALERT_EMAIL_TO", "MAIL_TO")
    )
    ALERT_MIN_SEVERITY: str = Field(
        default="HIGH", validation_alias=AliasChoices("ALERT_MIN_SEVERITY")
    )
    
    # Webhook Notifications (Slack / Discord / Teams)
    WEBHOOK_URL: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL")
    )
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, list):
            return v
        import json
        return json.loads(v) if isinstance(v, str) else ["*"]


settings = Settings()
