"""Application settings (env-driven)."""

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://gf_gateway:change-me-gateway@localhost:5432/ghostfence"
    tool_registry_path: str = "../tool-registry.yaml"
    policy_path: str = "../policies/example.yaml"
    resources_path: str = "../resources.yaml"
    destinations_path: str = "../destinations.yaml"
    run_token_secret: str = Field(default="change-me-run-token-secret", validation_alias=AliasChoices("GHOSTFENCE_RUN_TOKEN_SECRET", "RUN_TOKEN_SECRET"))
    audit_hmac_key: str = Field(default="change-me-audit-hmac-key", validation_alias=AliasChoices("GHOSTFENCE_AUDIT_HMAC_KEY", "AUDIT_HMAC_KEY"))
    admin_api_key: str = Field(default="dev-admin-key", validation_alias=AliasChoices("GHOSTFENCE_ADMIN_API_KEY", "ADMIN_API_KEY"))
    approver_api_key: str = Field(default="dev-approver-key", validation_alias=AliasChoices("GHOSTFENCE_APPROVER_API_KEY", "APPROVER_API_KEY"))
    agent_api_key: str = Field(default="dev-agent-key", validation_alias=AliasChoices("GHOSTFENCE_AGENT_API_KEY", "AGENT_API_KEY"))
    run_ttl_seconds: int = 1800
    denial_threshold: int = 5
    demo_allow_evil_test: bool = True
    anthropic_model: str = Field(default="claude-sonnet-4-5", validation_alias=AliasChoices("GHOSTFENCE_ANTHROPIC_MODEL", "ANTHROPIC_MODEL"))


settings = Settings()