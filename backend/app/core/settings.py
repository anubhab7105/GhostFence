"""Application settings (env-driven)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://gf_gateway:change-me-gateway@localhost:5432/ghostfence"
    tool_registry_path: str = "../tool-registry.yaml"
    policy_path: str = "../policies/example.yaml"
    resources_path: str = "../resources.yaml"
    destinations_path: str = "../destinations.yaml"
    run_token_secret: str = "change-me-run-token-secret"
    audit_hmac_key: str = "change-me-audit-hmac-key"
    admin_api_key: str = "dev-admin-key"
    approver_api_key: str = "dev-approver-key"
    agent_api_key: str = "dev-agent-key"
    run_ttl_seconds: int = 1800
    denial_threshold: int = 5
    demo_allow_evil_test: bool = True


settings = Settings()