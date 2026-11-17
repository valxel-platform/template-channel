"""Settings, from the environment (prefix CHANNEL_). Secrets are mounted files (secrets.py)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHANNEL_")

    config_path: str = "channel.yaml"
    contracts_dir: str = "contracts"
    secrets_dir: str = "/var/run/secrets/valxel"
    environment: str = "dev"
    product: str = ""
    port: int = 8080
    # The public URL the providers call (Twilio signs it): https://<host>, no trailing slash.
    public_url: str = "http://localhost:8080"
    # People confirm a link from the product's own sign-in: the BFF calls /links/{nonce}/confirm with
    # their token (audience below).
    oidc_issuer: str = ""
    oidc_jwks_url: str = ""
    audience: str = "channel"
    tenant_claim: str = "organization"
    # Sign-in links offered per channel per minute, across everyone (per replica): each is an outbound
    # message, so a flood of spoofed senders can't run up the product's SMS or email bill.
    link_offers_per_minute: int = 30
    database_url: str = ""
    kafka_bootstrap: str = ""
    kafka_config: dict[str, str] = {}
    audit_sink: str = "log"
    audit_kafka_bootstrap: str = ""
    audit_topic: str = "audit.v1"
    audit_kafka_config: dict[str, str] = {}
    audit_required: bool | None = None
    flags_url: str = ""
    flags_environment: str = ""
    flags_namespace: str = ""
    flags_token: str = ""
    flags_timeout_s: float = 0.25
    flags_cache_s: float = 30.0
