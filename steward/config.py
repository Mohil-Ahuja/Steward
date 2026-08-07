"""Environment-driven configuration for every Steward subsystem."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


def _csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ---- storage -------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./steward.db"

    # ---- agent identity (the token an agent presents to Steward) -------
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    jwt_algorithms: str = "RS256"
    jwt_leeway_seconds: int = 30

    # ---- control-plane identity (who may write policy) -----------------
    # Comma-separated ``key:role`` pairs, e.g. "sk-admin-1:admin,sk-ro-2:auditor".
    # Roles: admin (full), author (policy write), auditor (read-only).
    admin_api_keys: str = ""
    # When true a completely empty admin_api_keys still permits writes. This is
    # only tolerable in development and is refused when environment=production.
    allow_unauthenticated_control_plane: bool = False

    environment: Literal["development", "staging", "production"] = "development"

    # ---- audit ---------------------------------------------------------
    audit_argument_redaction_keys: str = (
        "password,token,secret,authorization,api_key,apikey,private_key,"
        "access_token,refresh_token,client_secret,ssn,card_number"
    )
    # HMAC key for the tamper-evident audit chain. Generated per-process when
    # unset, which means restarts start a new chain segment; set it in prod.
    audit_chain_key: str | None = None
    audit_redact_value_patterns: bool = True

    # ---- policy engine --------------------------------------------------
    # Deny a call whose tool is not present in the upstream tool catalogue.
    require_known_tool: bool = True
    # Reject upstream tools whose description hash drifted after pinning
    # (MCP "rug pull" defence).
    enforce_tool_integrity: bool = True
    # Treat MCP tool annotations as a *hint* only; never as authorization.
    trust_tool_annotations: bool = False
    default_decision: Literal["deny", "allow"] = "deny"

    # ---- gateway --------------------------------------------------------
    gateway_server_name: str = "steward-gateway"
    gateway_protocol_version: str = "2026-07-28"
    upstream_registry_path: str = "config/upstreams.yaml"
    upstream_timeout_seconds: float = 30.0
    # Namespacing separator used when aggregating tools from many servers.
    # The MCP spec recommends proxies disambiguate by prefixing with a server id.
    tool_namespace_separator: str = "__"

    # ---- approvals ------------------------------------------------------
    approval_ttl_seconds: int = 900

    # ---- model access ---------------------------------------------------
    anthropic_api_key: str | None = None
    agent_model: str = "claude-opus-5"
    judge_model: str = "claude-opus-5"
    agent_max_tokens: int = 8000
    agent_max_steps: int = 12

    # ---- derived --------------------------------------------------------
    @property
    def algorithms(self) -> list[str]:
        return _csv(self.jwt_algorithms)

    @property
    def redaction_keys(self) -> set[str]:
        return {key.lower() for key in _csv(self.audit_argument_redaction_keys)}

    @property
    def control_plane_keys(self) -> dict[str, str]:
        """Map of API key -> role for the policy control plane."""
        mapping: dict[str, str] = {}
        for entry in _csv(self.admin_api_keys):
            key, _, role = entry.partition(":")
            mapping[key] = (role or "admin").strip().lower()
        return mapping

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook: drop the memoised settings so env changes take effect."""
    get_settings.cache_clear()
