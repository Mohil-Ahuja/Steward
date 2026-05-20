from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite+aiosqlite:///./steward.db"
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    jwt_algorithms: str = "RS256"
    environment: str = "development"
    audit_argument_redaction_keys: str = "password,token,secret,authorization"

    @property
    def algorithms(self) -> list[str]:
        return [x.strip() for x in self.jwt_algorithms.split(",") if x.strip()]

    @property
    def redaction_keys(self) -> set[str]:
        return {x.strip().lower() for x in self.audit_argument_redaction_keys.split(",") if x.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()

