"""Authentication for both planes.

Steward has two distinct populations of caller and they need different
treatment:

**The data plane** -- agents invoking tools. Identified by a bearer JWT whose
``sub`` becomes the policy subject. Verified against the issuer's JWKS.

**The control plane** -- humans and CI writing policy, pinning tools, deciding
approvals. This is the more sensitive of the two, and in the original version
of this service it had *no authentication at all*: an unauthenticated
``POST /v1/policies`` let anyone reachable on the network grant themselves
``subject:*, server:*, tool:*``. Every guarantee downstream rested on a door
that was propped open. Control-plane calls now carry an API key mapped to a
role, and writes are refused outright in production if no keys are configured.

The JWKS client is cached per URL. Constructing a fresh ``PyJWKClient`` inside
the request path -- as this module previously did -- re-fetched the key set on
every single call, adding a network round trip to each authorization decision
and handing anyone who could reach the endpoint a way to make Steward hammer
its own identity provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import jwt
from fastapi import Header, HTTPException, Request, status
from jwt import PyJWKClient

from .config import get_settings

# Control-plane roles, from least to most authority.
ROLE_AUDITOR = "auditor"
ROLE_AUTHOR = "author"
ROLE_ADMIN = "admin"

_ROLE_RANK = {ROLE_AUDITOR: 1, ROLE_AUTHOR: 2, ROLE_ADMIN: 3}


@dataclass(frozen=True)
class Operator:
    """An authenticated control-plane caller."""

    key_id: str
    role: str

    def can(self, required: str) -> bool:
        return _ROLE_RANK.get(self.role, 0) >= _ROLE_RANK.get(required, 99)


@lru_cache(maxsize=8)
def _jwks_client(url: str) -> PyJWKClient:
    """One cached JWKS client per URL.

    ``PyJWKClient`` maintains its own key cache; the point of memoising the
    client is to keep that cache alive across requests.
    """
    return PyJWKClient(url, cache_keys=True, lifespan=300)


def reset_jwks_cache() -> None:
    _jwks_client.cache_clear()


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()


def decode_claims(token: str) -> dict[str, Any]:
    """Verify and decode an agent's access token."""
    settings = get_settings()

    try:
        if settings.jwt_jwks_url:
            signing_key = _jwks_client(settings.jwt_jwks_url).get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=settings.algorithms,
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                leeway=settings.jwt_leeway_seconds,
                options={
                    "require": ["exp", "sub"],
                    "verify_aud": bool(settings.jwt_audience),
                    "verify_iss": bool(settings.jwt_issuer),
                },
            )

        if settings.is_production:
            # Never fall back to unverified tokens in production, whatever
            # else is misconfigured.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT_JWKS_URL must be configured in production",
            )

        if settings.jwt_issuer:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT_ISSUER is set but JWT_JWKS_URL is not; cannot verify tokens",
            )

        # Development only: accept an unsigned token so the demo runs without
        # standing up an identity provider.
        return jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
            algorithms=settings.algorithms,
        )

    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Access token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise HTTPException(status_code=401, detail="Access token audience is not accepted") from exc
    except jwt.InvalidIssuerError as exc:
        raise HTTPException(status_code=401, detail="Access token issuer is not accepted") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid access token") from exc


async def current_principal(request: Request) -> str:
    """Resolve the agent subject for a data-plane call."""
    claims = decode_claims(_bearer_token(request))
    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="Token has no subject claim")
    return str(subject)


async def current_principal_context(request: Request) -> tuple[str, dict[str, Any]]:
    claims = decode_claims(_bearer_token(request))
    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="Token has no subject claim")
    return str(subject), claims


# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------


def _resolve_operator(api_key: str | None) -> Operator:
    settings = get_settings()
    keys = settings.control_plane_keys

    if not keys:
        if settings.is_production:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "No control-plane API keys are configured. Refusing to "
                    "serve an unauthenticated policy API in production."
                ),
            )
        if not settings.allow_unauthenticated_control_plane:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "Control plane is locked. Set ADMIN_API_KEYS, or set "
                    "ALLOW_UNAUTHENTICATED_CONTROL_PLANE=true for local "
                    "development only."
                ),
            )
        return Operator(key_id="local-dev", role=ROLE_ADMIN)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Steward-Key header required",
        )

    role = keys.get(api_key)
    if role is None:
        # Constant-ish response: never reveal whether the key merely lacked
        # the role or does not exist.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown API key")

    return Operator(key_id=api_key[:8] + "...", role=role)


def require_role(required: str):
    """FastAPI dependency enforcing a minimum control-plane role."""

    async def dependency(
        x_steward_key: str | None = Header(default=None, alias="X-Steward-Key"),
    ) -> Operator:
        operator = _resolve_operator(x_steward_key)
        if not operator.can(required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {required!r} required; key has {operator.role!r}",
            )
        return operator

    return dependency


require_admin = require_role(ROLE_ADMIN)
require_author = require_role(ROLE_AUTHOR)
require_auditor = require_role(ROLE_AUDITOR)
