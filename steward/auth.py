from typing import Any

import jwt
from fastapi import HTTPException, Request, status
from jwt import PyJWKClient

from .config import get_settings


def _claims_from_request(request: Request) -> dict[str, Any]:
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    token = header[7:].strip()
    settings = get_settings()
    try:
        if settings.jwt_jwks_url:
            key = PyJWKClient(settings.jwt_jwks_url).get_signing_key_from_jwt(token).key
            return jwt.decode(token, key, algorithms=settings.algorithms, audience=settings.jwt_audience,
                              issuer=settings.jwt_issuer)
        # Development mode permits an unverified token only when no issuer is configured.
        if settings.environment == "development" and not settings.jwt_issuer:
            return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT_JWKS_URL is required outside unsigned development mode",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from exc


async def current_principal(request: Request) -> str:
    claims = _claims_from_request(request)
    subject = claims.get("sub")
    if not subject:
        raise HTTPException(status_code=401, detail="Token subject is required")
    return str(subject)
