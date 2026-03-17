"""FastAPI/Starlette dependency for Bearer token validation."""

from __future__ import annotations

from collections.abc import Callable

from authgate.exceptions import OAuthError
from authgate.middleware.core import ValidationMode, extract_bearer_token, validate_token
from authgate.middleware.models import TokenInfo
from authgate.oauth.client import OAuthClient

try:
    from fastapi import Depends, HTTPException, Request
    from fastapi.security import HTTPBearer
except ImportError as exc:
    raise ImportError(
        "FastAPI is required for this module. Install with: pip install authgate[fastapi]"
    ) from exc


class BearerAuth:
    """FastAPI dependency that validates Bearer tokens."""

    def __init__(
        self,
        client: OAuthClient,
        *,
        mode: ValidationMode = ValidationMode.TOKEN_INFO,
        required_scopes: list[str] | None = None,
    ) -> None:
        self._client = client
        self._mode = mode
        self._required_scopes = required_scopes or []
        self._scheme = HTTPBearer(auto_error=False)

    async def __call__(self, request: Request) -> TokenInfo:
        auth_header = request.headers.get("Authorization", "")
        token = extract_bearer_token(auth_header)
        if not token:
            raise HTTPException(
                status_code=401,
                detail={"error": "missing_token", "error_description": "Bearer token required"},
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        try:
            info = validate_token(self._client, token, mode=self._mode)
        except OAuthError as exc:
            if exc.code == "server_error":
                raise HTTPException(
                    status_code=500,
                    detail={"error": exc.code, "error_description": exc.description},
                ) from exc
            raise HTTPException(
                status_code=401,
                detail={"error": exc.code, "error_description": exc.description},
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            ) from exc

        for scope in self._required_scopes:
            if not info.has_scope(scope):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "insufficient_scope",
                        "error_description": f"Token does not have required scope: {scope}",
                    },
                    headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
                )

        return info


def require_scope(*scopes: str) -> Callable[..., object]:
    """FastAPI dependency that checks for additional scopes.

    Must be used after BearerAuth.
    """

    _default = Depends()

    async def dependency(info: TokenInfo = _default) -> TokenInfo:
        for scope in scopes:
            if not info.has_scope(scope):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "insufficient_scope",
                        "error_description": f"Token does not have required scope: {scope}",
                    },
                    headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
                )
        return info

    return dependency
