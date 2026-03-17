"""Auto-caching TokenSource for Client Credentials grant."""

from __future__ import annotations

import asyncio
import threading
import time

from authgate.oauth.async_client import AsyncOAuthClient
from authgate.oauth.client import OAuthClient
from authgate.oauth.models import Token

_DEFAULT_EXPIRY_DELTA = 30.0  # seconds


class TokenSource:
    """Thread-safe, auto-caching token source for client credentials (sync).

    Concurrent callers share a single in-flight fetch via singleflight pattern.
    """

    def __init__(
        self,
        client: OAuthClient,
        *,
        scopes: list[str] | None = None,
        expiry_delta: float = _DEFAULT_EXPIRY_DELTA,
    ) -> None:
        self._client = client
        self._scopes = scopes
        self._expiry_delta = expiry_delta
        self._lock = threading.RLock()
        self._token: Token | None = None
        self._inflight: threading.Event | None = None
        self._inflight_result: Token | None = None
        self._inflight_error: Exception | None = None

    def token(self) -> Token:
        """Return a valid access token, fetching a new one if expired."""
        # Fast path
        with self._lock:
            if self._token is not None and self._is_valid():
                return self._token

        return self._slow_path()

    def _is_valid(self) -> bool:
        if self._token is None or not self._token.access_token:
            return False
        if self._token.expires_at == 0:
            return True
        return (time.time() + self._expiry_delta) < self._token.expires_at

    def _slow_path(self) -> Token:
        with self._lock:
            # Re-check after acquiring lock
            if self._token is not None and self._is_valid():
                return self._token

            if self._inflight is not None:
                event = self._inflight
            else:
                event = threading.Event()
                self._inflight = event
                self._inflight_result = None
                self._inflight_error = None
                try:
                    tok = self._client.client_credentials(self._scopes)
                    self._token = tok
                    self._inflight_result = tok
                except Exception as exc:
                    self._inflight_error = exc
                finally:
                    self._inflight = None
                    event.set()
                return self._get_result()

        event.wait()
        return self._get_result()

    def _get_result(self) -> Token:
        if self._inflight_error is not None:
            raise self._inflight_error
        if self._inflight_result is None:
            raise RuntimeError("clientcreds: no token available")
        return self._inflight_result


class AsyncTokenSource:
    """Auto-caching token source for client credentials (async)."""

    def __init__(
        self,
        client: AsyncOAuthClient,
        *,
        scopes: list[str] | None = None,
        expiry_delta: float = _DEFAULT_EXPIRY_DELTA,
    ) -> None:
        self._client = client
        self._scopes = scopes
        self._expiry_delta = expiry_delta
        self._lock = asyncio.Lock()
        self._token: Token | None = None

    async def token(self) -> Token:
        """Return a valid access token, fetching a new one if expired."""
        if self._token is not None and self._is_valid():
            return self._token

        async with self._lock:
            if self._token is not None and self._is_valid():
                return self._token
            self._token = await self._client.client_credentials(self._scopes)
            return self._token

    def _is_valid(self) -> bool:
        if self._token is None or not self._token.access_token:
            return False
        if self._token.expires_at == 0:
            return True
        return (time.time() + self._expiry_delta) < self._token.expires_at
