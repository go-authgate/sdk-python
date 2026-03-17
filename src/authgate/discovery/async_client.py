"""Asynchronous OIDC discovery client with caching."""

from __future__ import annotations

import asyncio
import copy
import time

import httpx

from authgate.discovery.client import _parse_metadata
from authgate.discovery.models import Metadata
from authgate.exceptions import DiscoveryError

_WELL_KNOWN_PATH = "/.well-known/openid-configuration"
_DEFAULT_CACHE_TTL = 3600.0


class AsyncDiscoveryClient:
    """OIDC discovery client with caching (async)."""

    def __init__(
        self,
        issuer_url: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        cache_ttl: float = _DEFAULT_CACHE_TTL,
    ) -> None:
        self._issuer_url = issuer_url.rstrip("/")
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._cache_ttl = cache_ttl
        self._lock = asyncio.Lock()
        self._cached: Metadata | None = None
        self._fetched_at: float = 0.0

    async def fetch(self) -> Metadata:
        """Retrieve the OIDC provider metadata, using the cache if still valid."""
        if self._cached is not None and (time.time() - self._fetched_at) < self._cache_ttl:
            return copy.deepcopy(self._cached)
        return await self._refresh()

    async def _refresh(self) -> Metadata:
        async with self._lock:
            if self._cached is not None and (time.time() - self._fetched_at) < self._cache_ttl:
                return copy.deepcopy(self._cached)

            url = self._issuer_url + _WELL_KNOWN_PATH
            resp = await self._http.get(url)
            if resp.status_code != 200:
                raise DiscoveryError(
                    f"discovery: unexpected status {resp.status_code} from {url}"
                )

            body = resp.json()
            meta = _parse_metadata(body)

            issuer = meta.issuer.rstrip("/")
            if issuer != self._issuer_url:
                raise DiscoveryError(
                    f"discovery: issuer mismatch: got {meta.issuer!r},"
                    f" expected {self._issuer_url!r}"
                )

            if not meta.device_authorization_endpoint:
                meta.device_authorization_endpoint = issuer + "/oauth/device/code"

            if not meta.introspection_endpoint:
                meta.introspection_endpoint = issuer + "/oauth/introspect"

            self._cached = meta
            self._fetched_at = time.time()
            return copy.deepcopy(meta)
