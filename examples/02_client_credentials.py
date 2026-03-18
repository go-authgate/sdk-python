"""Example 2: Machine-to-machine (M2M) with Client Credentials grant.

Tokens are cached in memory and refreshed automatically before expiry.
No user interaction is required.

Usage:
    uv run python examples/02_client_credentials.py
"""

from __future__ import annotations

import os

import httpx

from authgate.clientcreds.token_source import TokenSource
from authgate.discovery.client import DiscoveryClient
from authgate.oauth.client import OAuthClient

AUTHGATE_URL = os.environ["AUTHGATE_URL"]
CLIENT_ID = os.environ["AUTHGATE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AUTHGATE_CLIENT_SECRET"]
API_URL = "https://api.example.com/data"


def make_token_source() -> TokenSource:
    meta = DiscoveryClient(AUTHGATE_URL).fetch()
    client = OAuthClient(CLIENT_ID, meta.to_endpoints(), client_secret=CLIENT_SECRET)
    return TokenSource(client, scopes=["api:read"])


def main() -> None:
    ts = make_token_source()

    # ts.token() returns a cached token and only fetches a new one when needed.
    token = ts.token()
    print(f"Access token: {token.access_token[:20]}...")

    # Attach the token to an outbound HTTP request.
    headers = {"Authorization": f"Bearer {token.access_token}"}
    resp = httpx.get(API_URL, headers=headers, timeout=10)
    print(f"API response: {resp.status_code}")


if __name__ == "__main__":
    main()
