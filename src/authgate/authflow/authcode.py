"""Authorization Code + PKCE flow with local callback server."""

from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from authgate.authflow.browser import open_browser
from authgate.authflow.pkce import generate_pkce
from authgate.exceptions import OAuthError
from authgate.oauth.client import OAuthClient
from authgate.oauth.models import Token


def _generate_state() -> str:
    """Generate a cryptographically random state string for CSRF protection."""
    return os.urandom(16).hex()


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for the OAuth callback."""

    result: dict[str, str]  # shared via class attribute set by factory
    event: threading.Event

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return

        params = parse_qs(parsed.query)

        # Only process the first callback
        if self.event.is_set():
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Already processed</h1></body></html>")
            return

        state = params.get("state", [""])[0]
        if state != self.result.get("expected_state"):
            self.result["error"] = "invalid_state"
            self.result["error_description"] = "State parameter mismatch"
            self.event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Authentication failed</h1>"
                b"<p>State mismatch. You can close this window.</p></body></html>"
            )
            return

        code = params.get("code", [""])[0]
        if not code:
            self.result["error"] = params.get("error", ["no code received"])[0]
            self.result["error_description"] = params.get("error_description", [""])[0]
            self.event.set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Authentication failed</h1>"
                b"<p>You can close this window.</p></body></html>"
            )
            return

        self.result["code"] = code
        self.event.set()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(
            b"<html><body><h1>Authentication successful</h1>"
            b"<p>You can close this window.</p></body></html>"
        )

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # Suppress HTTP server logs


def run_auth_code_flow(
    client: OAuthClient,
    scopes: list[str] | None = None,
    *,
    local_port: int = 0,
) -> Token:
    """Execute the Authorization Code + PKCE flow with a local callback server."""
    pkce = generate_pkce()
    state = _generate_state()

    # Start the callback server
    server = HTTPServer(("127.0.0.1", local_port), _CallbackHandler)
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    # Set up shared state via handler class attributes
    result: dict[str, str] = {"expected_state": state}
    event = threading.Event()
    _CallbackHandler.result = result
    _CallbackHandler.event = event

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Build authorization URL
        endpoints = client.endpoints
        params = (
            f"response_type=code"
            f"&client_id={client.client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&scope={'+'.join(scopes or [])}"
            f"&state={state}"
            f"&code_challenge={pkce.challenge}"
            f"&code_challenge_method={pkce.method}"
        )
        auth_url = f"{endpoints.authorize_url}?{params}"

        if not open_browser(auth_url):
            print(f"Open this URL in your browser:\n{auth_url}")

        # Wait for callback
        event.wait()

        if "error" in result:
            raise OAuthError(
                code=result["error"],
                description=result.get("error_description", ""),
            )

        code = result["code"]
    finally:
        server.shutdown()
        server_thread.join(timeout=5)

    return client.exchange_auth_code(code, redirect_uri, pkce.verifier)
