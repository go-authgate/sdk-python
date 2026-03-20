# AuthGate Python SDK

[![PyPI](https://img.shields.io/pypi/v/go-authgate)](https://pypi.org/project/go-authgate/)
[![Python](https://img.shields.io/pypi/pyversions/go-authgate)](https://pypi.org/project/go-authgate/)
[![CI](https://github.com/go-authgate/sdk-python/actions/workflows/testing.yml/badge.svg)](https://github.com/go-authgate/sdk-python/actions/workflows/testing.yml)
[![Trivy](https://github.com/go-authgate/sdk-python/actions/workflows/trivy.yml/badge.svg)](https://github.com/go-authgate/sdk-python/actions/workflows/trivy.yml)
[![License](https://img.shields.io/pypi/l/go-authgate)](LICENSE)

Python SDK for [AuthGate](https://github.com/go-authgate) — OAuth 2.0 authentication and token management.

## Installation

```bash
pip install go-authgate
```

With framework support:

```bash
pip install go-authgate[fastapi]
pip install go-authgate[flask]
pip install go-authgate[django]
```

## Quick Start

```python
from authgate import authenticate

client, token = authenticate(
    "https://auth.example.com",
    "my-client-id",
    scopes=["profile", "email"],
)

print(f"Access token: {token.access_token}")
```

## Async Usage

```python
from authgate import async_authenticate

client, token = await async_authenticate(
    "https://auth.example.com",
    "my-client-id",
    scopes=["profile", "email"],
)
```

## Client Credentials (M2M)

```python
from authgate.discovery.client import DiscoveryClient
from authgate.oauth import OAuthClient
from authgate.clientcreds import TokenSource, BearerAuth
import httpx

disco = DiscoveryClient("https://auth.example.com")
meta = disco.fetch()
client = OAuthClient("my-service", meta.to_endpoints(), client_secret="secret")
ts = TokenSource(client, scopes=["api"])

# Auto-attaches Bearer token to every request
with httpx.Client(auth=BearerAuth(ts)) as http:
    resp = http.get("https://api.example.com/data")
```

## Middleware

### FastAPI

```python
from fastapi import FastAPI, Depends
from authgate.middleware.fastapi import BearerAuth
from authgate.middleware.models import TokenInfo

app = FastAPI()
auth = BearerAuth(oauth_client)

@app.get("/protected")
async def protected(info: TokenInfo = Depends(auth)):
    return {"user": info.user_id}
```

### Flask

```python
from flask import Flask
from authgate.middleware.flask import bearer_auth, get_token_info

app = Flask(__name__)

@app.route("/protected")
@bearer_auth(oauth_client)
def protected():
    info = get_token_info()
    return {"user": info.user_id}
```

## Examples

Ready-to-run examples are in the [`examples/`](examples/) directory:

| File                                                            | Description                                                       |
| --------------------------------------------------------------- | ----------------------------------------------------------------- |
| [`01_user_login.py`](examples/01_user_login.py)                 | Interactive user login — auto-selects browser or device code flow |
| [`02_client_credentials.py`](examples/02_client_credentials.py) | M2M service authentication with auto-cached tokens                |
| [`03_fastapi_server.py`](examples/03_fastapi_server.py)         | FastAPI server with Bearer token validation and scope enforcement |
| [`04_async_login.py`](examples/04_async_login.py)               | Async user login via device code flow                             |

Set the required environment variables, then run with `uv`:

```bash
export AUTHGATE_URL="https://auth.example.com"
export CLIENT_ID="my-app"

uv run python examples/01_user_login.py
```

## Development

```bash
make install    # uv sync --all-extras
make test
make lint
make typecheck
```

## License

MIT
