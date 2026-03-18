# AuthGate Python SDK

[![PyPI](https://img.shields.io/pypi/v/go-authgate)](https://pypi.org/project/go-authgate/)
[![Python](https://img.shields.io/pypi/pyversions/go-authgate)](https://pypi.org/project/go-authgate/)
[![CI](https://github.com/go-authgate/sdk-python/actions/workflows/testing.yml/badge.svg)](https://github.com/go-authgate/sdk-python/actions/workflows/testing.yml)
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
from authgate.oauth import OAuthClient, Endpoints
from authgate.clientcreds import TokenSource, BearerAuth
import httpx

client = OAuthClient("my-service", endpoints, client_secret="secret")
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

## Development

```bash
make install    # uv sync --all-extras
make test
make lint
make typecheck
```

## License

MIT
