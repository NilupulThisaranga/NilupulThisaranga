# fastapi-mpp

[![PyPI version](https://img.shields.io/pypi/v/fastapi-mpp.svg)](https://pypi.org/project/fastapi-mpp/)
[![Python versions](https://img.shields.io/pypi/pyversions/fastapi-mpp.svg)](https://pypi.org/project/fastapi-mpp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/SylvainCostes/fastapi-mpp?style=social)](https://github.com/SylvainCostes/fastapi-mpp)

Machine Payments Protocol middleware for FastAPI.

Version `v0.3` hardens receipt validation, replay protection, session binding, and
adds pluggable storage backends with Redis support for production deployments.
This project is still beta.

## Installation

```bash
pip install fastapi-mpp
```

For production validation, install Tempo support so default cryptographic validation
is available:

```bash
pip install "fastapi-mpp[tempo]"
```

Optional extras:

```bash
pip install "fastapi-mpp[dotenv]"
pip install "fastapi-mpp[redis]"
pip install "fastapi-mpp[stripe]"
pip install "fastapi-mpp[all]"
```

## System Prerequisites

- `RedisStore` is designed for Redis `6.2+` where `GETDEL` is available for atomic
    one-time challenge consumption.
- For older Redis versions, the library falls back to an atomic Lua script, but
    Redis `6.2+` is strongly recommended for production compatibility and operations.

## Usage

### Server setup

```python
import os

from fastapi import FastAPI, Request
from mpp_fastapi.core import MPP
from mpp_fastapi.stores import RedisStore

app = FastAPI()

# Production mode (default): requires receipt_validator or fastapi-mpp[tempo].
mpp = MPP(
    store=RedisStore(
        redis_url=os.getenv("MPP_REDIS_URL", "redis://localhost:6379/0"),
    )
)

@app.get("/premium")
@mpp.charge(amount="0.05", currency="USD", description="Premium data")
async def premium(request: Request):
    return {"data": "paid content"}
```

### HTTP flow (v0.3 hardened)

1. Client calls endpoint without credential.
2. Server responds `402 Payment Required` with:
    - `WWW-Authenticate: Payment challenge="<base64url(JSON)>", realm="MyAPI", expires="..."`
    - challenge body containing `challenge_id`, `intent`, `amount`, `currency`, `expires_at`, `hints`
3. Wallet pays and retries with:
    - `Authorization: Payment credential="<base64url(receipt-json)>"`
4. Server validates receipt (fail-closed in production), applies replay checks, and returns success with:
    - `Payment-Receipt: <base64url(receipt-json)>`
    - optional session headers when session mode is enabled.

Legacy compatibility can be kept with `allow_legacy_headers=True`:
- `X-MPP-Receipt`
- `X-MPP-Session-Id`

### Session budgets

```python
from fastapi import FastAPI, Request
from mpp_fastapi.core import MPP
from mpp_fastapi.types import MPPChargeOptions

app = FastAPI()
mpp = MPP()

session_options = MPPChargeOptions(
    amount="0.01",
    currency="USD",
    description="Session-metered call",
    session=True,
    max_amount="0.50",
    require_idempotency_key=True,
)

@app.post("/agent/infer")
@mpp.charge(options=session_options)
async def infer(request: Request):
    return {"result": "paid inference"}
```

Sessions are HMAC-signed opaque tokens bound to:
- route scope
- optional payer source
- currency/provider
- issued-at and expiry (default 15 minutes)
- max budget tracked in store

## Local Run

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
uvicorn examples.simple_app:app --reload
```

Then test:

```bash
curl -i http://127.0.0.1:8000/free
curl -i http://127.0.0.1:8000/premium
```

Expected behavior demo:

```text
GET /free -> 200 OK
GET /premium (without Authorization) -> 402 Payment Required
GET /premium (with Authorization: Payment credential="...") -> 200 OK
```

## Security

Read [SECURITY.md](SECURITY.md) before production usage.

- Beta warning: use with caution.
- In-memory replay/session/rate-limit stores are suitable for single-process deployments only.
- Production mode is fail-closed when receipt validation is not configured.
- HTTPS is enforced in production mode.

## Headers

Incoming:
- `Authorization: Payment credential="..."` (preferred)
- `Payment-Receipt` (supported)
- `Payment-Session` (session spends)
- `X-MPP-Receipt` and `X-MPP-Session-Id` in legacy mode
- `Idempotency-Key` for safer retries

Response on 402:
- `WWW-Authenticate: Payment challenge="...", realm="...", expires="..."`
- JSON challenge payload

Response on success:
- `Payment-Receipt`
- `Payment-Session` when session authorization is established

## Design Notes

- Storage is abstracted via `BaseStore`; default `InMemoryStore` is single-process only.
- `RedisStore` is available for multi-worker production deployments.
- Header size limit is enforced (`8KB`) for authorization and receipt headers.
- A basic in-memory challenge rate limiter is enabled (default `10` challenges/IP/minute).

## Roadmap

- Redis-backed replay/session/rate-limit stores
- Full conformance with evolving HTTP Payment auth draft semantics
- Advanced rate limiting and abuse controls
- Payment provider adapters and richer telemetry

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Add tests for behavior changes.
4. Run:

```bash
uv pip install -e ".[dev]"
pytest
ruff check .
mypy src
```

5. Open a PR with clear before/after behavior.

## Credits

Inspired by the MPP ecosystem work and early protocol specs from Tempo and Stripe collaborators.
Please refer to official protocol repos/specs for normative behavior and updates.

## License

MIT
