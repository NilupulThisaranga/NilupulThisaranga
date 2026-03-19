from __future__ import annotations

import base64
import json

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from mpp_fastapi.core import MPP
from mpp_fastapi.dependencies import WalletConfig
from mpp_fastapi.types import MPPChargeOptions


def build_app() -> FastAPI:
    app = FastAPI()
    mpp = MPP(
        debug_mode=True,
        weak_debug_validation=True,
        wallet_config=WalletConfig(session_secret="test-session-secret"),
    )

    @app.get("/paid")
    @mpp.charge(amount="0.10", currency="USD")
    async def paid(request: Request) -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/session")
    @mpp.charge(options=MPPChargeOptions(amount="0.01", currency="USD", session=True, max_amount="0.05"))
    async def paid_session(request: Request) -> dict[str, str]:
        return {"ok": "session"}

    return app


def test_requires_payment_without_receipt() -> None:
    client = TestClient(build_app())
    response = client.get("/paid")

    assert response.status_code == 402
    payload = response.json()
    assert payload["error"] == "payment_required"


def test_accepts_valid_receipt() -> None:
    client = TestClient(build_app())
    receipt = {
        "id": "rcpt_1",
        "provider": "tempo",
        "amount": "0.10",
        "currency": "USD",
    }

    response = client.get("/paid", headers={"X-MPP-Receipt": json.dumps(receipt)})

    assert response.status_code == 200
    assert response.json() == {"ok": "yes"}


def test_accepts_base64url_receipt() -> None:
    client = TestClient(build_app())
    receipt = {
        "id": "rcpt_1_b64",
        "provider": "tempo",
        "amount": "0.10",
        "currency": "USD",
    }
    encoded = base64.urlsafe_b64encode(json.dumps(receipt).encode("utf-8")).decode("utf-8")

    response = client.get("/paid", headers={"X-MPP-Receipt": encoded})

    assert response.status_code == 200
    assert response.json() == {"ok": "yes"}


def test_session_authorization_then_reuse() -> None:
    client = TestClient(build_app())

    auth_receipt = {
        "id": "rcpt_auth",
        "provider": "tempo",
        "amount": "0.01",
        "currency": "USD",
        "authorized_max_amount": "0.05",
    }

    first = client.get("/session", headers={"X-MPP-Receipt": json.dumps(auth_receipt)})
    session_id = first.headers.get("Payment-Session")
    assert session_id is not None

    second = client.get("/session", headers={"Payment-Session": session_id})
    third = client.get("/session", headers={"Payment-Session": session_id})
    fourth = client.get("/session", headers={"Payment-Session": session_id})
    fifth = client.get("/session", headers={"Payment-Session": session_id})
    sixth = client.get("/session", headers={"Payment-Session": session_id})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 200
    assert fourth.status_code == 200
    assert fifth.status_code == 200
    assert sixth.status_code == 402
