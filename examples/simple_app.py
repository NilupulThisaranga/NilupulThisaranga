"""Simple FastAPI app showing free, fixed and session MPP endpoints."""

from __future__ import annotations

import os

from fastapi import FastAPI, Request

from mpp_fastapi.core import MPP
from mpp_fastapi.dependencies import WalletConfig
from mpp_fastapi.types import MPPChargeOptions

wallet_config = WalletConfig(
    auto_retry_enabled=os.getenv("MPP_AUTO_RETRY", "true").lower() == "true",
    tempo_wallet_url=os.getenv("TEMPO_WALLET_URL"),
    tempo_api_key=os.getenv("TEMPO_API_KEY"),
    stripe_shared_payment_token=os.getenv("STRIPE_SHARED_PAYMENT_TOKEN"),
)

mpp = MPP(wallet_config=wallet_config, debug_mode=True, weak_debug_validation=True)
app = FastAPI(title="fastapi-mpp demo")


@app.get("/free")
async def free_endpoint() -> dict[str, str]:
    return {"message": "This endpoint is free."}


@app.get("/premium")
@mpp.charge(amount="0.05", currency="USD", description="Access to premium data")
async def premium_endpoint(request: Request) -> dict[str, str]:
    return {"data": "Premium content unlocked via MPP receipt."}


@app.get("/session")
@mpp.charge(
    options=MPPChargeOptions(
        amount="0.01",
        currency="USD",
        description="Session-metered endpoint",
        session=True,
        max_amount="0.25",
    )
)
async def session_endpoint(request: Request) -> dict[str, str]:
    return {"data": "Charged from session budget."}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
