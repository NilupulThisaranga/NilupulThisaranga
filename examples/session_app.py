"""Advanced example focusing on MPP sessions."""

from __future__ import annotations

from fastapi import FastAPI, Request

from mpp_fastapi.core import MPP
from mpp_fastapi.types import MPPChargeOptions

app = FastAPI(title="MPP session demo")
mpp = MPP(debug_mode=True, weak_debug_validation=True)

session_options = MPPChargeOptions(
    amount="0.02",
    currency="USD",
    description="Tokenized model inference call",
    session=True,
    max_amount="1.00",
    require_idempotency_key=True,
)


@app.post("/session/infer")
@mpp.charge(options=session_options)
async def infer(request: Request) -> dict[str, str]:
    return {"result": "Inference result after MPP authorization"}
