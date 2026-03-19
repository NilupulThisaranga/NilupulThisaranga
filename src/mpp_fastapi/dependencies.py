"""Dependency helpers for wallet config and receipt extraction."""

from __future__ import annotations

import base64
import json
import re
from functools import lru_cache
from typing import Any

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field

from .types import MPPReceipt

HEADER_MAX_BYTES = 8 * 1024
_PAYMENT_AUTH_RE = re.compile(r'^\s*Payment\s+credential="(?P<credential>[^"]+)"\s*$')


class WalletConfig(BaseModel):
    """Runtime configuration for optional wallet/provider integrations."""

    model_config = ConfigDict(extra="forbid")

    auto_retry_enabled: bool = Field(default=False)

    tempo_wallet_url: str | None = None
    tempo_api_key: str | None = None

    stripe_shared_payment_token: str | None = None
    session_secret: str | None = None

    @property
    def has_any_wallet(self) -> bool:
        return bool(self.tempo_wallet_url or self.stripe_shared_payment_token)


@lru_cache(maxsize=1)
def get_wallet_config() -> WalletConfig:
    """Reads wallet config from environment variables once per process."""

    import os

    return WalletConfig(
        auto_retry_enabled=os.getenv("MPP_AUTO_RETRY", "false").lower() == "true",
        tempo_wallet_url=os.getenv("TEMPO_WALLET_URL"),
        tempo_api_key=os.getenv("TEMPO_API_KEY"),
        stripe_shared_payment_token=os.getenv("STRIPE_SHARED_PAYMENT_TOKEN"),
        session_secret=os.getenv("MPP_SESSION_SECRET"),
    )


def extract_receipt_from_request(
    request: Request,
    *,
    allow_legacy_headers: bool,
) -> MPPReceipt | None:
    """Parses receipt headers accepted by the middleware.

    Supported formats:
    - Authorization: Payment credential="<base64url-json>"
    - Payment-Receipt: raw/base64url JSON payload
    - X-MPP-Receipt: raw JSON payload
    - X-MPP-Receipt: base64url-encoded JSON payload
    """

    auth_value = request.headers.get("authorization")
    if auth_value:
        _assert_header_size("Authorization", auth_value)
        credential = extract_payment_credential(auth_value)
        parsed_payload = _parse_json_or_base64_json(credential)
        return MPPReceipt.model_validate(parsed_payload)

    raw_value = request.headers.get("payment-receipt")
    if raw_value:
        _assert_header_size("Payment-Receipt", raw_value)
        parsed_payload = _parse_json_or_base64_json(raw_value)
        return MPPReceipt.model_validate(parsed_payload)

    if allow_legacy_headers:
        raw_value = request.headers.get("x-mpp-receipt")

    if not raw_value:
        return None

    _assert_header_size("X-MPP-Receipt", raw_value)

    parsed_payload = _parse_json_or_base64_json(raw_value)
    return MPPReceipt.model_validate(parsed_payload)


def extract_payment_credential(authorization_header: str) -> str:
    """Extracts credential from Authorization: Payment credential="..."."""

    match = _PAYMENT_AUTH_RE.match(authorization_header)
    if match is None:
        raise ValueError("Malformed Authorization header; expected Payment credential=\"...\"")
    return match.group("credential")


def _assert_header_size(name: str, value: str) -> None:
    if len(value.encode("utf-8")) > HEADER_MAX_BYTES:
        raise ValueError(f"{name} header exceeds {HEADER_MAX_BYTES} bytes")


def _parse_json_or_base64_json(value: str) -> dict[str, Any]:
    value = value.strip()

    if value.startswith("{"):
        return _loads_json(value)

    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Unable to decode X-MPP-Receipt header") from exc

    return _loads_json(decoded)


def _loads_json(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON in X-MPP-Receipt header") from exc

    if not isinstance(payload, dict):
        raise ValueError("Receipt payload must be a JSON object")
    return payload
