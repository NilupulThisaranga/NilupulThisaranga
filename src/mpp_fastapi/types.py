"""Pydantic models for MPP FastAPI integration."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MPPProvider = Literal["tempo", "stripe"]


class MPPChargeOptions(BaseModel):
    """Defines how much and under which constraints an endpoint should charge."""

    model_config = ConfigDict(extra="forbid")

    amount: str | float = Field(..., description="Amount to charge for one call")
    currency: str = Field(default="USD", min_length=3, max_length=8)
    description: str | None = Field(default=None)
    provider: MPPProvider | None = Field(default=None)

    # Session controls.
    session: bool = Field(default=False)
    session_id: str | None = Field(default=None)
    max_amount: str | None = Field(
        default=None,
        description="Maximum authorized amount for a session pre-authorization",
    )

    # Idempotency / behavior hints.
    require_idempotency_key: bool = Field(default=False)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def amount_decimal(self) -> Decimal:
        return _to_positive_decimal(self.amount, field_name="amount")

    @property
    def max_amount_decimal(self) -> Decimal | None:
        if self.max_amount is None:
            return None
        return _to_positive_decimal(self.max_amount, field_name="max_amount")

    @model_validator(mode="after")
    def _validate_constraints(self) -> MPPChargeOptions:
        self.currency = self.currency.upper()
        _ = self.amount_decimal
        if self.max_amount is not None:
            max_amount = self.max_amount_decimal
            if max_amount is not None and max_amount < self.amount_decimal:
                raise ValueError("max_amount must be greater than or equal to amount")
        if self.session and self.max_amount is None:
            self.max_amount = str(self.amount)
        return self


class MPPReceipt(BaseModel):
    """Represents a parsed MPP receipt returned by a wallet/provider."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., min_length=1)
    provider: MPPProvider
    amount: str | float
    currency: str = Field(default="USD", min_length=3, max_length=8)

    session_id: str | None = Field(default=None)
    authorized_max_amount: str | None = Field(default=None)
    idempotency_key: str | None = Field(default=None)

    signature: str | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    source: str | None = None
    challenge_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def amount_decimal(self) -> Decimal:
        return _to_positive_decimal(self.amount, field_name="receipt.amount")

    @property
    def authorized_max_amount_decimal(self) -> Decimal | None:
        if self.authorized_max_amount is None:
            return None
        return _to_positive_decimal(
            self.authorized_max_amount,
            field_name="receipt.authorized_max_amount",
        )

    @model_validator(mode="after")
    def _normalize(self) -> MPPReceipt:
        self.currency = self.currency.upper()
        _ = self.amount_decimal
        if self.authorized_max_amount is not None:
            _ = self.authorized_max_amount_decimal
        return self


class MPPSession(BaseModel):
    """Lightweight in-memory representation of an MPP budget session."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    provider: MPPProvider
    currency: str
    route_scope: str
    source: str | None = None
    max_amount: str
    spent_amount: str = "0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def max_amount_decimal(self) -> Decimal:
        return _to_positive_decimal(self.max_amount, field_name="session.max_amount")

    @property
    def spent_amount_decimal(self) -> Decimal:
        return _to_non_negative_decimal(self.spent_amount, field_name="session.spent_amount")

    @property
    def remaining_amount_decimal(self) -> Decimal:
        return self.max_amount_decimal - self.spent_amount_decimal


class MPPChallenge(BaseModel):
    """Challenge payload encoded into WWW-Authenticate for 402 responses."""

    model_config = ConfigDict(extra="forbid")

    error: str = Field(default="payment_required")
    message: str = Field(default="This endpoint requires a valid payment credential")
    challenge_id: str = Field(..., min_length=8)
    intent: str = Field(default="mpp_charge")
    method: str = Field(..., min_length=1)
    path: str = Field(..., min_length=1)
    amount: str
    currency: str = Field(default="USD", min_length=3, max_length=8)
    expires_at: datetime
    providers: list[MPPProvider]
    hints: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _normalize(self) -> MPPChallenge:
        self.currency = self.currency.upper()
        return self


def _to_positive_decimal(value: str | float, field_name: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid decimal value") from exc

    if amount <= Decimal("0"):
        raise ValueError(f"{field_name} must be > 0")
    return amount


def _to_non_negative_decimal(value: str | float, field_name: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid decimal value") from exc

    if amount < Decimal("0"):
        raise ValueError(f"{field_name} must be >= 0")
    return amount
