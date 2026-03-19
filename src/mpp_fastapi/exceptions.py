"""Custom exceptions for fastapi-mpp."""

from __future__ import annotations

from typing import Any


class MPPError(Exception):
    """Base error for all MPP-related failures."""


class PaymentRequiredError(MPPError):
    """Raised when an endpoint requires payment before execution."""

    def __init__(self, challenge: dict[str, Any], message: str = "Payment required") -> None:
        super().__init__(message)
        self.challenge = challenge


class InvalidReceiptError(MPPError):
    """Raised when a provided MPP receipt is invalid or does not match constraints."""


class SessionNotFoundError(MPPError):
    """Raised when a session id is unknown."""


class SessionBudgetExceededError(MPPError):
    """Raised when a session cannot cover the requested charge amount."""


class IdempotencyConflictError(MPPError):
    """Raised when the same idempotency key is reused with different payment data."""
