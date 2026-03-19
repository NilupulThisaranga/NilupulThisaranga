"""Convenience decorator helpers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from .core import MPP
from .types import MPPChargeOptions

_default_mpp = MPP(debug_mode=True, weak_debug_validation=True)
RouteCallable = Callable[..., Awaitable[Any]]


def charge(
    *,
    amount: str | float | None = None,
    currency: str = "USD",
    description: str | None = None,
    options: MPPChargeOptions | None = None,
) -> Callable[[RouteCallable], RouteCallable]:
    """Module-level shortcut so users can import a single decorator."""

    return _default_mpp.charge(
        amount=amount,
        currency=currency,
        description=description,
        options=options,
    )
