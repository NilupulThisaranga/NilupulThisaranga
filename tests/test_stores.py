from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from mpp_fastapi.exceptions import (
    ChallengeRateLimitError,
    IdempotencyConflictError,
    InvalidReceiptError,
    SessionBudgetExceededError,
)
from mpp_fastapi.stores import InMemoryStore
from mpp_fastapi.types import MPPChallenge


@pytest.mark.asyncio
async def test_inmemory_store_replay_rejected_on_second_use() -> None:
    store = InMemoryStore()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)

    await store.consume_receipt_once(receipt_key="receipt:1", expires_at=expires_at)

    with pytest.raises(IdempotencyConflictError):
        await store.consume_receipt_once(receipt_key="receipt:1", expires_at=expires_at)


@pytest.mark.asyncio
async def test_inmemory_store_rejects_expired_receipt() -> None:
    store = InMemoryStore()
    expired = datetime.now(timezone.utc) - timedelta(seconds=1)

    with pytest.raises(InvalidReceiptError):
        await store.consume_receipt_once(receipt_key="expired:1", expires_at=expired)


@pytest.mark.asyncio
async def test_inmemory_store_session_budget_is_enforced() -> None:
    store = InMemoryStore()
    session_id = "s1"

    await store.upsert_authorized_session(
        session_id=session_id,
        provider="tempo",
        currency="USD",
        route_scope="/paid",
        source="tester",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        max_amount=Decimal("0.05"),
    )

    await store.consume_session_budget(session_id=session_id, amount=Decimal("0.02"), currency="USD")
    await store.consume_session_budget(session_id=session_id, amount=Decimal("0.03"), currency="USD")

    with pytest.raises(SessionBudgetExceededError):
        await store.consume_session_budget(
            session_id=session_id,
            amount=Decimal("0.01"),
            currency="USD",
        )


@pytest.mark.asyncio
async def test_inmemory_store_challenge_validation() -> None:
    store = InMemoryStore()
    challenge = MPPChallenge(
        challenge_id="challenge_test_1234",
        method="GET",
        path="/paid",
        amount="0.10",
        currency="USD",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
        providers=["tempo"],
    )

    await store.issue_challenge(challenge=challenge)

    await store.consume_and_validate_challenge(
        challenge_id=challenge.challenge_id,
        method="GET",
        path="/paid",
        amount=Decimal("0.10"),
        currency="USD",
    )

    with pytest.raises(InvalidReceiptError):
        await store.consume_and_validate_challenge(
            challenge_id=challenge.challenge_id,
            method="GET",
            path="/paid",
            amount=Decimal("0.10"),
            currency="USD",
        )


@pytest.mark.asyncio
async def test_inmemory_store_challenge_rate_limit() -> None:
    store = InMemoryStore()

    for _ in range(3):
        await store.assert_within_challenge_rate_limit(client_ip="127.0.0.1", max_per_minute=3)

    with pytest.raises(ChallengeRateLimitError):
        await store.assert_within_challenge_rate_limit(client_ip="127.0.0.1", max_per_minute=3)
