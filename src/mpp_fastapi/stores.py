"""Storage backends for replay protection, session budgets, challenges and rate limits."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable

from .exceptions import (
    ChallengeRateLimitError,
    IdempotencyConflictError,
    InvalidReceiptError,
    SessionBudgetExceededError,
    SessionNotFoundError,
)
from .types import MPPChallenge, MPPProvider, MPPSession


@runtime_checkable
class BaseStore(Protocol):
    """Persistence contract used by MPP for security-critical state."""

    async def consume_receipt_once(self, *, receipt_key: str, expires_at: datetime) -> None:
        """Marks a receipt as consumed once, raising on replay."""

    async def upsert_authorized_session(
        self,
        *,
        session_id: str,
        provider: MPPProvider,
        currency: str,
        route_scope: str,
        source: str | None,
        expires_at: datetime,
        max_amount: Decimal,
        metadata: dict[str, Any] | None = None,
    ) -> MPPSession:
        """Creates session budget if absent and returns the stored session."""

    async def consume_session_budget(
        self,
        *,
        session_id: str,
        amount: Decimal,
        currency: str,
    ) -> MPPSession:
        """Consumes session budget or raises if invalid/exhausted."""

    async def issue_challenge(self, *, challenge: MPPChallenge) -> None:
        """Stores challenge binding data until expiry."""

    async def consume_and_validate_challenge(
        self,
        *,
        challenge_id: str,
        method: str,
        path: str,
        amount: Decimal,
        currency: str,
    ) -> None:
        """Consumes challenge once and validates route and amount binding."""

    async def assert_within_challenge_rate_limit(
        self,
        *,
        client_ip: str,
        max_per_minute: int,
    ) -> None:
        """Enforces per-IP challenge issuance limits."""


class InMemoryStore:
    """In-memory backend for single-process development and tests."""

    def __init__(self) -> None:
        self._consumed: dict[str, float] = {}
        self._sessions: dict[str, MPPSession] = {}
        self._issued_challenges: dict[str, tuple[float, dict[str, Any]]] = {}
        self._rate_limits: dict[str, tuple[int, int]] = {}

    async def consume_receipt_once(self, *, receipt_key: str, expires_at: datetime) -> None:
        now_ts = time.time()
        self._prune_consumed(now_ts)

        expires_ts = expires_at.timestamp()
        if expires_ts <= now_ts:
            raise InvalidReceiptError("Receipt is expired")

        known = self._consumed.get(receipt_key)
        if known is not None and known > now_ts:
            raise IdempotencyConflictError("Receipt was already consumed")

        self._consumed[receipt_key] = expires_ts

    async def upsert_authorized_session(
        self,
        *,
        session_id: str,
        provider: MPPProvider,
        currency: str,
        route_scope: str,
        source: str | None,
        expires_at: datetime,
        max_amount: Decimal,
        metadata: dict[str, Any] | None = None,
    ) -> MPPSession:
        existing = self._sessions.get(session_id)
        if existing is not None:
            return existing

        session = MPPSession(
            session_id=session_id,
            provider=provider,
            currency=currency,
            route_scope=route_scope,
            source=source,
            expires_at=expires_at,
            max_amount=str(max_amount),
            metadata=metadata or {},
        )
        self._sessions[session_id] = session
        return session

    async def consume_session_budget(
        self,
        *,
        session_id: str,
        amount: Decimal,
        currency: str,
    ) -> MPPSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(f"Unknown MPP session: {session_id}")

        if session.expires_at is not None and session.expires_at <= datetime.now(timezone.utc):
            self._sessions.pop(session_id, None)
            raise SessionBudgetExceededError("Session expired")

        if session.currency.upper() != currency.upper():
            raise SessionBudgetExceededError("Session currency mismatch")

        if session.remaining_amount_decimal < amount:
            raise SessionBudgetExceededError("Session budget exceeded")

        session.spent_amount = str(session.spent_amount_decimal + amount)
        self._sessions[session_id] = session
        return session

    async def issue_challenge(self, *, challenge: MPPChallenge) -> None:
        self._issued_challenges[challenge.challenge_id] = (
            challenge.expires_at.timestamp(),
            {
                "method": challenge.method,
                "path": challenge.path,
                "amount": challenge.amount,
                "currency": challenge.currency,
            },
        )

    async def consume_and_validate_challenge(
        self,
        *,
        challenge_id: str,
        method: str,
        path: str,
        amount: Decimal,
        currency: str,
    ) -> None:
        now_ts = time.time()
        self._prune_challenges(now_ts)

        issued = self._issued_challenges.pop(challenge_id, None)
        if issued is None:
            raise InvalidReceiptError("Unknown or expired challenge id")

        _, expected = issued
        if expected["method"] != method or expected["path"] != path:
            raise InvalidReceiptError("Receipt challenge is bound to another route")
        if Decimal(expected["amount"]) != amount:
            raise InvalidReceiptError("Receipt challenge amount mismatch")
        if str(expected["currency"]).upper() != currency.upper():
            raise InvalidReceiptError("Receipt challenge currency mismatch")

    async def assert_within_challenge_rate_limit(
        self,
        *,
        client_ip: str,
        max_per_minute: int,
    ) -> None:
        minute_bucket = int(time.time() // 60)
        bucket, count = self._rate_limits.get(client_ip, (minute_bucket, 0))

        if bucket != minute_bucket:
            self._rate_limits[client_ip] = (minute_bucket, 1)
            return

        if count >= max_per_minute:
            raise ChallengeRateLimitError("Too many payment challenges from this IP")

        self._rate_limits[client_ip] = (bucket, count + 1)

    def _prune_consumed(self, now_ts: float) -> None:
        stale = [key for key, expires_ts in self._consumed.items() if expires_ts <= now_ts]
        for key in stale:
            self._consumed.pop(key, None)

    def _prune_challenges(self, now_ts: float) -> None:
        stale = [
            key
            for key, (expires_ts, _) in self._issued_challenges.items()
            if expires_ts <= now_ts
        ]
        for key in stale:
            self._issued_challenges.pop(key, None)


class RedisStore:
    """Redis-backed store suitable for multi-worker and multi-instance deployments."""

    def __init__(
        self,
        *,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "mpp",
        redis_client: Any | None = None,
    ) -> None:
        self._key_prefix = key_prefix.rstrip(":")
        if redis_client is not None:
            self._redis = redis_client
            return

        try:
            from redis.asyncio import Redis  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "redis package is required for RedisStore. Install fastapi-mpp[redis]."
            ) from exc

        self._redis = Redis.from_url(redis_url, decode_responses=True)

    async def consume_receipt_once(self, *, receipt_key: str, expires_at: datetime) -> None:
        ttl_seconds = _seconds_until(expires_at)
        if ttl_seconds <= 0:
            raise InvalidReceiptError("Receipt is expired")

        key = self._key("replay", receipt_key)
        set_ok = await self._redis.set(key, "1", ex=ttl_seconds, nx=True)
        if not set_ok:
            raise IdempotencyConflictError("Receipt was already consumed")

    async def upsert_authorized_session(
        self,
        *,
        session_id: str,
        provider: MPPProvider,
        currency: str,
        route_scope: str,
        source: str | None,
        expires_at: datetime,
        max_amount: Decimal,
        metadata: dict[str, Any] | None = None,
    ) -> MPPSession:
        key = self._key("session", session_id)
        existing_raw = await self._redis.get(key)
        if existing_raw is not None:
            return _decode_session(existing_raw)

        ttl_seconds = _seconds_until(expires_at)
        if ttl_seconds <= 0:
            raise SessionBudgetExceededError("Session expired")

        session = MPPSession(
            session_id=session_id,
            provider=provider,
            currency=currency,
            route_scope=route_scope,
            source=source,
            expires_at=expires_at,
            max_amount=str(max_amount),
            metadata=metadata or {},
        )
        encoded = _encode_session(session)
        created = await self._redis.set(key, encoded, ex=ttl_seconds, nx=True)
        if created:
            return session

        raced_raw = await self._redis.get(key)
        if raced_raw is None:
            raise SessionNotFoundError("Unable to persist session")
        return _decode_session(raced_raw)

    async def consume_session_budget(
        self,
        *,
        session_id: str,
        amount: Decimal,
        currency: str,
    ) -> MPPSession:
        key = self._key("session", session_id)

        while True:
            async with self._redis.pipeline() as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        raise SessionNotFoundError(f"Unknown MPP session: {session_id}")

                    ttl = await pipe.ttl(key)
                    if ttl <= 0:
                        await pipe.unwatch()
                        raise SessionBudgetExceededError("Session expired")

                    session = _decode_session(raw)
                    if session.currency.upper() != currency.upper():
                        await pipe.unwatch()
                        raise SessionBudgetExceededError("Session currency mismatch")

                    if session.expires_at is not None and session.expires_at <= datetime.now(
                        timezone.utc
                    ):
                        await pipe.unwatch()
                        raise SessionBudgetExceededError("Session expired")

                    if session.remaining_amount_decimal < amount:
                        await pipe.unwatch()
                        raise SessionBudgetExceededError("Session budget exceeded")

                    session.spent_amount = str(session.spent_amount_decimal + amount)
                    encoded = _encode_session(session)

                    pipe.multi()
                    pipe.set(key, encoded, ex=ttl)
                    await pipe.execute()
                    return session
                except SessionNotFoundError:
                    raise
                except SessionBudgetExceededError:
                    raise
                except Exception as exc:
                    # Retry only when Redis watch detects a write race.
                    if exc.__class__.__name__ != "WatchError":
                        raise

    async def issue_challenge(self, *, challenge: MPPChallenge) -> None:
        key = self._key("challenge", challenge.challenge_id)
        ttl_seconds = _seconds_until(challenge.expires_at)
        if ttl_seconds <= 0:
            return

        payload = json.dumps(
            {
                "method": challenge.method,
                "path": challenge.path,
                "amount": challenge.amount,
                "currency": challenge.currency,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        await self._redis.set(key, payload, ex=ttl_seconds)

    async def consume_and_validate_challenge(
        self,
        *,
        challenge_id: str,
        method: str,
        path: str,
        amount: Decimal,
        currency: str,
    ) -> None:
        key = self._key("challenge", challenge_id)

        getdel = getattr(self._redis, "getdel", None)
        if callable(getdel):
            raw = await getdel(key)
        else:
            raw = await self._redis.eval(
                "local v=redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); end; return v",
                1,
                key,
            )
        if raw is None:
            raise InvalidReceiptError("Unknown or expired challenge id")

        try:
            expected = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise InvalidReceiptError("Stored challenge is malformed") from exc

        if expected.get("method") != method or expected.get("path") != path:
            raise InvalidReceiptError("Receipt challenge is bound to another route")
        if Decimal(str(expected.get("amount", "0"))) != amount:
            raise InvalidReceiptError("Receipt challenge amount mismatch")
        if str(expected.get("currency", "")).upper() != currency.upper():
            raise InvalidReceiptError("Receipt challenge currency mismatch")

    async def assert_within_challenge_rate_limit(
        self,
        *,
        client_ip: str,
        max_per_minute: int,
    ) -> None:
        minute_bucket = int(time.time() // 60)
        key = self._key("ratelimit", f"{client_ip}:{minute_bucket}")

        count = int(await self._redis.incr(key))
        if count == 1:
            await self._redis.expire(key, 120)

        if count > max_per_minute:
            raise ChallengeRateLimitError("Too many payment challenges from this IP")

    async def close(self) -> None:
        """Closes underlying Redis connections."""

        close = getattr(self._redis, "aclose", None)
        if callable(close):
            await close()
            return

        legacy_close = getattr(self._redis, "close", None)
        if callable(legacy_close):
            maybe_awaitable = legacy_close()
            if maybe_awaitable is not None:
                await maybe_awaitable

    def _key(self, namespace: str, identifier: str) -> str:
        return f"{self._key_prefix}:{namespace}:{identifier}"


def _seconds_until(expires_at: datetime) -> int:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    delta = expires_at - datetime.now(timezone.utc)
    return max(0, int(delta.total_seconds()))


def _encode_session(session: MPPSession) -> str:
    return json.dumps(session.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)


def _decode_session(raw: str) -> MPPSession:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SessionNotFoundError("Stored session data is malformed") from exc
    return MPPSession.model_validate(payload)
