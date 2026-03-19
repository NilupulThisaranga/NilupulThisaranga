"""Core MPP integration for FastAPI endpoints."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps
from ipaddress import ip_address
from typing import Any

from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response

from .dependencies import (
    HEADER_MAX_BYTES,
    WalletConfig,
    extract_receipt_from_request,
    get_wallet_config,
)
from .exceptions import (
    IdempotencyConflictError,
    InvalidReceiptError,
    PaymentRequiredError,
    SessionBudgetExceededError,
    SessionNotFoundError,
)
from .types import MPPChallenge, MPPChargeOptions, MPPProvider, MPPReceipt, MPPSession

RouteCallable = Callable[..., Awaitable[Any]]
ReceiptValidator = Callable[[MPPReceipt, MPPChargeOptions, Request], Awaitable[None] | None]
logger = logging.getLogger(__name__)


class ChallengeRateLimitError(Exception):
    """Raised when challenge issuance crosses in-memory per-IP limits."""


class InMemoryIdempotencyStore:
    """Tracks idempotency key to receipt mapping."""

    def __init__(self) -> None:
        self._index: dict[str, str] = {}

    def assert_or_set(self, *, endpoint_key: str, idempotency_key: str, receipt_id: str) -> None:
        composite = f"{endpoint_key}:{idempotency_key}"
        known = self._index.get(composite)
        if known is None:
            self._index[composite] = receipt_id
            return

        if known != receipt_id:
            raise IdempotencyConflictError(
                "This Idempotency-Key was already used with another receipt"
            )


class InMemorySessionStore:
    """In-memory budget session store (replaceable with Redis)."""

    def __init__(self) -> None:
        self._sessions: dict[str, MPPSession] = {}

    def upsert_authorized_session(
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

    def get(self, session_id: str) -> MPPSession:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise SessionNotFoundError(f"Unknown MPP session: {session_id}") from exc

    def consume(self, *, session_id: str, amount: Decimal, currency: str) -> MPPSession:
        session = self.get(session_id)

        if session.expires_at is not None and session.expires_at <= datetime.now(timezone.utc):
            raise SessionBudgetExceededError("Session expired")

        if session.currency.upper() != currency.upper():
            raise SessionBudgetExceededError("Session currency mismatch")

        if session.remaining_amount_decimal < amount:
            raise SessionBudgetExceededError("Session budget exceeded")

        session.spent_amount = str(session.spent_amount_decimal + amount)
        self._sessions[session_id] = session
        return session


class InMemoryReceiptReplayStore:
    """Tracks consumed receipts until expiry to mitigate replay attacks."""

    def __init__(self) -> None:
        self._consumed: dict[str, float] = {}

    def consume_once(self, *, receipt_key: str, expires_at: datetime) -> None:
        now_ts = time.time()
        self._prune(now_ts)
        expires_ts = expires_at.timestamp()

        if expires_ts <= now_ts:
            raise InvalidReceiptError("Receipt is expired")

        known = self._consumed.get(receipt_key)
        if known is not None and known > now_ts:
            raise IdempotencyConflictError("Receipt was already consumed")

        self._consumed[receipt_key] = expires_ts

    def _prune(self, now_ts: float) -> None:
        stale_keys = [key for key, exp_ts in self._consumed.items() if exp_ts <= now_ts]
        for stale in stale_keys:
            self._consumed.pop(stale, None)


class InMemoryChallengeStore:
    """Tracks issued challenges so receipts are bound to prior 402 challenges."""

    def __init__(self) -> None:
        self._issued: dict[str, tuple[float, dict[str, Any]]] = {}

    def issue(self, *, challenge: MPPChallenge) -> None:
        self._issued[challenge.challenge_id] = (
            challenge.expires_at.timestamp(),
            {
                "method": challenge.method,
                "path": challenge.path,
                "amount": challenge.amount,
                "currency": challenge.currency,
            },
        )

    def consume_and_validate(
        self,
        *,
        challenge_id: str,
        method: str,
        path: str,
        amount: Decimal,
        currency: str,
    ) -> None:
        now_ts = time.time()
        self._prune(now_ts)

        issued = self._issued.pop(challenge_id, None)
        if issued is None:
            raise InvalidReceiptError("Unknown or expired challenge id")

        _, expected = issued
        if expected["method"] != method or expected["path"] != path:
            raise InvalidReceiptError("Receipt challenge is bound to another route")
        if Decimal(expected["amount"]) != amount:
            raise InvalidReceiptError("Receipt challenge amount mismatch")
        if str(expected["currency"]).upper() != currency.upper():
            raise InvalidReceiptError("Receipt challenge currency mismatch")

    def _prune(self, now_ts: float) -> None:
        stale_keys = [key for key, (exp_ts, _) in self._issued.items() if exp_ts <= now_ts]
        for stale in stale_keys:
            self._issued.pop(stale, None)


class InMemoryChallengeRateLimiter:
    """Simple fixed-window challenge rate limiter (per IP/minute)."""

    def __init__(self, *, max_per_minute: int = 10) -> None:
        self.max_per_minute = max_per_minute
        self._state: dict[str, tuple[int, int]] = {}

    def assert_within_limit(self, *, client_ip: str) -> None:
        minute_bucket = int(time.time() // 60)
        bucket, count = self._state.get(client_ip, (minute_bucket, 0))

        if bucket != minute_bucket:
            self._state[client_ip] = (minute_bucket, 1)
            return

        if count >= self.max_per_minute:
            raise ChallengeRateLimitError("Too many payment challenges from this IP")

        self._state[client_ip] = (bucket, count + 1)


class HMACSessionSigner:
    """Signs and verifies opaque session tokens."""

    def __init__(self, *, secret: str) -> None:
        self._secret = secret.encode("utf-8")

    def encode(self, claims: dict[str, Any]) -> str:
        payload_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload = base64.urlsafe_b64encode(payload_json).decode("utf-8").rstrip("=")
        signature = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).digest()
        sig = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")
        return f"{payload}.{sig}"

    def decode_and_verify(self, token: str) -> dict[str, Any]:
        try:
            payload, signature = token.split(".", maxsplit=1)
        except ValueError as exc:
            raise SessionNotFoundError("Malformed session token") from exc

        expected = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).digest()
        expected_sig = base64.urlsafe_b64encode(expected).decode("utf-8").rstrip("=")
        if not hmac.compare_digest(signature, expected_sig):
            raise SessionNotFoundError("Invalid session token signature")

        padded = payload + "=" * (-len(payload) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
            claims = json.loads(decoded)
        except Exception as exc:  # noqa: BLE001
            raise SessionNotFoundError("Malformed session token payload") from exc

        if not isinstance(claims, dict):
            raise SessionNotFoundError("Malformed session token claims")
        return claims


class MPP:
    """Main integration object exposing the @charge decorator."""

    def __init__(
        self,
        *,
        wallet_config: WalletConfig | None = None,
        receipt_validator: ReceiptValidator | None = None,
        session_store: InMemorySessionStore | None = None,
        idempotency_store: InMemoryIdempotencyStore | None = None,
        replay_store: InMemoryReceiptReplayStore | None = None,
        challenge_store: InMemoryChallengeStore | None = None,
        challenge_rate_limiter: InMemoryChallengeRateLimiter | None = None,
        protocol_version: str = "2026-03-19",
        realm: str = "MyAPI",
        allow_legacy_headers: bool = True,
        debug_mode: bool = False,
        weak_debug_validation: bool = False,
        session_ttl_seconds: int = 900,
        challenge_ttl_seconds: int = 300,
    ) -> None:
        self.wallet_config = wallet_config or get_wallet_config()
        self.allow_legacy_headers = allow_legacy_headers
        self.debug_mode = debug_mode
        self.weak_debug_validation = weak_debug_validation
        self.realm = realm
        self.session_ttl_seconds = session_ttl_seconds
        self.challenge_ttl_seconds = challenge_ttl_seconds

        self.receipt_validator = receipt_validator or _load_default_tempo_validator()

        self.session_store = session_store or InMemorySessionStore()
        self.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
        self.replay_store = replay_store or InMemoryReceiptReplayStore()
        self.challenge_store = challenge_store or InMemoryChallengeStore()
        self.challenge_rate_limiter = challenge_rate_limiter or InMemoryChallengeRateLimiter()
        self.protocol_version = protocol_version

        self._session_signer: HMACSessionSigner | None = None
        if self.wallet_config.session_secret:
            self._session_signer = HMACSessionSigner(secret=self.wallet_config.session_secret)

        if not self.debug_mode and self.receipt_validator is None:
            raise RuntimeError(
                "receipt_validator is required in production mode. "
                "Install fastapi-mpp[tempo] or pass receipt_validator explicitly."
            )

        if not self.debug_mode and self._session_signer is None:
            logger.warning(
                "MPP_SESSION_SECRET is not configured; session mode will fail closed for security."
            )

        if self.wallet_config.auto_retry_enabled:
            logger.warning(
                "MPP_AUTO_RETRY is enabled, but retries are client/wallet-driven; "
                "server-side auto-retry is not implemented."
            )

        logger.warning(
            "Using in-memory replay/session stores. This is not horizontally safe; "
            "use Redis in production."
        )

    def charge(
        self,
        *,
        amount: str | float | None = None,
        currency: str = "USD",
        description: str | None = None,
        options: MPPChargeOptions | None = None,
    ) -> Callable[[RouteCallable], RouteCallable]:
        """Decorator to mark an endpoint as payable via MPP."""

        if options is None:
            if amount is None:
                raise ValueError("Either options or amount must be provided")
            options = MPPChargeOptions(amount=amount, currency=currency, description=description)

        charge_options = options

        def decorator(func: RouteCallable) -> RouteCallable:
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                request = _extract_request(args=args, kwargs=kwargs)

                if request is None:
                    raise HTTPException(
                        status_code=500,
                        detail="MPP decorator requires a FastAPI Request parameter",
                    )

                try:
                    await self._authorize_request(request=request, options=charge_options)
                except PaymentRequiredError as exc:
                    challenge = MPPChallenge.model_validate(exc.challenge)
                    encoded_challenge = _base64url_json(challenge.model_dump(mode="json"))
                    headers = {
                        "Cache-Control": "no-store",
                        "WWW-Authenticate": (
                            f'Payment challenge="{encoded_challenge}", '
                            f'realm="{self.realm}", expires="{challenge.expires_at.isoformat()}"'
                        ),
                    }
                    if self.allow_legacy_headers:
                        headers["X-MPP-Version"] = self.protocol_version
                        headers["X-MPP-Retryable"] = (
                            str(self.wallet_config.auto_retry_enabled).lower()
                        )

                    return JSONResponse(
                        status_code=402,
                        content=challenge.model_dump(mode="json"),
                        headers=headers,
                    )
                except InvalidReceiptError as exc:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "invalid_receipt",
                            "message": str(exc),
                            "mpp_version": self.protocol_version,
                        },
                        headers={"Cache-Control": "no-store"},
                    )
                except IdempotencyConflictError as exc:
                    return JSONResponse(
                        status_code=409,
                        content={
                            "error": "receipt_replay",
                            "message": str(exc),
                            "mpp_version": self.protocol_version,
                        },
                        headers={"Cache-Control": "no-store"},
                    )
                except ChallengeRateLimitError as exc:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "rate_limited",
                            "message": str(exc),
                        },
                        headers={"Cache-Control": "no-store", "Retry-After": "60"},
                    )

                result = await func(*args, **kwargs)
                receipt = request.state._mpp_receipt if hasattr(request.state, "_mpp_receipt") else None
                session_id = (
                    request.state._mpp_session_id if hasattr(request.state, "_mpp_session_id") else None
                )
                return _attach_payment_headers(
                    result=result,
                    receipt=receipt,
                    session_id=session_id,
                    allow_legacy_headers=self.allow_legacy_headers,
                )

            return wrapper

        return decorator

    async def _authorize_request(self, *, request: Request, options: MPPChargeOptions) -> None:
        self._assert_secure_transport(request)
        self._assert_header_sizes(request)

        endpoint_key = f"{request.method}:{request.url.path}"
        idempotency_key = request.headers.get("idempotency-key")

        if options.require_idempotency_key and not idempotency_key:
            raise InvalidReceiptError("Missing Idempotency-Key header")

        requested_amount = options.amount_decimal
        currency = options.currency.upper()

        session_header = _extract_session_header(request) or options.session_id
        if session_header:
            try:
                self._consume_session(
                    request=request,
                    options=options,
                    session_token=session_header,
                    amount=requested_amount,
                    currency=currency,
                )
                request.state._mpp_session_id = session_header
                return
            except (SessionNotFoundError, SessionBudgetExceededError):
                # Missing or exhausted session should trigger a fresh payment challenge.
                pass

        receipt = _extract_receipt_or_none(request, allow_legacy_headers=self.allow_legacy_headers)
        if receipt is None:
            client_ip = _extract_client_ip(request)
            self.challenge_rate_limiter.assert_within_limit(client_ip=client_ip)
            raise PaymentRequiredError(self._build_402_challenge(request=request, options=options))

        await self._validate_receipt(receipt=receipt, options=options, request=request)
        request.state._mpp_receipt = receipt

        if idempotency_key:
            self.idempotency_store.assert_or_set(
                endpoint_key=endpoint_key,
                idempotency_key=idempotency_key,
                receipt_id=receipt.id,
            )

        replay_key = f"{receipt.id}:{idempotency_key or receipt.idempotency_key or '-'}"
        receipt_expires_at = receipt.expires_at or (
            datetime.now(timezone.utc) + timedelta(seconds=self.challenge_ttl_seconds)
        )
        self.replay_store.consume_once(receipt_key=replay_key, expires_at=receipt_expires_at)

        if options.session:
            if self._session_signer is None:
                raise InvalidReceiptError("Session mode requires MPP_SESSION_SECRET")

            authorized_budget = receipt.authorized_max_amount_decimal or options.max_amount_decimal
            if authorized_budget is not None:
                source = receipt.source
                if source is None and isinstance(receipt.metadata, dict):
                    source = receipt.metadata.get("source")
                session_id = self._issue_session(
                    request=request,
                    options=options,
                    receipt=receipt,
                    max_amount=authorized_budget,
                    source=source,
                )
                self.session_store.upsert_authorized_session(
                    session_id=session_id,
                    provider=receipt.provider,
                    currency=currency,
                    route_scope=request.url.path,
                    source=source,
                    expires_at=datetime.now(timezone.utc)
                    + timedelta(seconds=self.session_ttl_seconds),
                    max_amount=authorized_budget,
                    metadata={"receipt_id": receipt.id},
                )
                self.session_store.consume(
                    session_id=session_id,
                    amount=requested_amount,
                    currency=currency,
                )
                request.state._mpp_session_id = session_id

    async def _validate_receipt(
        self,
        *,
        receipt: MPPReceipt,
        options: MPPChargeOptions,
        request: Request,
    ) -> None:
        """Validates receipt content against charge options and optional provider hooks."""

        if receipt.currency.upper() != options.currency.upper():
            raise InvalidReceiptError("Receipt currency does not match endpoint currency")

        if receipt.amount_decimal < options.amount_decimal:
            raise InvalidReceiptError("Receipt amount is lower than required amount")

        if options.provider and receipt.provider != options.provider:
            raise InvalidReceiptError("Receipt provider does not match required provider")

        if receipt.expires_at is not None and receipt.expires_at <= datetime.now(timezone.utc):
            raise InvalidReceiptError("Receipt has expired")

        if not self.debug_mode:
            challenge_id = receipt.challenge_id
            if not challenge_id:
                raise InvalidReceiptError("Receipt must include challenge_id")

            self.challenge_store.consume_and_validate(
                challenge_id=challenge_id,
                method=request.method,
                path=request.url.path,
                amount=options.amount_decimal,
                currency=options.currency,
            )

        if self.receipt_validator is not None:
            maybe_awaitable = self.receipt_validator(receipt, options, request)
            if maybe_awaitable is not None:
                await maybe_awaitable
        elif not self.weak_debug_validation:
            raise InvalidReceiptError("No receipt validator configured")

        logger.info(
            "Validated MPP receipt id=%s provider=%s path=%s",
            receipt.id,
            receipt.provider,
            request.url.path,
        )

    def _build_402_challenge(self, *, request: Request, options: MPPChargeOptions) -> dict[str, Any]:
        providers = ["tempo", "stripe"]
        if options.provider is not None:
            providers = [options.provider]

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.challenge_ttl_seconds)
        challenge = MPPChallenge(
            challenge_id=secrets.token_urlsafe(18),
            intent="mpp_charge",
            method=request.method,
            path=request.url.path,
            amount=str(options.amount_decimal),
            currency=options.currency.upper(),
            expires_at=expires_at,
            providers=providers,
            hints={},
        )

        payment_hints: dict[str, Any] = {}
        if "tempo" in providers:
            payment_hints["tempo"] = {
                "intent": {
                    "type": "mpp_charge",
                    "resource": request.url.path,
                },
                "wallet_url": self.wallet_config.tempo_wallet_url,
            }
        if "stripe" in providers:
            payment_hints["stripe"] = {
                "shared_payment_token": {
                    "configured": bool(self.wallet_config.stripe_shared_payment_token),
                }
            }

        challenge.hints = payment_hints
        self.challenge_store.issue(challenge=challenge)

        return challenge.model_dump(mode="json")

    def _assert_secure_transport(self, request: Request) -> None:
        if self.debug_mode:
            return

        forwarded = request.headers.get("x-forwarded-proto", "")
        forwarded_proto = forwarded.split(",", maxsplit=1)[0].strip().lower() if forwarded else ""
        if request.url.scheme == "https" or forwarded_proto == "https":
            return
        raise InvalidReceiptError("HTTPS is required for MPP payment endpoints")

    def _assert_header_sizes(self, request: Request) -> None:
        for header_name in ("authorization", "payment-receipt", "x-mpp-receipt"):
            raw = request.headers.get(header_name)
            if raw is None:
                continue
            if len(raw.encode("utf-8")) > HEADER_MAX_BYTES:
                raise InvalidReceiptError(
                    f"{header_name} header exceeds {HEADER_MAX_BYTES} bytes limit"
                )

    def _issue_session(
        self,
        *,
        request: Request,
        options: MPPChargeOptions,
        receipt: MPPReceipt,
        max_amount: Decimal,
        source: str | None,
    ) -> str:
        if self._session_signer is None:
            raise InvalidReceiptError("Session signer is not configured")

        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=self.session_ttl_seconds)
        claims = {
            "sid": secrets.token_urlsafe(18),
            "scp": request.url.path,
            "src": source,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "cur": options.currency.upper(),
            "max": str(max_amount),
            "prv": receipt.provider,
        }
        return self._session_signer.encode(claims)

    def _consume_session(
        self,
        *,
        request: Request,
        options: MPPChargeOptions,
        session_token: str,
        amount: Decimal,
        currency: str,
    ) -> None:
        if self._session_signer is None:
            raise SessionNotFoundError("Session signer is not configured")

        claims = self._session_signer.decode_and_verify(session_token)
        exp = int(claims.get("exp", 0))
        if exp <= int(time.time()):
            raise SessionBudgetExceededError("Session token expired")

        if str(claims.get("scp", "")) != request.url.path:
            raise SessionBudgetExceededError("Session token route scope mismatch")

        if str(claims.get("cur", "")).upper() != currency.upper():
            raise SessionBudgetExceededError("Session token currency mismatch")

        if options.provider is not None and str(claims.get("prv", "")) != options.provider:
            raise SessionBudgetExceededError("Session token provider mismatch")

        self.session_store.consume(
            session_id=session_token,
            amount=amount,
            currency=currency,
        )


def _extract_request(*, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Request | None:
    maybe_request = kwargs.get("request")
    if isinstance(maybe_request, Request):
        return maybe_request

    for arg in args:
        if isinstance(arg, Request):
            return arg
    return None


def _extract_receipt_or_none(request: Request, *, allow_legacy_headers: bool) -> MPPReceipt | None:
    try:
        return extract_receipt_from_request(request, allow_legacy_headers=allow_legacy_headers)
    except ValueError as exc:
        raise InvalidReceiptError(str(exc)) from exc


def _extract_session_header(request: Request) -> str | None:
    payment_session = request.headers.get("payment-session")
    if payment_session:
        return payment_session
    return request.headers.get("x-mpp-session-id")


def _extract_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        candidate = forwarded_for.split(",", maxsplit=1)[0].strip()
        try:
            return str(ip_address(candidate))
        except ValueError:
            pass

    client = request.client.host if request.client is not None else "127.0.0.1"
    try:
        return str(ip_address(client))
    except ValueError:
        return "127.0.0.1"


def _base64url_json(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(serialized).decode("utf-8").rstrip("=")


def _attach_payment_headers(
    *,
    result: Any,
    receipt: MPPReceipt | None,
    session_id: str | None,
    allow_legacy_headers: bool,
) -> Any:
    if receipt is None and session_id is None:
        return result

    headers: dict[str, str] = {}
    if receipt is not None:
        headers["Payment-Receipt"] = _base64url_json(receipt.model_dump(mode="json"))
        if allow_legacy_headers:
            headers["X-MPP-Receipt"] = headers["Payment-Receipt"]
    if session_id is not None:
        headers["Payment-Session"] = session_id
        if allow_legacy_headers:
            headers["X-MPP-Session-Id"] = session_id

    if isinstance(result, Response):
        for key, value in headers.items():
            result.headers[key] = value
        return result

    return JSONResponse(content=jsonable_encoder(result), headers=headers)


def _load_default_tempo_validator() -> ReceiptValidator | None:
    try:
        from pympp import validate as pympp_validate  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        return None

    async def _validator(receipt: MPPReceipt, _: MPPChargeOptions, __: Request) -> None:
        payload = receipt.model_dump(mode="json")
        try:
            result = pympp_validate(payload)
        except TypeError:
            result = pympp_validate(receipt)

        if isinstance(result, bool) and not result:
            raise InvalidReceiptError("pympp validation failed")

    return _validator
