"""LangGraph agent example that handles fastapi-mpp protected endpoints.

Flow:
1) Tool calls a protected API endpoint.
2) If API returns 402, tool decodes challenge and creates a mocked signed receipt.
3) Tool retries with Authorization: Payment credential="..." and returns protected data.

This example intentionally mocks signing logic to demonstrate integration behavior.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger("langgraph_mpp_example")


def _b64url_json(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _decode_b64url_json(value: str) -> dict[str, Any]:
    padded = value + "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")
    payload = json.loads(decoded)
    if not isinstance(payload, dict):
        raise ValueError("Decoded challenge must be a JSON object")
    return payload


def sign_mock_receipt(*, challenge: dict[str, Any], private_key: str) -> dict[str, Any]:
    """Builds a deterministic mock receipt signed with HMAC for demo purposes."""

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=2)
    receipt_payload = {
        "id": f"demo-{secrets.token_hex(8)}",
        "provider": "tempo",
        "amount": challenge.get("amount", "0.01"),
        "currency": challenge.get("currency", "USD"),
        "challenge_id": challenge["challenge_id"],
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "metadata": {
            "simulated": True,
            "method": challenge.get("method"),
            "path": challenge.get("path"),
        },
    }
    signature_input = json.dumps(receipt_payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    signature = hmac.new(private_key.encode("utf-8"), signature_input, hashlib.sha256).hexdigest()
    receipt_payload["signature"] = signature
    return receipt_payload


async def call_protected_endpoint(
    *,
    base_url: str,
    path: str,
    private_key: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    logger.info("Calling protected endpoint: %s", url)

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        first = await client.get(url)
        logger.info("Initial response status=%s", first.status_code)

        if first.status_code == 200:
            logger.info("Endpoint accepted first call without payment challenge")
            return {"status": "ok", "payload": first.json(), "used_payment_flow": False}

        if first.status_code != 402:
            message = (
                f"Expected 402 challenge or 200 success, got {first.status_code}: {first.text[:500]}"
            )
            logger.error(message)
            raise RuntimeError(message)

        challenge_header = first.headers.get("WWW-Authenticate", "")
        challenge_credential = None
        marker = 'challenge="'
        if marker in challenge_header:
            challenge_credential = challenge_header.split(marker, 1)[1].split('"', 1)[0]

        if not challenge_credential:
            logger.warning("No challenge found in WWW-Authenticate, attempting JSON body fallback")
            challenge = first.json()
        else:
            challenge = _decode_b64url_json(challenge_credential)

        if "challenge_id" not in challenge:
            raise RuntimeError("Challenge payload does not include challenge_id")

        receipt = sign_mock_receipt(challenge=challenge, private_key=private_key)
        encoded_receipt = _b64url_json(receipt)

        retry_headers = {"Authorization": f'Payment credential="{encoded_receipt}"'}
        second = await client.get(url, headers=retry_headers)
        logger.info("Retry response status=%s", second.status_code)

        if second.status_code != 200:
            message = f"Payment retry failed with {second.status_code}: {second.text[:500]}"
            logger.error(message)
            raise RuntimeError(message)

        return {
            "status": "ok",
            "payload": second.json(),
            "used_payment_flow": True,
            "payment_receipt_header_present": "Payment-Receipt" in second.headers,
        }


def _build_langgraph_agent() -> Any:
    """Builds a minimal LangGraph React-style agent with one payment-aware tool."""

    try:
        langchain_tools = importlib.import_module("langchain_core.tools")
        langchain_openai = importlib.import_module("langchain_openai")
        langgraph_prebuilt = importlib.import_module("langgraph.prebuilt")
    except ImportError as exc:
        raise RuntimeError(
            "Missing dependencies for this example. Install langgraph, langchain-core, "
            "and langchain-openai."
        ) from exc

    tool = getattr(langchain_tools, "tool")
    chat_openai_cls = getattr(langchain_openai, "ChatOpenAI")
    create_react_agent = getattr(langgraph_prebuilt, "create_react_agent")

    @tool
    async def fetch_paid_resource(query: str) -> str:
        """Fetch data from a protected API endpoint that may require MPP payment."""

        del query
        result = await call_protected_endpoint(
            base_url=_CONFIG["base_url"],
            path=_CONFIG["path"],
            private_key=_CONFIG["private_key"],
            timeout_seconds=_CONFIG["timeout"],
        )
        return json.dumps(result, separators=(",", ":"))

    model = chat_openai_cls(model="gpt-4o-mini", temperature=0)
    return create_react_agent(model=model, tools=[fetch_paid_resource])


_CONFIG: dict[str, Any] = {}


async def main() -> None:
    parser = argparse.ArgumentParser(description="LangGraph + fastapi-mpp integration demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Target API base URL")
    parser.add_argument("--path", default="/premium", help="Protected endpoint path")
    parser.add_argument("--private-key", default="demo-private-key", help="Mock signing key")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout seconds")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    _CONFIG.update(
        {
            "base_url": args.base_url,
            "path": args.path,
            "private_key": args.private_key,
            "timeout": args.timeout,
        }
    )

    agent = _build_langgraph_agent()

    prompt = (
        "Use the tool to call the protected API and return the final JSON response. "
        "If payment challenge is required, complete the payment flow automatically."
    )

    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": prompt}]},
    )

    print("\n=== LangGraph Agent Result ===")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
