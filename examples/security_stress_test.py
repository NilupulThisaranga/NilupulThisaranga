"""Security stress test script for fastapi-mpp protected endpoints.

This script runs three focused abuse scenarios:
1) Malformed and oversized Authorization headers (up to 100KB blobs)
2) Challenge rate-limit saturation from one client IP
3) Massive replay attempts using the same receipt payload
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable

import httpx

logger = logging.getLogger("mpp_stress")


@dataclass
class AttackReport:
    name: str
    total_requests: int
    status_counts: Counter[int]
    avg_latency_ms: float
    p95_latency_ms: float
    block_code: int | None = None

    @property
    def block_rate(self) -> float:
        if self.block_code is None or self.total_requests == 0:
            return 0.0
        return self.status_counts.get(self.block_code, 0) / self.total_requests


async def run_attack(
    *,
    name: str,
    total_requests: int,
    concurrency: int,
    request_factory: Callable[[int], tuple[str, dict[str, str]]],
    timeout_seconds: float,
    rate_per_second: int | None = None,
) -> AttackReport:
    latencies: list[float] = []
    status_counts: Counter[int] = Counter()
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        start_time = time.perf_counter()

        async def one_request(index: int) -> None:
            if rate_per_second is not None and rate_per_second > 0:
                target_offset = index / float(rate_per_second)
                now_offset = time.perf_counter() - start_time
                if target_offset > now_offset:
                    await asyncio.sleep(target_offset - now_offset)

            method, data = request_factory(index)
            url = data.pop("url")
            headers = data
            async with semaphore:
                started = time.perf_counter()
                try:
                    response = await client.request(method, url, headers=headers)
                    status_counts[response.status_code] += 1
                except Exception:
                    status_counts[0] += 1
                finally:
                    elapsed_ms = (time.perf_counter() - started) * 1000.0
                    latencies.append(elapsed_ms)

        await asyncio.gather(*(one_request(i) for i in range(total_requests)))

    if not latencies:
        avg_ms = 0.0
        p95_ms = 0.0
    else:
        avg_ms = statistics.fmean(latencies)
        p95_ms = statistics.quantiles(latencies, n=100)[94] if len(latencies) >= 20 else max(latencies)

    return AttackReport(
        name=name,
        total_requests=total_requests,
        status_counts=status_counts,
        avg_latency_ms=avg_ms,
        p95_latency_ms=p95_ms,
    )


def _encode_receipt(receipt: dict[str, str]) -> str:
    payload = json.dumps(receipt, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")


def _format_counts(counts: Counter[int]) -> str:
    ordered = sorted(counts.items(), key=lambda kv: kv[0])
    return ", ".join(f"{status}:{count}" for status, count in ordered)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Stress-test a fastapi-mpp endpoint")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Target base URL")
    parser.add_argument("--path", default="/premium", help="Protected path to attack")
    parser.add_argument("--requests", type=int, default=5000, help="Requests per attack scenario")
    parser.add_argument("--concurrency", type=int, default=200, help="Concurrent request workers")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds")
    parser.add_argument("--replay-rps", type=int, default=100, help="Replay burst rate (req/s)")
    parser.add_argument("--log-level", default="INFO", help="Logging level")

    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    target_url = f"{args.base_url.rstrip('/')}{args.path}"
    logger.info("Target endpoint: %s", target_url)

    # Scenario 1: malformed and giant auth headers.
    giant_blob = "A" * (100 * 1024)

    def malformed_factory(i: int) -> tuple[str, dict[str, str]]:
        if i % 2 == 0:
            auth = f"Payment credential={giant_blob}"
        else:
            auth = f"Bearer {giant_blob}"
        return "GET", {"url": target_url, "Authorization": auth}

    malformed_report = await run_attack(
        name="malformed_headers",
        total_requests=args.requests,
        concurrency=args.concurrency,
        request_factory=malformed_factory,
        timeout_seconds=args.timeout,
    )

    # Scenario 2: challenge flood to trigger 429 responses.
    def challenge_flood_factory(_: int) -> tuple[str, dict[str, str]]:
        return "GET", {"url": target_url}

    challenge_report = await run_attack(
        name="challenge_flood",
        total_requests=args.requests,
        concurrency=args.concurrency,
        request_factory=challenge_flood_factory,
        timeout_seconds=args.timeout,
    )
    challenge_report.block_code = 429

    # Scenario 3: replay one receipt at 100 req/s (configurable) to trigger 409.
    receipt = {
        "id": "stress-replay-receipt",
        "provider": "tempo",
        "amount": "0.10",
        "currency": "USD",
    }
    encoded = _encode_receipt(receipt)
    replay_headers = {"Authorization": f'Payment credential="{encoded}"'}

    replay_total = max(args.requests, args.replay_rps)
    replay_concurrency = min(args.concurrency, max(1, args.replay_rps))

    def replay_factory(_: int) -> tuple[str, dict[str, str]]:
        return "GET", {"url": target_url, **replay_headers}

    replay_report = await run_attack(
        name="replay_attack",
        total_requests=replay_total,
        concurrency=replay_concurrency,
        request_factory=replay_factory,
        timeout_seconds=args.timeout,
        rate_per_second=args.replay_rps,
    )
    replay_report.block_code = 409

    reports = [malformed_report, challenge_report, replay_report]

    print("\n=== fastapi-mpp security stress report ===")
    for report in reports:
        print(f"\n[{report.name}]")
        print(f"total_requests: {report.total_requests}")
        print(f"status_counts: {_format_counts(report.status_counts)}")
        print(f"avg_latency_ms: {report.avg_latency_ms:.2f}")
        print(f"p95_latency_ms: {report.p95_latency_ms:.2f}")
        if report.block_code is not None:
            print(f"block_rate_{report.block_code}: {report.block_rate * 100:.2f}%")

    print("\n=== Required security KPIs ===")
    print(f"average_response_time_ms: {statistics.fmean([r.avg_latency_ms for r in reports]):.2f}")
    print(f"challenge_block_success_429: {challenge_report.block_rate * 100:.2f}%")
    print(f"replay_block_success_409: {replay_report.block_rate * 100:.2f}%")


if __name__ == "__main__":
    asyncio.run(main())
