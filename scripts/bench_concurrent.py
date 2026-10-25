#!/usr/bin/env python3
"""Light concurrent load against a running agent (async httpx client)."""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import httpx


async def _one(client: httpx.AsyncClient, url: str) -> float:
    started = time.perf_counter()
    response = await client.get(url)
    response.raise_for_status()
    return (time.perf_counter() - started) * 1000.0


async def run(base: str, *, concurrency: int, requests: int) -> None:
    url = base.rstrip("/") + "/health"
    sem = asyncio.Semaphore(max(1, concurrency))
    latencies: list[float] = []

    async with httpx.AsyncClient(timeout=30.0) as client:

        async def task() -> None:
            async with sem:
                latencies.append(await _one(client, url))

        started = time.perf_counter()
        await asyncio.gather(*(task() for _ in range(requests)))
        elapsed = time.perf_counter() - started

    latencies.sort()
    p50 = latencies[len(latencies) // 2] if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    print(
        f"requests={requests} concurrency={concurrency} "
        f"elapsed_s={elapsed:.2f} rps={requests / elapsed:.1f} "
        f"p50_ms={p50:.1f} p95_ms={p95:.1f} mean_ms={statistics.mean(latencies):.1f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:18443")
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--requests", type=int, default=200)
    args = parser.parse_args()
    asyncio.run(
        run(args.base, concurrency=args.concurrency, requests=args.requests),
    )


if __name__ == "__main__":
    main()
