"""Benchmark runner (Phase 7)."""

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

from ..attack_lab.runner import ensure_app_state
from ..core.security import verify_run_token
from ..gateway.pipeline import execute_request
from ..gateway.runs import create_run
from ..schemas.api import ExecuteRequest


async def one(run_token_payload, session_id):
    start = time.perf_counter()
    await execute_request(
        ExecuteRequest(
            agent_id="invoice-agent",
            session_id=session_id,
            task="bench",
            tool_name="read_file",
            arguments={"path": "invoices/invoice-1.pdf"},
        ),
        run_token_payload,
    )
    return (time.perf_counter() - start) * 1000


async def main_async(iterations: int, concurrency: int, out: str):
    ensure_app_state()
    run = create_run("invoice-agent", "bench", {"mode": "enforce"})
    token_payload = verify_run_token(run["run_token"])
    session_id = run["session_id"]

    latencies = []
    sem = asyncio.Semaphore(concurrency)

    async def worker():
        async with sem:
            return await one(token_payload, session_id)

    tasks = [asyncio.create_task(worker()) for _ in range(iterations)]
    for fut in asyncio.as_completed(tasks):
        latencies.append(await fut)

    latencies.sort()
    def pct(p):
        return latencies[min(len(latencies)-1, int(p * len(latencies)))]
    result = {
        "iterations": iterations,
        "concurrency": concurrency,
        "postgres_audit_append": True,
        "http_layer": False,
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": max(latencies),
    }
    Path(out).write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--out", type=str, default="/tmp/ghostfence-bench.json")
    args = parser.parse_args()
    asyncio.run(main_async(args.iterations, args.concurrency, args.out))


if __name__ == "__main__":
    main()