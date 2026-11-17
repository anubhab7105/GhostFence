"""Benchmark runner (Phase 7)."""

import argparse
import asyncio
import statistics
import time

from ..core.security import verify_run_token
from ..gateway.pipeline import execute_request
from ..gateway.runs import create_run
from ..schemas.api import ExecuteRequest


async def main_async(iterations: int, out: str):
    run = create_run("invoice-agent", "bench", {"mode": "enforce"})
    token_payload = verify_run_token(run["run_token"])
    session_id = run["session_id"]
    latencies = []
    for _ in range(iterations):
        start = time.perf_counter()
        await execute_request(
            ExecuteRequest(
                agent_id="invoice-agent",
                session_id=session_id,
                task="bench",
                tool_name="read_file",
                arguments={"path": "invoices/invoice-1.pdf"},
            ),
            token_payload,
        )
        latencies.append((time.perf_counter() - start) * 1000)
    latencies.sort()
    p95 = latencies[int(0.95 * len(latencies)) - 1]
    result = {"iterations": iterations, "p50_ms": statistics.median(latencies), "p95_ms": p95, "max_ms": max(latencies)}
    import json
    from pathlib import Path
    Path(out).write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--out", type=str, default="/tmp/ghostfence-bench.json")
    args = parser.parse_args()
    asyncio.run(main_async(args.iterations, args.out))


if __name__ == "__main__":
    main()