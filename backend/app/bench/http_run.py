"""HTTP benchmark over uvicorn with real Postgres (Phase 7)."""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[2]
ROOT = BACKEND.parent


async def main_async(iterations, concurrency, out):
    env = dict(os.environ)
    db_url = env.get("DATABASE_URL", f"postgresql+psycopg://{os.getenv('USER','babai')}@/ghostfence_test?host=/tmp/opencode&port=5433")
    env.setdefault("DATABASE_URL", db_url)
    env.setdefault("TOOL_REGISTRY_PATH", str(ROOT / "tool-registry.yaml"))
    env.setdefault("POLICY_PATH", str(ROOT / "policies" / "example.yaml"))
    env.setdefault("RESOURCES_PATH", str(ROOT / "resources.yaml"))
    env.setdefault("DESTINATIONS_PATH", str(ROOT / "destinations.yaml"))
    env.setdefault("ADMIN_API_KEY", "dev-admin-key")
    env.setdefault("APPROVER_API_KEY", "dev-approver-key")
    env.setdefault("AGENT_API_KEY", "dev-agent-key")
    env.setdefault("RUN_TOKEN_SECRET", "change-me-run-token-secret")
    env.setdefault("AUDIT_HMAC_KEY", "change-me-audit-hmac-key")

    server_cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8124"]
    proc = subprocess.Popen(server_cmd, cwd=str(BACKEND), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # wait health
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            r = httpx.get("http://127.0.0.1:8124/health", timeout=2)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        proc.kill()
        raise RuntimeError("gateway not healthy")

    # create run
    r = httpx.post("http://127.0.0.1:8124/v1/runs", headers={"X-API-Key": env["AGENT_API_KEY"]}, json={"agent_id": "invoice-agent", "task": "bench", "mode": "enforce"}, timeout=10)
    r.raise_for_status()
    run = r.json()
    token = run["run_token"]
    session_id = run["session_id"]

    sem = asyncio.Semaphore(concurrency)
    latencies = []
    lock_waits = []
    lock_holds = []

    async def one(client):
        async with sem:
            start = time.perf_counter()
            resp = await client.post("http://127.0.0.1:8124/v1/execute", headers={"X-Run-Token": token}, json={
                "agent_id": "invoice-agent",
                "session_id": session_id,
                "task": "bench",
                "tool_name": "read_file",
                "arguments": {"path": "invoices/invoice-1.pdf"},
            })
            elapsed = (time.perf_counter() - start) * 1000.0
            data = resp.json()
            return elapsed, data.get("audit_lock_wait_ms"), data.get("audit_lock_hold_ms")

    wall_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=30) as client:
        tasks = [asyncio.create_task(one(client)) for _ in range(iterations)]
        for fut in asyncio.as_completed(tasks):
            elapsed, lw, lh = await fut
            latencies.append(elapsed)
            if lw is not None:
                lock_waits.append(lw)
            if lh is not None:
                lock_holds.append(lh)
    wall_duration = time.perf_counter() - wall_start

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()

    latencies.sort()
    def pct(p):
        return latencies[min(len(latencies)-1, int(p * len(latencies)))]
    throughput = iterations / wall_duration if wall_duration > 0 else 0

    git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT)).decode().strip()

    result = {
        "git_sha": git_sha,
        "server_start_command": " ".join(server_cmd),
        "client_command": " ".join(sys.argv),
        "concurrency_model": "asyncio with Semaphore; 8 truly concurrent in-flight requests",
        "iterations": iterations,
        "concurrency": concurrency,
        "wall_clock_duration_s": wall_duration,
        "throughput_rps": throughput,
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": max(latencies),
        "lock_wait_p50_ms": (sorted(lock_waits)[len(lock_waits)//2] if lock_waits else None),
        "lock_wait_p95_ms": (sorted(lock_waits)[int(0.95*len(lock_waits))-1] if lock_waits else None),
        "lock_hold_p50_ms": (sorted(lock_holds)[len(lock_holds)//2] if lock_holds else None),
        "lock_hold_p95_ms": (sorted(lock_holds)[int(0.95*len(lock_holds))-1] if lock_holds else None),
        "raw_latencies_ms": latencies,
    }
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_path = Path(out) if out else (ROOT / "attack-lab" / "results" / f"bench-{ts}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ["iterations","concurrency","p50_ms","p95_ms","p99_ms","throughput_rps","lock_wait_p50_ms","lock_wait_p95_ms"]}, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--out", type=str, default="")
    args = parser.parse_args()
    asyncio.run(main_async(args.iterations, args.concurrency, args.out))


if __name__ == "__main__":
    main()