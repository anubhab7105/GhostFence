"""Reliability runner (Phase 7)."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path

from ..attack_lab.runner import run_scenario


async def main_async(runs: int, out: str):
    scenarios = ["s1", "s2", "s3"]
    modes = ["protected", "unprotected"]
    results = []
    for scenario in scenarios:
        for mode in modes:
            outcomes = []
            for _ in range(runs):
                r = await run_scenario(scenario, mode)
                outcomes.append(r["summary"])
            results.append({
                "scenario": scenario,
                "mode": mode,
                "runs": runs,
                "outcomes": outcomes,
            })
    payload = {
        "agent_type": "scripted-stub",
        "model_version": "scripted-agent (no live LLM)",
        "temperature": 0,
        "policy_version": "risk-v1",
        "unprotected_attack_success_rate": None,
        "note": "Stub agent; do not interpret as live LLM attack success.",
        "scenario_hashes": {s: hashlib.sha256(s.encode()).hexdigest() for s in scenarios},
        "results": results,
    }
    Path(out).write_text(json.dumps(payload, indent=2))
    print(json.dumps({"status": "done", "out": out, "runs": runs * len(scenarios) * len(modes)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--out", type=str, default="/tmp/ghostfence-reliability.json")
    args = parser.parse_args()
    asyncio.run(main_async(args.runs, args.out))


if __name__ == "__main__":
    main()