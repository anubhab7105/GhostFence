import os
import yaml

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.db import ping
from app.main import app, app_state
from app.policy_engine.engine import PolicyEngine
from app.policy_engine.loaders import load_destinations, load_policy, load_registry, load_resources

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def skip_if_no_db():
    try:
        ping()
    except Exception:
        pytest.skip("database unavailable")


@pytest.fixture(scope="module", autouse=True)
def benign_policy():
    reg = load_registry("/home/babai/Desktop/codeing/GhostFence/tool-registry.yaml")
    pol = load_policy("/home/babai/Desktop/codeing/GhostFence/policies/benign.yaml")
    res = load_resources("/home/babai/Desktop/codeing/GhostFence/resources.yaml")
    dst = load_destinations("/home/babai/Desktop/codeing/GhostFence/destinations.yaml")
    engine = PolicyEngine(pol, reg, res, dst)
    engine.validate_startup()
    app_state["policy_engine"] = engine
    app_state["registry"] = reg
    app_state["resources"] = res
    app_state["destinations"] = dst
    yield


def test_benign_suite():
    with TestClient(app) as client:
        from app.policy_engine.loaders import load_destinations, load_policy, load_registry, load_resources
        from app.policy_engine.engine import PolicyEngine
        reg = load_registry("/home/babai/Desktop/codeing/GhostFence/tool-registry.yaml")
        pol = load_policy("/home/babai/Desktop/codeing/GhostFence/policies/benign.yaml")
        res = load_resources("/home/babai/Desktop/codeing/GhostFence/resources.yaml")
        dst = load_destinations("/home/babai/Desktop/codeing/GhostFence/destinations.yaml")
        engine = PolicyEngine(pol, reg, res, dst)
        engine.validate_startup()
        app_state["policy_engine"] = engine
        app_state["registry"] = reg
        app_state["resources"] = res
        app_state["destinations"] = dst
        from app.gateway.egress import EgressClient
        app_state["egress"] = EgressClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")), demo_allow=True)
        api_key = os.getenv("AGENT_API_KEY", os.getenv("GHOSTFENCE_AGENT_API_KEY", "dev-agent-key"))
        suite = yaml.safe_load(open("/home/babai/Desktop/codeing/GhostFence/attack-lab/benign-suite.yaml"))
        tasks = suite["tasks"]
        assert len(tasks) >= 30
        total = 0
        false_positives = []
        trifecta_fps = 0
        for task in tasks:
            run_resp = client.post("/v1/runs", headers={"X-API-Key": api_key}, json={"agent_id": "invoice-agent", "task": task["id"], "mode": "enforce"})
            assert run_resp.status_code == 200
            run = run_resp.json()
            token = run["run_token"]
            sid = run["session_id"]
            for step in task["steps"]:
                total += 1
                resp = client.post("/v1/execute", headers={"X-Run-Token": token}, json={
                    "agent_id": "invoice-agent",
                    "session_id": sid,
                    "task": task["id"],
                    "tool_name": step["tool"],
                    "arguments": step["args"],
                })
                assert resp.status_code == 200
                data = resp.json()
                if data["decision"] == "block":
                    false_positives.append({"task": task["id"], "tool": step["tool"], "reason": data["reason_code"]})
                    if data["reason_code"] == "tainted_sensitive_tool":
                        trifecta_fps += 1
        fp_rate = len(false_positives) / total if total else 0
        from collections import Counter
        print("reasons:", Counter(x["reason"] for x in false_positives))
        print(f"benign suite size={len(tasks)} steps={total} false_positives={len(false_positives)} fp_rate={fp_rate} trifecta_fps={trifecta_fps}")
        assert fp_rate < 0.05, false_positives