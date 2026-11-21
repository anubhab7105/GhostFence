import os

import pytest
from fastapi.testclient import TestClient

from app.core.db import ping
from app.main import app

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def skip_if_no_db():
    try:
        ping()
    except Exception:
        pytest.skip("database unavailable")


def test_approve_route_not_reachable():
    with TestClient(app) as client:
        resp = client.get("/v1/approvals", headers={"X-API-Key": "dev-admin-key"})
        assert resp.status_code == 404


def test_require_approval_maps_to_block():
    with TestClient(app) as client:
        api_key = os.getenv("AGENT_API_KEY", os.getenv("GHOSTFENCE_AGENT_API_KEY", "dev-agent-key"))
        run_resp = client.post("/v1/runs", headers={"X-API-Key": api_key}, json={"agent_id": "invoice-agent", "task": "t", "mode": "enforce"})
        run = run_resp.json()
        token = run["run_token"]
        sid = run["session_id"]
        # Force a require_approval policy result to test mapping.
        from app.main import app_state
        original = app_state["policy_engine"].evaluate
        app_state["policy_engine"].evaluate = lambda **kwargs: {"decision": "require_approval", "reason_code": "approval_required", "risk_score": 0, "matched_rules": []}
        try:
            resp = client.post("/v1/execute", headers={"X-Run-Token": token}, json={
                "agent_id": "invoice-agent",
                "session_id": sid,
                "task": "t",
                "tool_name": "read_file",
                "arguments": {"path": "invoices/invoice-1.pdf"},
            })
        finally:
            app_state["policy_engine"].evaluate = original
        assert resp.status_code == 200
        assert resp.json()["decision"] == "block"
        assert resp.json()["reason_code"] == "approval_required"