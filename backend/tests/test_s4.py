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


def test_s4_unregistered_tool_and_run_token():
    with TestClient(app) as client:
        api_key = os.getenv("AGENT_API_KEY", os.getenv("GHOSTFENCE_AGENT_API_KEY", "dev-agent-key"))
        run_resp = client.post("/v1/runs", headers={"X-API-Key": api_key}, json={"agent_id": "invoice-agent", "task": "s4", "mode": "enforce"})
        assert run_resp.status_code == 200
        run = run_resp.json()
        token = run["run_token"]
        sid = run["session_id"]
        # unregistered tool
        resp = client.post("/v1/execute", headers={"X-Run-Token": token}, json={
            "agent_id": "invoice-agent", "session_id": sid, "task": "s4", "tool_name": "run_code", "arguments": {}
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "block"
        # attempt to create run with run token (no API key)
        resp2 = client.post("/v1/runs", headers={"X-Run-Token": token}, json={"agent_id": "invoice-agent", "task": "s4", "mode": "enforce"})
        assert resp2.status_code in (401, 403)