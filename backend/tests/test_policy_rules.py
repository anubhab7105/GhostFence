"""Policy rule tests (Phase 1/3)."""

import asyncio

import pytest

from app.attack_lab.runner import ensure_app_state
from app.core.db import session_scope
from app.gateway.pipeline import execute_request
from app.gateway.runs import create_run
from app.main import app_state
from app.policy_engine.engine import PolicyEngine
from app.policy_engine.loaders import load_destinations, load_policy, load_registry, load_resources
from app.schemas.api import ExecuteRequest
from app.schemas.common import Sensitivity
from app.core.security import verify_run_token


def engine():
    reg = load_registry("/home/babai/Desktop/codeing/GhostFence/tool-registry.yaml")
    pol = load_policy("/home/babai/Desktop/codeing/GhostFence/policies/example.yaml")
    res = load_resources("/home/babai/Desktop/codeing/GhostFence/resources.yaml")
    dst = load_destinations("/home/babai/Desktop/codeing/GhostFence/destinations.yaml")
    e = PolicyEngine(pol, reg, res, dst)
    e.validate_startup()
    return e, reg


def test_unregistered_tool_blocked():
    e, reg = engine()
    r = e.evaluate(tool_name="run_code", arguments={}, session_tainted=False)
    assert r["decision"] == "block"
    assert r["reason_code"] == "unregistered_tool"


def test_trifecta_blocks_sensitive_tool_when_tainted():
    e, reg = engine()
    r = e.evaluate(tool_name="fetch_document", arguments={"url": "http://vendor-site/documents/a"}, session_tainted=True, inspector_severity=80)
    assert r["decision"] == "block"


def test_allow_with_flag_not_on_outbound():
    e, reg = engine()
    r = e.evaluate(tool_name="read_file", arguments={"path": "invoices/invoice-1.pdf"}, session_tainted=True, inspector_severity=80)
    assert r["risk_score"] > 0


def test_unknown_resource_restricted():
    from app.schemas.resources import ResourceCatalogue
    c = ResourceCatalogue(resources=[])
    assert c.classify("anything") == Sensitivity.restricted


def test_allow_with_flag_matrix():
    ensure_app_state()
    # Monkeypatch policy engine to return allow with risk > 0.
    original_evaluate = app_state["policy_engine"].evaluate
    app_state["policy_engine"].evaluate = lambda **kwargs: {"decision": "allow", "reason_code": "allowed", "risk_score": 50, "matched_rules": []}
    # Monkeypatch registry tool to be egress.
    original_get = app_state["registry"].get
    class Tool:
        egress = True
        side_effect = True
    app_state["registry"].get = lambda name: Tool()
    try:
        run = create_run("invoice-agent", "matrix", {"mode": "enforce"})
        token_payload = verify_run_token(run["run_token"])
        req = ExecuteRequest(
            agent_id="invoice-agent",
            session_id=run["session_id"],
            task="matrix",
            tool_name="http_request",
            arguments={"url": "https://example.com/"},
        )
        resp = asyncio.run(execute_request(req, token_payload))
        assert resp.decision.value == "require_approval"
    finally:
        app_state["policy_engine"].evaluate = original_evaluate
        app_state["registry"].get = original_get