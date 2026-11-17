"""Policy rule tests (Phase 1/3)."""

from app.policy_engine.engine import PolicyEngine
from app.policy_engine.loaders import load_destinations, load_policy, load_registry, load_resources

registry = load_registry("../tool-registry.yaml") if False else None


def engine():
    # Paths relative to backend cwd
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
    # fetch_document is allowed tool but sensitive; taint should block
    r = e.evaluate(tool_name="fetch_document", arguments={"url": "http://vendor-site/documents/a"}, session_tainted=True, inspector_severity=80)
    assert r["decision"] == "block"


def test_allow_with_flag_not_on_outbound():
    # Simulated in pipeline: outbound risk escalation becomes require_approval, not allow_with_flag.
    # Policy engine marks risk; pipeline decides. Here ensure risk_score > 0 for tainted read.
    e, reg = engine()
    r = e.evaluate(tool_name="read_file", arguments={"path": "invoices/invoice-1.pdf"}, session_tainted=True, inspector_severity=80)
    assert r["risk_score"] > 0


def test_unknown_resource_restricted():
    from app.schemas.common import Sensitivity
    from app.schemas.resources import ResourceCatalogue
    c = ResourceCatalogue(resources=[])
    assert c.classify("anything") == Sensitivity.restricted