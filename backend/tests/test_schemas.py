"""Phase 0 schema validation tests."""

from pathlib import Path

import yaml

from app.schemas.audit import AuditEntry
from app.schemas.common import Sensitivity
from app.schemas.destinations import DestinationCatalogue
from app.schemas.policy import Policy
from app.schemas.resources import ResourceCatalogue
from datetime import datetime, timezone

from app.schemas.scenario import Scenario
from app.schemas.tool_registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]


def test_tool_registry_validates():
    data = yaml.safe_load((ROOT / "tool-registry.yaml").read_text())
    registry = ToolRegistry.model_validate(data)
    assert registry.get("read_file") is not None
    assert registry.get("missing") is None


def test_policy_validates():
    data = yaml.safe_load((ROOT / "policies" / "example.yaml").read_text())
    policy = Policy.model_validate(data)
    assert policy.default_decision == "block"
    assert "transfer_money" in policy.approval_required


def test_resources_validates_and_fail_closed():
    data = yaml.safe_load((ROOT / "resources.yaml").read_text())
    catalogue = ResourceCatalogue.model_validate(data)
    assert catalogue.classify("payroll.csv") == Sensitivity.restricted
    assert catalogue.classify("unknown-resource") == Sensitivity.restricted


def test_destinations_validates():
    data = yaml.safe_load((ROOT / "destinations.yaml").read_text())
    catalogue = DestinationCatalogue.model_validate(data)
    assert any(d.host == "evil.test" and d.demo_only for d in catalogue.destinations)


def test_scenario_validates():
    data = yaml.safe_load((ROOT / "attack-lab" / "scenarios" / "s1-indirect-injection.yaml").read_text())
    scenario = Scenario.model_validate(data)
    assert scenario.expected.sink_exposed_bytes == 0


def test_audit_entry_accepts_genesis_previous_hash():
    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc),        agent_id="agent",
        session_id="session",
        tool_name="read_file",
        decision="allow",
        reason_code="allowed",
        risk_score=0,
        policy_version="1.0",
        previous_hash="4febf9bd83efbb0c82bbe8cef0eb8aa3d69224b0f0086675fc198f32c1c396de",
    )
    assert entry.decision.value == "allow"