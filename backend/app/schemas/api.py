"""HTTP API models (FR-4, FR-6)."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field

from .common import Decision


class ExecuteRequest(BaseModel):
    agent_id: str
    session_id: str
    task: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    provenance: List[str] = Field(default_factory=list)
    idempotency_key: str | None = None


class ExecuteResponse(BaseModel):
    request_id: str
    decision: Decision
    reason_code: str
    risk_score: int | None = None
    policy_version: str | None = None
    approval_id: str | None = None
    result: dict | None = None
    audit_lock_wait_ms: float | None = None
    audit_lock_hold_ms: float | None = None


class InspectRequest(BaseModel):
    content: str
    source_type: str
    content_ref: str | None = None


class InspectResponse(BaseModel):
    severity: int
    findings: List[str] = Field(default_factory=list)
    evidence_hash: str
    tainted: bool = False


class RunCreateRequest(BaseModel):
    agent_id: str
    task: str
    scenario_id: str | None = None
    mode: str = "enforce"


class RunCloseRequest(BaseModel):
    status: str = "closed"