"""Audit entry schema (FR-29, FR-30, D8)."""

from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from .common import Decision


class AuditEntry(BaseModel):
    sequence: int = 0
    timestamp: datetime
    agent_id: str
    session_id: str
    tool_name: str
    decision: Decision
    reason_code: str
    risk_score: int = 0
    policy_version: str
    previous_hash: str
    entry_hash: str = ""
    evidence_hashes: List[str] = Field(default_factory=list)
    redacted_excerpt: str | None = None
    payload: Dict[str, Any] = Field(default_factory=dict)