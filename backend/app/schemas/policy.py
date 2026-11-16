"""Policy schema (FR-12 to FR-17). Deny by default is represented by default_decision=block."""

from typing import List, Literal

from pydantic import BaseModel, Field, field_validator

from .common import Sensitivity


class Policy(BaseModel):
    policy_id: str
    version: str
    agent_id: str
    default_decision: Literal["block"] = "block"
    allowed_tools: List[str] = Field(default_factory=list)
    allowed_resources: List[str] = Field(default_factory=list)
    allowed_operations: List[str] = Field(default_factory=list)
    allowed_destinations: List[str] = Field(default_factory=list)
    sensitivity_ceiling: Sensitivity = Sensitivity.public
    approval_required: List[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("allowed_tools", "allowed_resources", "allowed_operations", "allowed_destinations", "approval_required")
    @classmethod
    def _deduplicate(cls, value: List[str]) -> List[str]:
        return list(dict.fromkeys(value))