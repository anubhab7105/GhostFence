"""Tool registry schema (FR-1, FR-5, FR-9)."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ToolDefinition(BaseModel):
    name: str
    description: str
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    side_effect: bool = False
    egress: bool = False
    requires_approval: bool = False
    fail_closed: bool = True
    registered: bool = True


class ToolRegistry(BaseModel):
    tools: List[ToolDefinition]

    def get(self, name: str) -> ToolDefinition | None:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None