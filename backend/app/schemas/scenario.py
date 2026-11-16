"""Attack scenario schema (FR-34, FR-39)."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ScenarioDocument(BaseModel):
    name: str
    content: str
    source_type: str = "untrusted"
    classification: str = "internal"


class ScenarioExpected(BaseModel):
    decisions: List[str] = Field(default_factory=list)
    sink_exposed_bytes: int = 0


class Scenario(BaseModel):
    id: str
    title: str
    task: str
    mode: str = "protected"
    documents: List[ScenarioDocument] = Field(default_factory=list)
    expected: ScenarioExpected = Field(default_factory=ScenarioExpected)
    metadata: Dict[str, Any] = Field(default_factory=dict)