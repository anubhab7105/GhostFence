"""Resource classification schema (FR-18, FR-25, FR-63)."""

from typing import List

from pydantic import BaseModel, Field

from .common import Sensitivity


class ResourceEntry(BaseModel):
    id: str
    pattern: str
    classification: Sensitivity
    owner: str = ""
    notes: str = ""


class ResourceCatalogue(BaseModel):
    resources: List[ResourceEntry] = Field(default_factory=list)

    def classify(self, resource_id: str) -> Sensitivity:
        # Fail closed: unknown resources are restricted (FR-63).
        for entry in self.resources:
            if entry.id == resource_id or entry.pattern == resource_id:
                return entry.classification
        return Sensitivity.restricted