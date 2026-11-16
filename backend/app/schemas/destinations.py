"""Destination allowlist schema (FR-20, FR-21, D1)."""

from typing import List

from pydantic import BaseModel, Field

from .common import Sensitivity


class DestinationEntry(BaseModel):
    host: str
    approved_up_to: Sensitivity = Sensitivity.public
    retention: str = ""
    training: bool = False
    demo_only: bool = False
    notes: str = ""


class DestinationCatalogue(BaseModel):
    destinations: List[DestinationEntry] = Field(default_factory=list)