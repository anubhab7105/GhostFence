"""Shared enums and primitives (FR-2, FR-18)."""

from enum import Enum


class Sensitivity(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class Decision(str, Enum):
    allow = "allow"
    block = "block"
    require_approval = "require_approval"
    allow_with_flag = "allow_with_flag"


SENSITIVITY_ORDER = {
    Sensitivity.public: 0,
    Sensitivity.internal: 1,
    Sensitivity.confidential: 2,
    Sensitivity.restricted: 3,
}