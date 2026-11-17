"""Load YAML config into schemas."""

import yaml
from pathlib import Path

from ..schemas.destinations import DestinationCatalogue
from ..schemas.policy import Policy
from ..schemas.resources import ResourceCatalogue
from ..schemas.tool_registry import ToolRegistry


def load_yaml(path: str):
    return yaml.safe_load(Path(path).read_text())


def load_registry(path: str) -> ToolRegistry:
    return ToolRegistry.model_validate(load_yaml(path))


def load_policy(path: str) -> Policy:
    return Policy.model_validate(load_yaml(path))


def load_resources(path: str) -> ResourceCatalogue:
    return ResourceCatalogue.model_validate(load_yaml(path))


def load_destinations(path: str) -> DestinationCatalogue:
    return DestinationCatalogue.model_validate(load_yaml(path))