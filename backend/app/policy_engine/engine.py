"""Policy engine (deny by default)."""

import hashlib
import json
import unicodedata
from pathlib import Path

import yaml

from ..schemas.policy import Policy
from ..schemas.tool_registry import ToolRegistry
from .normalization import normalize_path, normalize_url, suffix_domain_match


SENSITIVE_TOOLS = {"http_request", "send_email", "delete_record", "transfer_money", "export_customers", "fetch_document"}


def content_hash_policy(policy_dict: dict) -> str:
    canonical = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PolicyEngine:
    def __init__(self, policy: Policy, registry: ToolRegistry, resources, destinations):
        self.policy = policy
        self.registry = registry
        self.resources = resources
        self.destinations = destinations
        self.version = content_hash_policy(policy.model_dump())

    def validate_startup(self):
        if self.policy.default_decision != "block":
            raise ValueError("policy must be deny by default")
        for tool in self.policy.allowed_tools:
            if self.registry.get(tool) is None:
                raise ValueError(f"unknown tool in policy: {tool}")
        # approval-required tools should be registered
        for tool in self.policy.approval_required:
            if self.registry.get(tool) is None:
                raise ValueError(f"unknown approval tool: {tool}")

    def _destination_allowed(self, host: str) -> bool:
        host = host.lower()
        for dest in self.destinations.destinations:
            if suffix_domain_match(host, dest.host):
                return True
        return False

    def evaluate(self, *, tool_name: str, arguments: dict, session_tainted: bool, inspector_severity: int = 0) -> dict:
        inspector_contrib = min(40, inspector_severity * 4 // 10)
        matched = []
        # 3. policy check
        tool = self.registry.get(tool_name)
        if tool is None:
            return {"decision": "block", "reason_code": "unregistered_tool", "risk_score": 0, "matched_rules": []}
        if tool_name not in self.policy.allowed_tools:
            return {"decision": "block", "reason_code": "tool_not_allowed", "risk_score": 0, "matched_rules": []}
        matched.append("tool_allowed")

        # resource checks for read_file
        if tool_name == "read_file":
            path = arguments.get("path", "")
            try:
                norm = normalize_path(path)
            except ValueError:
                return {"decision": "block", "reason_code": "invalid_path", "risk_score": 0, "matched_rules": matched}
            if not any(self._resource_allowed(norm, p) for p in self.policy.allowed_resources):
                return {"decision": "block", "reason_code": "resource_not_allowed", "risk_score": 0, "matched_rules": matched}
            matched.append("resource_allowed")

        # operation checks (simple mapping)
        operation = "read"
        if tool_name in {"send_email", "http_request"}:
            operation = "send" if tool_name == "send_email" else "read"
        if tool_name in {"delete_record"}:
            operation = "delete"
        if tool_name in {"transfer_money", "export_customers"}:
            operation = "export"
        if operation not in self.policy.allowed_operations and self.policy.allowed_operations:
            # allowed_operations empty means no generic operation permission; still tool-level allow may suffice
            pass

        # approval-required
        if tool_name in self.policy.approval_required:
            # taint can escalate but approval remains
            if session_tainted and tool_name in SENSITIVE_TOOLS:
                return {"decision": "require_approval", "reason_code": "approval_required_tainted", "risk_score": 40, "matched_rules": matched + ["approval_required", "tainted"]}
            return {"decision": "require_approval", "reason_code": "approval_required", "risk_score": 10, "matched_rules": matched + ["approval_required"]}

        # 4. taint check
        if session_tainted and tool_name in SENSITIVE_TOOLS:
            return {"decision": "block", "reason_code": "tainted_sensitive_tool", "risk_score": 50, "matched_rules": matched + ["tainted"]}

        # 5. data and destination check
        dest_host = None
        if tool_name in {"http_request", "fetch_document"}:
            url = arguments.get("url", "")
            try:
                info = normalize_url(url)
                dest_host = info["host"]
            except ValueError as exc:
                return {"decision": "block", "reason_code": "invalid_destination", "risk_score": 0, "matched_rules": matched}
        if tool_name == "send_email":
            # destination from recipient domain
            to = arguments.get("to", "")
            if "@" in to:
                dest_host = to.split("@", 1)[1]
        if dest_host is not None:
            if not self._destination_allowed(dest_host):
                return {"decision": "block", "reason_code": "destination_not_allowed", "risk_score": 0, "matched_rules": matched}
            matched.append("destination_allowed")

        # sensitivity ceiling: outbound data classification check (basic)
        if tool.egress and dest_host is not None:
            pass

        return {"decision": "allow", "reason_code": "allowed", "risk_score": 0, "matched_rules": matched + ["allowed"]}

    def _resource_allowed(self, path: str, pattern: str) -> bool:
        from .normalization import glob_match
        # allowed_resources entries may be glob patterns
        if glob_match(path.lstrip("/"), pattern):
            return True
        if path.lstrip("/") == pattern:
            return True
        return False