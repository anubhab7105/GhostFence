"""GhostFence Python SDK (Phase 1)."""

import os
from typing import Any, Dict

import httpx


class GhostFenceClient:
    def __init__(self, gateway_url: str | None = None, run_token: str | None = None, api_key: str | None = None, timeout: float = 10.0):
        self.gateway_url = (gateway_url or os.getenv("GHOSTFENCE_GATEWAY_URL", "http://localhost:8000")).rstrip("/")
        self.run_token = run_token
        self.api_key = api_key
        self.timeout = timeout

    def execute(self, tool_name: str, arguments: Dict[str, Any], agent_id: str, session_id: str, task: str, provenance=None, idempotency_key=None):
        headers = {}
        if self.run_token:
            headers["X-Run-Token"] = self.run_token
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        payload = {
            "agent_id": agent_id,
            "session_id": session_id,
            "task": task,
            "tool_name": tool_name,
            "arguments": arguments,
            "provenance": provenance or [],
            "idempotency_key": idempotency_key,
        }
        try:
            response = httpx.post(f"{self.gateway_url}/v1/execute", json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            # Fail closed for sensitive tools: return a block decision.
            return {
                "request_id": "sdk-fail-closed",
                "decision": "block",
                "reason_code": "gateway_unreachable",
                "risk_score": 0,
                "policy_version": "unknown",
                "error": str(exc),
            }