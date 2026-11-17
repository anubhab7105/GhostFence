"""Decision pipeline (PRD section 8)."""

import json
import time
import uuid

from jsonschema import ValidationError, validate as jsonschema_validate

from ..audit.service import append_entry, evidence_hash
from ..core.settings import settings
from ..gateway.egress import EgressClient
from ..gateway.executor import execute_tool
from ..gateway.runs import get_run, increment_denial, is_tainted, set_tainted
from ..schemas.api import ExecuteRequest, ExecuteResponse
from ..schemas.common import Decision


IDEMPOTENCY_CACHE: dict[str, dict] = {}


async def execute_request(req: ExecuteRequest, token: dict) -> ExecuteResponse:
    run = get_run(token["run_id"])
    if run is None or run["status"] != "active":
        return _deny(req, token, "invalid_session", 0, run)
    if int(run["expires_at"]) < time.time():
        return _deny(req, token, "session_expired", 0, run)
    if run["agent_id"] != token["agent_id"] or run["agent_id"] != req.agent_id:
        return _deny(req, token, "identity_mismatch", 0, run)
    if run["session_id"] != token["session_id"] or run["session_id"] != req.session_id:
        return _deny(req, token, "session_mismatch", 0, run)

    # Idempotency
    if req.idempotency_key and req.idempotency_key in IDEMPOTENCY_CACHE:
        cached = IDEMPOTENCY_CACHE[req.idempotency_key]
        return ExecuteResponse(**cached)

    from ..main import app_state

    registry = app_state["registry"]
    policy_engine = app_state["policy_engine"]
    egress = app_state.get("egress", EgressClient())

    tool = registry.get(req.tool_name)
    # 2. argument validation
    if tool is None:
        # still block; policy engine also blocks unregistered
        pass
    if tool is not None and tool.input_schema:
        try:
            jsonschema_validate(instance=req.arguments, schema=tool.input_schema)
        except ValidationError:
            return await _block(req, token, run, "schema_validation_failed", 0, policy_engine.version)

    session_tainted = is_tainted(req.session_id)
    inspector_severity = __import__("app.gateway.runs", fromlist=["get_inspector_severity"]).get_inspector_severity(req.session_id)

    # 3-6 policy evaluation
    result = policy_engine.evaluate(
        tool_name=req.tool_name,
        arguments=req.arguments,
        session_tainted=session_tainted,
        inspector_severity=inspector_severity,
    )
    decision = result["decision"]
    reason_code = result["reason_code"]
    risk_score = result["risk_score"]
    policy_version = policy_engine.version
    matched = result["matched_rules"]

    request_id = str(uuid.uuid4())

    # Write-ahead audit entry before execution.
    append_entry(
        agent_id=req.agent_id,
        session_id=req.session_id,
        tool_name=req.tool_name,
        decision=decision,
        reason_code=reason_code,
        risk_score=risk_score,
        policy_version=policy_version,
        evidence_hashes=[evidence_hash(json.dumps(req.arguments, sort_keys=True))],
        redacted_excerpt=None,
        payload={"request_id": request_id, "matched_rules": matched, "provenance": req.provenance, "risk_formula_version": "risk-v1", "risk_signals": matched},
    )

    if decision in {"block"}:
        count = increment_denial(run["id"])
        if count >= settings.denial_threshold:
            # run terminated
            pass
        response = ExecuteResponse(
            request_id=request_id,
            decision=decision,
            reason_code=reason_code,
            risk_score=risk_score,
            policy_version=policy_version,
        )
        if req.idempotency_key:
            IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
        return response

    if decision == "require_approval":
        # Phase 1: no approval workflow yet; treat as pending block-ish? 
        # Return require_approval decision to caller.
        response = ExecuteResponse(
            request_id=request_id,
            decision=decision,
            reason_code=reason_code,
            risk_score=risk_score,
            policy_version=policy_version,
        )
        if req.idempotency_key:
            IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
        return response

    # allow or allow_with_flag
    try:
        outcome = await execute_tool(req.tool_name, req.arguments, egress)
    except Exception as exc:
        append_entry(
            agent_id=req.agent_id,
            session_id=req.session_id,
            tool_name=req.tool_name,
            decision="outcome_unknown",
            reason_code="execution_error",
            risk_score=risk_score,
            policy_version=policy_version,
            evidence_hashes=[],
            payload={"request_id": request_id, "error": str(exc)},
        )
        return ExecuteResponse(
            request_id=request_id,
            decision="block",
            reason_code="execution_error",
            risk_score=risk_score,
            policy_version=policy_version,
        )

    # Write the separate outcome entry after execution (write-ahead audit).
    append_entry(
        agent_id=req.agent_id,
        session_id=req.session_id,
        tool_name=req.tool_name,
        decision="outcome",
        reason_code="completed",
        risk_score=risk_score,
        policy_version=policy_version,
        evidence_hashes=[],
        payload={"request_id": request_id, "result_keys": sorted(list(outcome.keys()))},
    )

    response = ExecuteResponse(
        request_id=request_id,
        decision=decision,
        reason_code=reason_code,
        risk_score=risk_score,
        policy_version=policy_version,
    )
    if req.idempotency_key:
        IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
    return response


async def _block(req, token, run, reason_code, risk_score, policy_version):
    request_id = str(__import__("uuid").uuid4())
    append_entry(
        agent_id=req.agent_id,
        session_id=req.session_id,
        tool_name=req.tool_name,
        decision="block",
        reason_code=reason_code,
        risk_score=risk_score,
        policy_version=policy_version or "unknown",
        evidence_hashes=[],
        payload={"request_id": request_id},
    )
    if run is not None:
        increment_denial(run["id"])
    return ExecuteResponse(
        request_id=request_id,
        decision="block",
        reason_code=reason_code,
        risk_score=risk_score,
        policy_version=policy_version or "unknown",
    )


def _deny(req, token, reason_code, risk_score, run):
    # sync deny (no await needed) but append audit
    request_id = str(__import__("uuid").uuid4())
    append_entry(
        agent_id=req.agent_id,
        session_id=req.session_id,
        tool_name=req.tool_name,
        decision="block",
        reason_code=reason_code,
        risk_score=risk_score,
        policy_version="unknown",
        evidence_hashes=[],
        payload={"request_id": request_id},
    )
    if run is not None:
        increment_denial(run["id"])
    return ExecuteResponse(
        request_id=request_id,
        decision="block",
        reason_code=reason_code,
        risk_score=risk_score,
        policy_version="unknown",
    )