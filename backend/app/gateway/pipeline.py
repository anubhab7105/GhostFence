"""Decision pipeline (PRD section 8)."""

import asyncio
import json
import time
import uuid

from jsonschema import ValidationError, validate as jsonschema_validate

from ..audit.service import append_entry, evidence_hash

async def _append(*args, **kwargs):
    return await asyncio.to_thread(append_entry, *args, **kwargs)
from ..core.settings import settings
from ..core.settings import settings
from ..gateway.egress import EgressClient
from ..gateway.executor import execute_tool
from ..data_protection.scanner import scan_outbound
from ..gateway.runs import get_inspector_severity, get_run, increment_denial, is_tainted, set_tainted, get_sensitivity_high_water
from ..schemas.api import ExecuteRequest, ExecuteResponse
from ..schemas.common import Decision


IDEMPOTENCY_CACHE: dict[str, dict] = {}


async def execute_request(req: ExecuteRequest, token: dict) -> ExecuteResponse:
    run = await asyncio.to_thread(get_run, token["run_id"])
    mode = "enforce"
    if run is not None:
        scope = run.get("scope")
        if isinstance(scope, str):
            try:
                scope = __import__("json").loads(scope)
            except Exception:
                scope = {}
        if isinstance(scope, dict):
            mode = scope.get("mode", "enforce")
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

    session_tainted = await asyncio.to_thread(is_tainted, req.session_id)
    inspector_severity = await asyncio.to_thread(get_inspector_severity, req.session_id)

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

    # allow_with_flag impact matrix (FR-64): never on outbound/destructive operations.
    if decision == "allow" and risk_score > 0:
        tool = registry.get(req.tool_name)
        if tool is not None and (tool.egress or tool.side_effect):
            decision = "require_approval"
            reason_code = "risk_escalation_outbound"
        else:
            decision = "allow_with_flag"
            reason_code = "allowed_with_flag"

    request_id = str(uuid.uuid4())

    # Outbound payload scanning and classification checks for egress tools.
    tool = registry.get(req.tool_name)
    if tool is not None and tool.egress:
        dest_host = None
        if req.tool_name in {"http_request", "fetch_document"}:
            from ..policy_engine.normalization import normalize_url
            try:
                dest_host = normalize_url(req.arguments.get("url", ""))["host"]
            except Exception:
                dest_host = None
        elif req.tool_name == "send_email":
            to = req.arguments.get("to", "")
            if "@" in to:
                dest_host = to.split("@", 1)[1]
        if dest_host is not None:
            allowed_hosts = {d.host for d in app_state["destinations"].destinations}
            scan = scan_outbound(
                __import__("json").dumps(req.arguments, sort_keys=True),
                dest_host,
                allowed_hosts,
                sensitive_markers=[],
            )
            if not scan["ok"]:
                decision = "block"
                reason_code = scan["reason"]
                risk_score = max(risk_score, 60)
            # classification high-water check
            sens = await asyncio.to_thread(get_sensitivity_high_water, req.session_id)
            dest_entry = None
            for d in app_state["destinations"].destinations:
                if d.host == dest_host or d.host in dest_host:
                    dest_entry = d
                    break
            if dest_entry is not None:
                order = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
                if order.get(sens, 0) > order.get(dest_entry.approved_up_to.value if hasattr(dest_entry.approved_up_to, "value") else str(dest_entry.approved_up_to), 0):
                    decision = "block"
                    reason_code = "sensitivity_exceeds_destination"
                    risk_score = max(risk_score, 70)

    # Write-ahead audit entry before execution.
    audit_result = await _append(
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
    lock_wait_ms = audit_result.get("lock_wait_ms")
    lock_hold_ms = audit_result.get("lock_hold_ms")

    if decision in {"block"}:
        count = await asyncio.to_thread(increment_denial, run["id"])
        if count >= settings.denial_threshold:
            pass
        # log_only mode records the would-be decision but executes (D3).
        if mode == "log_only":
            try:
                outcome = await execute_tool(req.tool_name, req.arguments, egress)
                await _append(
                    agent_id=req.agent_id,
                    session_id=req.session_id,
                    tool_name=req.tool_name,
                    decision="outcome",
                    reason_code="completed",
                    risk_score=risk_score,
                    policy_version=policy_version,
                    evidence_hashes=[],
                    payload={"request_id": request_id, "log_only": True},
                )
                response = ExecuteResponse(
                    request_id=request_id,
                    decision=decision,
                    reason_code=reason_code,
                    risk_score=None,
                    policy_version=None,
                    result=outcome,
                    audit_lock_wait_ms=lock_wait_ms,
                    audit_lock_hold_ms=lock_hold_ms,
                )
                if req.idempotency_key:
                    IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
                return response
            except Exception as exc:
                reason = "partial_transmission" if "timeout" in str(exc).lower() or "connect" in str(exc).lower() else "execution_error"
                await _append(
                    agent_id=req.agent_id,
                    session_id=req.session_id,
                    tool_name=req.tool_name,
                    decision="outcome_unknown",
                    reason_code=reason,
                    risk_score=risk_score,
                    policy_version=policy_version,
                    evidence_hashes=[],
                    payload={"request_id": request_id, "error": str(exc), "log_only": True},
                )
                return ExecuteResponse(
                    request_id=request_id,
                    decision=decision,
                    reason_code=reason_code,
                    risk_score=None,
                    policy_version=None,
                    result=None,
                    audit_lock_wait_ms=lock_wait_ms,
                    audit_lock_hold_ms=lock_hold_ms,
                )
        response = ExecuteResponse(
            request_id=request_id,
            decision=decision,
            reason_code=reason_code,
            risk_score=None,
            policy_version=None,
            result=None,
        audit_lock_wait_ms=lock_wait_ms,
        audit_lock_hold_ms=lock_hold_ms,
        )
        if req.idempotency_key:
            IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
        return response

    if decision == "require_approval":
        # Approvals are disabled (deferred): map to block, reason recorded.
        decision = "block"
        # keep the already-determined reason_code (e.g. approval_required or risk_escalation_outbound)
        if mode == "log_only":
            try:
                outcome = await execute_tool(req.tool_name, req.arguments, egress)
                await _append(
                    agent_id=req.agent_id,
                    session_id=req.session_id,
                    tool_name=req.tool_name,
                    decision="outcome",
                    reason_code="completed",
                    risk_score=risk_score,
                    policy_version=policy_version,
                    evidence_hashes=[],
                    payload={"request_id": request_id, "log_only": True},
                )
                response = ExecuteResponse(
                    request_id=request_id,
                    decision=decision,
                    reason_code=reason_code,
                    risk_score=risk_score,
                    policy_version=policy_version,
                    result=outcome,
                    approval_id=None,
                )
                if req.idempotency_key:
                    IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
                return response
            except Exception:
                pass
        response = ExecuteResponse(
            request_id=request_id,
            decision=decision,
            reason_code=reason_code,
            risk_score=None,
            policy_version=None,
            result=None,
            approval_id=None,
        )
        if req.idempotency_key:
            IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
        return response

    # allow or allow_with_flag
    try:
        outcome = await execute_tool(req.tool_name, req.arguments, egress)
    except Exception as exc:
        reason = "partial_transmission" if "timeout" in str(exc).lower() or "connect" in str(exc).lower() else "execution_error"
        await _append(
            agent_id=req.agent_id,
            session_id=req.session_id,
            tool_name=req.tool_name,
            decision="outcome_unknown",
            reason_code=reason,
            risk_score=risk_score,
            policy_version=policy_version,
            evidence_hashes=[],
            payload={"request_id": request_id, "error": str(exc)},
        )
        return ExecuteResponse(
            request_id=request_id,
            decision="block",
            reason_code=reason,
            risk_score=risk_score,
            policy_version=policy_version,
        )

    # Write the separate outcome entry after execution (write-ahead audit).
    await _append(
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
        result=outcome,
        audit_lock_wait_ms=lock_wait_ms,
        audit_lock_hold_ms=lock_hold_ms,
    )
    if req.idempotency_key:
        IDEMPOTENCY_CACHE[req.idempotency_key] = response.model_dump()
    return response


async def _block(req, token, run, reason_code, risk_score, policy_version):
    request_id = str(__import__("uuid").uuid4())
    await _append(
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
        risk_score=None,
        policy_version=None,
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
        risk_score=None,
        policy_version=None,
    )