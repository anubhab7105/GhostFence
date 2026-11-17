"""Approval workflow (Phase 6, basic)."""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException

from ..api.deps import require_operator
from ..core.db import get_session, session_scope
from ..gateway.runs import get_run
from ..gateway.executor import execute_tool
from ..gateway.egress import EgressClient
from sqlalchemy import text

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


@router.get("")
def list_approvals(role: str = Depends(require_operator)):
    with get_session() as session:
        rows = session.execute(text("SELECT * FROM approvals ORDER BY created_at DESC")).mappings().all()
    return [dict(r) for r in rows]


@router.post("/{approval_id}/decide")
def decide(approval_id: str, payload: dict, role: str = Depends(require_operator)):
    decision = payload.get("decision", "reject")
    with session_scope() as session:
        row = session.execute(text("SELECT * FROM approvals WHERE id = :id"), {"id": approval_id}).mappings().first()
        if row is None:
            raise HTTPException(status_code=404, detail="approval not found")
        session.execute(
            text("UPDATE approvals SET status = :status, approver = :approver, decided_at = now(), notes = :notes WHERE id = :id"),
            {"status": decision, "approver": role, "notes": payload.get("notes", ""), "id": approval_id},
        )
    return {"approval_id": approval_id, "status": decision}