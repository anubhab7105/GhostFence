"""Startup recovery for write-ahead audit (FR-69)."""

from sqlalchemy import text

from ..core.db import get_session, session_scope
from .service import append_entry


def recover_pending_outcomes() -> int:
    recovered = 0
    with get_session() as session:
        rows = session.execute(
            text(
                """
                SELECT a.sequence, a.agent_id, a.session_id, a.tool_name, a.risk_score, a.policy_version, a.payload
                FROM audit_entries a
                WHERE a.decision IN ('allow', 'allow_with_flag')
                  AND NOT EXISTS (
                    SELECT 1 FROM audit_entries b
                    WHERE b.payload->>'request_id' = a.payload->>'request_id'
                      AND b.decision = 'outcome'
                  )
                """
            )
        ).mappings().all()
    for row in rows:
        payload = row["payload"]
        if isinstance(payload, str):
            import json
            payload = json.loads(payload)
        request_id = payload.get("request_id", "")
        append_entry(
            agent_id=row["agent_id"],
            session_id=row["session_id"],
            tool_name=row["tool_name"],
            decision="outcome_unknown",
            reason_code="recovered_after_crash",
            risk_score=row["risk_score"],
            policy_version=row["policy_version"],
            evidence_hashes=[],
            payload={"request_id": request_id, "recovered_from_sequence": row["sequence"]},
        )
        recovered += 1
    return recovered