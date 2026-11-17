"""Server-side run state (FR: POST /v1/runs)."""

import time
import uuid

from sqlalchemy import text

from ..core.db import get_session, session_scope
from ..core.security import issue_run_token


def create_run(agent_id: str, task: str, scope: dict | None = None, ttl: int = 1800) -> dict:
    run_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    now = int(time.time())
    expires_at = now + ttl
    scope = scope or {}
    with session_scope() as session:
        session.execute(
            text(
                """
                INSERT INTO sessions (id, agent_id, task, tainted, taint_sources)
                VALUES (:id, :agent_id, :task, false, '[]'::jsonb)
                """
            ),
            {"id": session_id, "agent_id": agent_id, "task": task},
        )
        session.execute(
            text(
                """
                INSERT INTO runs (id, agent_id, session_id, task, scope, status, denial_count, expires_at, created_at)
                VALUES (:id, :agent_id, :session_id, :task, CAST(:scope AS jsonb), 'active', 0, to_timestamp(:expires_at), to_timestamp(:created_at))
                """
            ),
            {
                "id": run_id,
                "agent_id": agent_id,
                "session_id": session_id,
                "task": task,
                "scope": __import__("json").dumps(scope),
                "expires_at": expires_at,
                "created_at": now,
            },
        )
    token = issue_run_token(run_id, agent_id, session_id, expires_at)
    return {
        "run_id": run_id,
        "session_id": session_id,
        "run_token": token,
        "expires_at": expires_at,
    }


def get_run(run_id: str) -> dict | None:
    with get_session() as session:
        row = session.execute(
            text("SELECT id, agent_id, session_id, task, scope, status, denial_count, extract(epoch from expires_at) AS expires_at FROM runs WHERE id = :id"),
            {"id": run_id},
        ).mappings().first()
        if row is None:
            return None
        return dict(row)


def close_run(run_id: str, status: str = "closed") -> bool:
    with session_scope() as session:
        result = session.execute(
            text("UPDATE runs SET status = :status, ended_at = now() WHERE id = :id"),
            {"status": status, "id": run_id},
        )
        return result.rowcount > 0


def increment_denial(run_id: str) -> int:
    with session_scope() as session:
        row = session.execute(
            text("UPDATE runs SET denial_count = denial_count + 1 WHERE id = :id RETURNING denial_count, denial_count >= :threshold AS terminated"),
            {"id": run_id, "threshold": 5},
        ).mappings().first()
        if row and row["denial_count"] >= 5:
            session.execute(text("UPDATE runs SET status = 'terminated' WHERE id = :id"), {"id": run_id})
        return int(row["denial_count"]) if row else 0


def is_tainted(session_id: str) -> bool:
    with get_session() as session:
        row = session.execute(text("SELECT tainted FROM sessions WHERE id = :id"), {"id": session_id}).scalar()
        return bool(row)


def set_tainted(session_id: str, tainted: bool = True, sources: list | None = None):
    with session_scope() as session:
        session.execute(
            text("UPDATE sessions SET tainted = :tainted, taint_sources = CAST(:sources AS jsonb) WHERE id = :id"),
            {"tainted": tainted, "sources": __import__("json").dumps(sources or []), "id": session_id},
        )