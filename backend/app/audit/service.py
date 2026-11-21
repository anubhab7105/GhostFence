"""Hash-chained audit log (FR-29 to FR-33, D8)."""

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

from sqlalchemy import text

from ..core.db import engine, get_session, session_scope
from ..core.settings import settings


GENESIS_HASH = hashlib.sha256(b"ghostfence/audit/genesis/v1").hexdigest()
DOMAIN_SEPARATOR = b"ghostfence/audit/entry/v1\x00"


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def evidence_hash(value: str) -> str:
    return hmac.new(settings.audit_hmac_key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_entry_hash(previous_hash_hex: str, payload: dict) -> str:
    canonical = canonical_json(payload).encode("utf-8")
    previous_raw = bytes.fromhex(previous_hash_hex)
    return hashlib.sha256(DOMAIN_SEPARATOR + previous_raw + canonical).hexdigest()


def append_entry(
    *,
    agent_id: str,
    session_id: str,
    tool_name: str,
    decision: str,
    reason_code: str,
    risk_score: int,
    policy_version: str,
    evidence_hashes: list[str] | None = None,
    redacted_excerpt: str | None = None,
    payload: dict | None = None,
    timestamp: datetime | None = None,
) -> dict:
    timestamp = timestamp or datetime.now(timezone.utc)
    ts = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    from sqlalchemy.orm import Session
    session = Session(engine, future=True)
    try:
        t0 = time.perf_counter()
        row = session.execute(
            text("SELECT last_sequence, encode(last_hash, 'hex') AS last_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE")
        ).mappings().first()
        t1 = time.perf_counter()
        if row is None:
            raise RuntimeError("audit chain head missing")
        previous_hash = row["last_hash"]
        sequence = int(row["last_sequence"]) + 1
        full_payload = {
            "agent_id": agent_id,
            "decision": decision,
            "evidence_hashes": evidence_hashes or [],
            "policy_version": policy_version,
            "previous_hash": previous_hash,
            "reason_code": reason_code,
            "redacted_excerpt": redacted_excerpt,
            "risk_score": risk_score,
            "sequence": sequence,
            "session_id": session_id,
            "timestamp": ts,
            "tool_name": tool_name,
        }
        if payload:
            full_payload["payload"] = payload
        entry_hash = compute_entry_hash(previous_hash, full_payload)
        session.execute(
            text(
                """
                INSERT INTO audit_entries
                (sequence, timestamp, agent_id, session_id, tool_name, decision, reason_code, risk_score, policy_version, previous_hash, entry_hash, payload)
                VALUES
                (:sequence, :timestamp, :agent_id, :session_id, :tool_name, :decision, :reason_code, :risk_score, :policy_version, decode(:previous_hash, 'hex'), decode(:entry_hash, 'hex'), CAST(:payload AS jsonb))
                """
            ),
            {
                "sequence": sequence,
                "timestamp": ts,
                "agent_id": agent_id,
                "session_id": session_id,
                "tool_name": tool_name,
                "decision": decision,
                "reason_code": reason_code,
                "risk_score": risk_score,
                "policy_version": policy_version,
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
                "payload": canonical_json(full_payload),
            },
        )
        session.execute(
            text("UPDATE audit_chain_head SET last_sequence = :seq, last_hash = decode(:hash, 'hex'), updated_at = now() WHERE id = 1"),
            {"seq": sequence, "hash": entry_hash},
        )
        session.commit()
        t2 = time.perf_counter()
        return {
            "sequence": sequence,
            "entry_hash": entry_hash,
            "previous_hash": previous_hash,
            "lock_wait_ms": (t1 - t0) * 1000.0,
            "lock_hold_ms": (t2 - t1) * 1000.0,
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def verify_chain() -> dict:
    with get_session() as session:
        rows = session.execute(
            text("SELECT sequence, encode(previous_hash,'hex') AS previous_hash, encode(entry_hash,'hex') AS entry_hash, payload, timestamp FROM audit_entries ORDER BY sequence")
        ).mappings().all()
        expected_previous = GENESIS_HASH
        for row in rows:
            if row["previous_hash"] != expected_previous:
                return {"ok": False, "first_bad_sequence": row["sequence"], "reason": "previous_hash mismatch"}
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            recomputed = compute_entry_hash(row["previous_hash"], payload)
            if recomputed != row["entry_hash"]:
                return {"ok": False, "first_bad_sequence": row["sequence"], "reason": "entry_hash mismatch"}
            expected_previous = row["entry_hash"]
        return {"ok": True, "entries": len(rows), "last_hash": expected_previous}