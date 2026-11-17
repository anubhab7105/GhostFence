"""Audit chain tests against real PostgreSQL (Phase 2)."""

import concurrent.futures
import json

import pytest
from sqlalchemy import text

from app.audit.recovery import recover_pending_outcomes
from app.audit.service import GENESIS_HASH, append_entry, compute_entry_hash, verify_chain
from app.core.db import get_session, session_scope

pytestmark = pytest.mark.docker


def reset_chain():
    with session_scope() as session:
        session.execute(text("DELETE FROM audit_entries"))
        session.execute(text("UPDATE audit_chain_head SET last_sequence = 0, last_hash = decode(:h, 'hex') WHERE id = 1"), {"h": GENESIS_HASH})


@pytest.fixture(autouse=True)
def clean_audit():
    reset_chain()
    yield
    reset_chain()


def test_d8_vector():
    previous_hash = "4febf9bd83efbb0c82bbe8cef0eb8aa3d69224b0f0086675fc198f32c1c396de"
    payload = {
        "agent_id": "invoice-agent",
        "decision": "allow",
        "evidence_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "policy_version": "1.0",
        "previous_hash": previous_hash,
        "reason_code": "allowed",
        "redacted_excerpt": None,
        "risk_score": 0,
        "sequence": 1,
        "session_id": "session-1",
        "timestamp": "2026-11-17T00:00:00Z",
        "tool_name": "read_file",
    }
    assert compute_entry_hash(previous_hash, payload) == "69305a8fc5a7ab3e87ead0ee020ae5d5638fd036a4a4dc57e294603747a32594"


def test_modification_detected():
    append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    with session_scope() as session:
        session.execute(text("UPDATE audit_entries SET reason_code = 'tampered' WHERE sequence = 2"))
    result = verify_chain()
    assert result["ok"] is False
    assert result["first_bad_sequence"] == 2


def test_deletion_detected():
    for _ in range(3):
        append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    with session_scope() as session:
        session.execute(text("DELETE FROM audit_entries WHERE sequence = 2"))
    result = verify_chain()
    assert result["ok"] is False


def test_reordering_detected():
    for _ in range(3):
        append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    with session_scope() as session:
        session.execute(text("UPDATE audit_entries SET sequence = 99 WHERE sequence = 1"))
        session.execute(text("UPDATE audit_entries SET sequence = 1 WHERE sequence = 2"))
        session.execute(text("UPDATE audit_entries SET sequence = 2 WHERE sequence = 99"))
    result = verify_chain()
    assert result["ok"] is False


def test_concurrent_appends():
    def worker(_):
        append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        list(executor.map(worker, range(20)))
    result = verify_chain()
    assert result["ok"] is True
    assert result["entries"] == 20
    with get_session() as session:
        seqs = [r[0] for r in session.execute(text("SELECT sequence FROM audit_entries ORDER BY sequence")).all()]
    assert seqs == list(range(1, 21))


def test_crash_between_decision_and_execution():
    append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    recovered = recover_pending_outcomes()
    assert recovered == 1
    result = verify_chain()
    assert result["ok"] is True


def test_crash_after_execution_before_outcome():
    append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    # simulate missing outcome entry; recovery should append outcome_unknown
    recovered = recover_pending_outcomes()
    assert recovered == 1


def test_verify_after_restore():
    for _ in range(3):
        append_entry(agent_id="a", session_id="s", tool_name="read_file", decision="allow", reason_code="allowed", risk_score=0, policy_version="1.0")
    # backup
    with get_session() as session:
        rows = session.execute(text("SELECT * FROM audit_entries")).mappings().all()
        head = session.execute(text("SELECT * FROM audit_chain_head WHERE id=1")).mappings().first()
    with session_scope() as session:
        session.execute(text("DELETE FROM audit_entries"))
        session.execute(text("UPDATE audit_chain_head SET last_sequence=0, last_hash=decode(:h,'hex') WHERE id=1"), {"h": GENESIS_HASH})
    # restore
    with session_scope() as session:
        for row in rows:
            session.execute(
                text("INSERT INTO audit_entries (sequence, timestamp, agent_id, session_id, tool_name, decision, reason_code, risk_score, policy_version, previous_hash, entry_hash, payload) VALUES (:sequence, :timestamp, :agent_id, :session_id, :tool_name, :decision, :reason_code, :risk_score, :policy_version, :previous_hash, :entry_hash, :payload)"),
                {
                    "sequence": row["sequence"],
                    "timestamp": row["timestamp"],
                    "agent_id": row["agent_id"],
                    "session_id": row["session_id"],
                    "tool_name": row["tool_name"],
                    "decision": row["decision"],
                    "reason_code": row["reason_code"],
                    "risk_score": row["risk_score"],
                    "policy_version": row["policy_version"],
                    "previous_hash": row["previous_hash"],
                    "entry_hash": row["entry_hash"],
                    "payload": json.dumps(row["payload"]),
                },
            )
        session.execute(text("UPDATE audit_chain_head SET last_sequence=:seq, last_hash=:hash WHERE id=1"), {"seq": head["last_sequence"], "hash": head["last_hash"]})
    assert verify_chain()["ok"] is True


def test_gateway_role_privileges():
    from sqlalchemy import create_engine
    engine = create_engine("postgresql+psycopg://gf_gateway:change-me-gateway@/ghostfence_test?host=/tmp/opencode&port=5433")
    with engine.connect() as conn:
        for sql in ["UPDATE audit_entries SET reason_code='x' WHERE sequence=1",
                    "DELETE FROM audit_entries WHERE sequence=1",
                    "TRUNCATE audit_entries"]:
            try:
                conn.execute(text(sql))
                conn.commit()
                assert False, f"gateway allowed: {sql}"
            except Exception as e:
                assert "permission denied" in str(e).lower() or "permission" in str(e).lower()
    engine.dispose()