#!/usr/bin/env bash
set -euo pipefail

: "${POSTGRES_DB:=ghostfence}"
: "${POSTGRES_USER:=gf_admin}"
: "${GATEWAY_DB_USER:=gf_gateway}"
: "${GATEWAY_DB_PASSWORD:=change-me-gateway}"
: "${CHECKPOINTER_DB_USER:=gf_checkpointer}"
: "${CHECKPOINTER_DB_PASSWORD:=change-me-checkpointer}"
: "${TAMPER_ADMIN_DB_USER:=gf_tamper_admin}"
: "${TAMPER_ADMIN_DB_PASSWORD:=change-me-tamper}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE ${GATEWAY_DB_USER} LOGIN PASSWORD '${GATEWAY_DB_PASSWORD}';
CREATE ROLE ${CHECKPOINTER_DB_USER} LOGIN PASSWORD '${CHECKPOINTER_DB_PASSWORD}';
CREATE ROLE ${TAMPER_ADMIN_DB_USER} LOGIN PASSWORD '${TAMPER_ADMIN_DB_PASSWORD}';

CREATE TABLE IF NOT EXISTS audit_chain_head (
    id INTEGER PRIMARY KEY,
    last_sequence BIGINT NOT NULL,
    last_hash BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_entries (
    id BIGSERIAL PRIMARY KEY,
    sequence BIGINT NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    policy_version TEXT NOT NULL,
    previous_hash BYTEA NOT NULL,
    entry_hash BYTEA NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT, status TEXT NOT NULL DEFAULT 'active', policy_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, version TEXT NOT NULL, rules JSONB NOT NULL, created_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, task TEXT NOT NULL, tainted BOOLEAN NOT NULL DEFAULT false, taint_sources JSONB NOT NULL DEFAULT '[]'::jsonb, started_at TIMESTAMPTZ NOT NULL DEFAULT now(), ended_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS tool_calls (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tool_name TEXT NOT NULL, arguments JSONB NOT NULL, provenance JSONB NOT NULL DEFAULT '[]'::jsonb, requested_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY, tool_call_id TEXT NOT NULL, outcome TEXT NOT NULL, reasons JSONB NOT NULL DEFAULT '[]'::jsonb, matched_rules JSONB NOT NULL DEFAULT '[]'::jsonb, risk_score INTEGER NOT NULL DEFAULT 0, policy_version TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, tool_call_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', approver TEXT, decided_at TIMESTAMPTZ, notes TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS content_inspections (id TEXT PRIMARY KEY, content_ref TEXT NOT NULL, source_type TEXT NOT NULL, severity INTEGER NOT NULL, findings JSONB NOT NULL DEFAULT '[]'::jsonb, evidence_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS attack_runs (id TEXT PRIMARY KEY, scenario TEXT NOT NULL, mode TEXT NOT NULL, summary JSONB NOT NULL DEFAULT '{}'::jsonb, started_at TIMESTAMPTZ NOT NULL DEFAULT now(), ended_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS checkpoints (id TEXT PRIMARY KEY, sequence BIGINT NOT NULL, signed_checkpoint BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());

INSERT INTO audit_chain_head (id, last_sequence, last_hash)
VALUES (1, 0, decode('4febf9bd83efbb0c82bbe8cef0eb8aa3d69224b0f0086675fc198f32c1c396de', 'hex'))
ON CONFLICT (id) DO NOTHING;

GRANT SELECT, INSERT ON audit_entries, audit_chain_head TO ${GATEWAY_DB_USER};
GRANT SELECT, INSERT, UPDATE, DELETE ON agents, policies, sessions, tool_calls, decisions, approvals, content_inspections, attack_runs TO ${GATEWAY_DB_USER};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${GATEWAY_DB_USER};

GRANT SELECT, INSERT, UPDATE, DELETE ON audit_entries, audit_chain_head, agents, policies, sessions, tool_calls, decisions, approvals, content_inspections, attack_runs, checkpoints TO ${TAMPER_ADMIN_DB_USER};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${TAMPER_ADMIN_DB_USER};

GRANT SELECT, INSERT ON checkpoints TO ${CHECKPOINTER_DB_USER};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${CHECKPOINTER_DB_USER};
SQL