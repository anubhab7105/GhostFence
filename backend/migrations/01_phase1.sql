CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    task TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    denial_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON runs TO gf_gateway;
GRANT SELECT, INSERT, UPDATE ON idempotency_keys TO gf_gateway;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gf_gateway;
GRANT SELECT, INSERT, UPDATE ON runs, idempotency_keys TO gf_tamper_admin;