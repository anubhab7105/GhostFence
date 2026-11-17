ALTER TABLE sessions ADD COLUMN IF NOT EXISTS sensitivity_high_water TEXT NOT NULL DEFAULT 'public';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS trust_state TEXT NOT NULL DEFAULT 'trusted';

GRANT SELECT, INSERT, UPDATE ON sessions TO gf_gateway;