-- ============================================================================
-- Migration: 20260420_agent_trust_key.sql
-- Purpose:   Add per-agent trust_key column to the agents table.
--            Each agent gets a unique rotating secret used to verify
--            that commands and telemetry originate from a known device.
--            Rotation invalidates the old key immediately without
--            revoking the tenant-level API key.
-- Applies to: PostgreSQL (production) and SQLite (dev/test)
-- Safe to re-run: all statements use IF NOT EXISTS / DO NOTHING guards
-- ============================================================================

-- ── 1. Add the column ────────────────────────────────────────────────────────
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS trust_key            VARCHAR(128),
    ADD COLUMN IF NOT EXISTS trust_key_issued_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS trust_key_rotated_by VARCHAR(128);  -- label of the admin key that triggered rotation

-- ── 2. Back-fill existing rows with a random key ─────────────────────────────
--      gen_random_bytes is available in PostgreSQL 9.6+ (pgcrypto built-in).
--      For SQLite dev environments this UPDATE will need to be run from Python
--      (see seed_demo_data.py patch note below).
UPDATE agents
SET
    trust_key            = encode(gen_random_bytes(32), 'hex'),
    trust_key_issued_at  = NOW(),
    trust_key_rotated_by = 'migration'
WHERE trust_key IS NULL;

-- ── 3. Index for fast lookup during command authentication ───────────────────
CREATE INDEX IF NOT EXISTS ix_agents_trust_key ON agents (trust_key)
    WHERE trust_key IS NOT NULL;

-- ── Notes ────────────────────────────────────────────────────────────────────
-- • trust_key is NOT the same as the tenant API key in tenant_api_keys.
--   It is scoped to a single agent and can be rotated without affecting
--   any other agent or the broader tenant authentication.
-- • The plaintext key is returned ONCE on rotate and must be stored by the
--   operator (same UX as tenant API key creation).
-- • For SQLite (dev): run the following after applying this migration:
--     python -c "
--     from db.session import SessionLocal
--     from models.agent import Agent
--     import secrets
--     db = SessionLocal()
--     for a in db.query(Agent).filter(Agent.trust_key == None).all():
--         a.trust_key = secrets.token_hex(32)
--     db.commit(); db.close()
--     print('done')
--     "
-- ============================================================================
