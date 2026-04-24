-- ============================================================================
-- Migration: 20260419_soft_delete_keys_tokens.sql
-- Purpose:   Replace hard-delete on API keys with soft-delete (archive).
--            Add full audit trail to both tenant_api_keys and
--            agent_enrollment_tokens: who revoked, when, and why.
-- ============================================================================

-- ── tenant_api_keys ──────────────────────────────────────────────────────────
ALTER TABLE tenant_api_keys
    ADD COLUMN IF NOT EXISTS revoked_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by_key_id  INTEGER,
    ADD COLUMN IF NOT EXISTS revocation_reason  VARCHAR(255);

-- ── agent_enrollment_tokens ──────────────────────────────────────────────────
ALTER TABLE agent_enrollment_tokens
    ADD COLUMN IF NOT EXISTS revoked_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by_key_id  INTEGER,
    ADD COLUMN IF NOT EXISTS revocation_reason  VARCHAR(255);
