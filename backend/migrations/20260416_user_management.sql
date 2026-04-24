-- CyberAssetIQ — Named User Management Migration
-- 20260416_user_management.sql
-- Creates: tenant_users, user_invitations
-- Safe to run multiple times (IF NOT EXISTS throughout)

-- ── tenant_users ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant_users (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128) NOT NULL,

    -- Identity
    email                 VARCHAR(256) NOT NULL,
    full_name             VARCHAR(256) NOT NULL DEFAULT '',
    password_hash         VARCHAR(256) NOT NULL,

    -- Role: admin | read  (agent role is API-key only, not for human users)
    role                  VARCHAR(32)  NOT NULL DEFAULT 'read',

    -- Status
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    email_verified        BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Provenance
    invited_by_user_id    INTEGER      NULL,

    -- Activity tracking
    last_login_at         TIMESTAMPTZ  NULL,
    login_count           INTEGER      NOT NULL DEFAULT 0,
    last_ip               VARCHAR(64)  NULL,

    -- Optional profile fields
    job_title             VARCHAR(128) NULL,
    phone                 VARCHAR(32)  NULL,
    notes                 TEXT         NULL,

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Unique: one email per tenant
CREATE UNIQUE INDEX IF NOT EXISTS ix_tenant_users_tenant_email
    ON tenant_users (tenant_id, email);

CREATE INDEX IF NOT EXISTS ix_tenant_users_email
    ON tenant_users (email);

CREATE INDEX IF NOT EXISTS ix_tenant_users_tenant_active
    ON tenant_users (tenant_id, is_active);

-- ── user_invitations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_invitations (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128) NOT NULL,
    email                 VARCHAR(256) NOT NULL,
    role                  VARCHAR(32)  NOT NULL DEFAULT 'read',

    -- Token (SHA-256 hash — plaintext sent in email only)
    token_hash            VARCHAR(64)  NOT NULL UNIQUE,

    -- Who sent invite
    invited_by_user_id    INTEGER      NULL,
    invited_by_name       VARCHAR(256) NULL,

    -- Lifecycle
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ  NOT NULL,
    accepted_at           TIMESTAMPTZ  NULL,
    is_used               BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Optional message
    message               TEXT         NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_user_invitations_token
    ON user_invitations (token_hash);

CREATE INDEX IF NOT EXISTS ix_user_invitations_tenant_email
    ON user_invitations (tenant_id, email);

CREATE INDEX IF NOT EXISTS ix_user_invitations_pending
    ON user_invitations (tenant_id, is_used)
    WHERE is_used = FALSE;

-- ── Done ──────────────────────────────────────────────────────────────────────
-- Verify:
--   SELECT COUNT(*) FROM tenant_users;
--   SELECT COUNT(*) FROM user_invitations;
--
-- Create your first admin via:
--   POST /api/users/register
--   (requires existing API key, creates first named user for the tenant)
