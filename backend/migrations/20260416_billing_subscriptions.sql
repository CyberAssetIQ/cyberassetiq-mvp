-- CyberAssetIQ — Billing & Subscription Migration
-- 20260416_billing_subscriptions.sql
-- Creates: tenant_subscriptions, usage_records
-- Safe to run multiple times (IF NOT EXISTS throughout)

-- ── tenant_subscriptions ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant_subscriptions (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128) NOT NULL UNIQUE,

    tier                    VARCHAR(32)  NOT NULL DEFAULT 'trial',
    -- trial | starter | growth | professional | enterprise
    -- msp_starter | msp_growth | msp_scale | unlimited

    status                  VARCHAR(32)  NOT NULL DEFAULT 'trialing',
    -- trialing | active | past_due | cancelled | suspended

    billing_period          VARCHAR(16)  NOT NULL DEFAULT 'trial',
    -- trial | monthly | annual | none

    -- Trial / billing dates
    trial_ends_at           TIMESTAMPTZ  NULL,
    current_period_start    TIMESTAMPTZ  NULL,
    current_period_end      TIMESTAMPTZ  NULL,

    -- Pricing (pence — audit trail)
    price_gbp_pence         INTEGER      NOT NULL DEFAULT 0,

    -- Stripe
    stripe_customer_id      VARCHAR(128) NULL,
    stripe_subscription_id  VARCHAR(128) NULL,
    stripe_price_id         VARCHAR(128) NULL,

    -- Custom overrides (enterprise deals)
    custom_asset_limit      INTEGER      NULL,
    custom_msp_client_limit INTEGER      NULL,

    -- Internal
    internal_notes          TEXT         NULL,
    cancel_at_period_end    BOOLEAN      NOT NULL DEFAULT FALSE,
    cancelled_at            TIMESTAMPTZ  NULL,

    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS ix_tenant_subscriptions_tenant
    ON tenant_subscriptions (tenant_id);

CREATE INDEX IF NOT EXISTS ix_tenant_subscriptions_status
    ON tenant_subscriptions (status);

CREATE INDEX IF NOT EXISTS ix_tenant_subscriptions_tier
    ON tenant_subscriptions (tier);

-- ── usage_records ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usage_records (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128) NOT NULL,
    recorded_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Asset counts
    managed_asset_count     INTEGER      NOT NULL DEFAULT 0,
    network_asset_count     INTEGER      NOT NULL DEFAULT 0,
    total_asset_count       INTEGER      NOT NULL DEFAULT 0,

    -- Module usage
    vuln_findings_count     INTEGER      NOT NULL DEFAULT 0,
    compliance_runs_count   INTEGER      NOT NULL DEFAULT 0,
    darkweb_findings_count  INTEGER      NOT NULL DEFAULT 0,
    api_calls_count         INTEGER      NOT NULL DEFAULT 0,

    -- Tier context
    tier_at_record          VARCHAR(32)  NOT NULL DEFAULT 'trial',
    was_over_limit          BOOLEAN      NOT NULL DEFAULT FALSE,
    over_limit_by           INTEGER      NOT NULL DEFAULT 0
);

-- Indexes
CREATE INDEX IF NOT EXISTS ix_usage_records_tenant_date
    ON usage_records (tenant_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS ix_usage_records_over_limit
    ON usage_records (tenant_id, was_over_limit)
    WHERE was_over_limit = TRUE;

-- ── Seed development tenant with unlimited plan ───────────────────────────────
-- (Development tenant gets unlimited plan so existing tests are unaffected)
INSERT INTO tenant_subscriptions (
    tenant_id, tier, status, billing_period, price_gbp_pence,
    current_period_start, internal_notes
)
VALUES (
    'tenant-001',
    'unlimited',
    'active',
    'none',
    0,
    NOW(),
    'Development tenant — unlimited plan, no billing enforcement'
)
ON CONFLICT (tenant_id) DO UPDATE
    SET tier = 'unlimited',
        status = 'active',
        internal_notes = 'Development tenant — unlimited plan, no billing enforcement';

-- ── Done ──────────────────────────────────────────────────────────────────────
-- Verify:
--   SELECT tier, status, billing_period FROM tenant_subscriptions WHERE tenant_id = 'tenant-001';
