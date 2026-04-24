-- ============================================================
-- CyberAssetIQ AI Module — Database Migration
-- File: 20260402_add_ai_module.sql
-- Run ONCE against the cyberassetiq PostgreSQL database
-- Safe: all statements use IF NOT EXISTS / DO NOTHING patterns
-- ============================================================

-- ── ai_correlations ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_correlations (
    id                  SERIAL PRIMARY KEY,
    tenant_id           VARCHAR(128)    NOT NULL DEFAULT 'tenant-001',
    correlation_type    VARCHAR(64)     NOT NULL,
    title               VARCHAR(255)    NOT NULL,
    summary             TEXT,
    status              VARCHAR(32)     NOT NULL DEFAULT 'open',
    confidence_score    FLOAT,
    risk_score          FLOAT,
    asset_id            INTEGER,
    asset_name          VARCHAR(255),
    ip_address          VARCHAR(64),
    hostname            VARCHAR(255),
    user_ref            VARCHAR(255),
    event_refs_json     JSONB,
    alert_refs_json     JSONB,
    attack_chain_json   JSONB,
    mitre_map_json      JSONB,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ai_correlations_tenant_status
    ON ai_correlations (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_ai_correlations_tenant_type
    ON ai_correlations (tenant_id, correlation_type);

CREATE INDEX IF NOT EXISTS ix_ai_correlations_tenant_asset
    ON ai_correlations (tenant_id, asset_id);


-- ── ai_investigations ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_investigations (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128)    NOT NULL DEFAULT 'tenant-001',
    alert_id                INTEGER         REFERENCES ai_alerts(id) ON DELETE SET NULL,
    correlation_id          INTEGER         REFERENCES ai_correlations(id) ON DELETE SET NULL,
    executive_summary       TEXT,
    technical_summary       TEXT,
    remediation_steps_json  JSONB,
    timeline_json           JSONB,
    model_used              VARCHAR(128),
    prompt_version          VARCHAR(64),
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ai_investigations_tenant_alert
    ON ai_investigations (tenant_id, alert_id);

CREATE INDEX IF NOT EXISTS ix_ai_investigations_tenant_correlation
    ON ai_investigations (tenant_id, correlation_id);


-- ── ai_baselines ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_baselines (
    id              SERIAL PRIMARY KEY,
    tenant_id       VARCHAR(128)    NOT NULL DEFAULT 'tenant-001',
    entity_type     VARCHAR(32)     NOT NULL,   -- asset, user, network
    entity_ref      VARCHAR(255)    NOT NULL,   -- hostname, username, subnet
    baseline_type   VARCHAR(64)     NOT NULL,   -- login_hours, outbound_ports, process_names
    baseline_json   JSONB           NOT NULL,
    version         INTEGER         NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ai_baselines_tenant_entity
    ON ai_baselines (tenant_id, entity_type, entity_ref);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_baselines_entity_type
    ON ai_baselines (tenant_id, entity_ref, baseline_type);


-- ── ai_model_runs ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ai_model_runs (
    id                  SERIAL PRIMARY KEY,
    tenant_id           VARCHAR(128)    NOT NULL DEFAULT 'tenant-001',
    model_name          VARCHAR(128)    NOT NULL,
    provider_name       VARCHAR(64),
    run_type            VARCHAR(64)     NOT NULL,   -- copilot, explain_alert, daily_brief, investigation
    input_ref           VARCHAR(255),
    output_ref          VARCHAR(255),
    latency_ms          INTEGER,
    prompt_tokens       INTEGER,
    completion_tokens   INTEGER,
    total_tokens        INTEGER,
    success             BOOLEAN         NOT NULL DEFAULT TRUE,
    error_message       TEXT,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ai_model_runs_tenant_type
    ON ai_model_runs (tenant_id, run_type);

CREATE INDEX IF NOT EXISTS ix_ai_model_runs_created_at
    ON ai_model_runs (created_at DESC);


-- ── Add missing columns to existing ai_events if upgrading ────
-- (Safe to run even if columns already exist — will error silently on PostgreSQL 9.6+)

DO $$
BEGIN
    -- mitre_tactic
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_events' AND column_name='mitre_tactic'
    ) THEN
        ALTER TABLE ai_events ADD COLUMN mitre_tactic VARCHAR(64);
    END IF;

    -- mitre_technique
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_events' AND column_name='mitre_technique'
    ) THEN
        ALTER TABLE ai_events ADD COLUMN mitre_technique VARCHAR(64);
    END IF;

    -- confidence_score
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_events' AND column_name='confidence_score'
    ) THEN
        ALTER TABLE ai_events ADD COLUMN confidence_score FLOAT;
    END IF;
END
$$;


-- ── Add missing columns to existing ai_alerts if upgrading ────

DO $$
BEGIN
    -- mitre_tactic
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_alerts' AND column_name='mitre_tactic'
    ) THEN
        ALTER TABLE ai_alerts ADD COLUMN mitre_tactic VARCHAR(64);
    END IF;

    -- mitre_technique
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_alerts' AND column_name='mitre_technique'
    ) THEN
        ALTER TABLE ai_alerts ADD COLUMN mitre_technique VARCHAR(64);
    END IF;

    -- risk_score
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_alerts' AND column_name='risk_score'
    ) THEN
        ALTER TABLE ai_alerts ADD COLUMN risk_score FLOAT;
    END IF;

    -- llm_summary
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='ai_alerts' AND column_name='llm_summary'
    ) THEN
        ALTER TABLE ai_alerts ADD COLUMN llm_summary TEXT;
    END IF;
END
$$;

-- ── Done ──────────────────────────────────────────────────────
-- Tables created: ai_correlations, ai_investigations, ai_baselines, ai_model_runs
-- Columns patched: ai_events (mitre_tactic, mitre_technique, confidence_score)
--                  ai_alerts (mitre_tactic, mitre_technique, risk_score, llm_summary)
