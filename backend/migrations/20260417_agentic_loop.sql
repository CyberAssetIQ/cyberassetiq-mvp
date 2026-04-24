-- CyberAssetIQ — Supervised Agentic AI Loop Migration
-- 20260417_agentic_loop.sql
-- Creates: agent_loop_runs, agent_loop_actions
-- Safe to run multiple times (IF NOT EXISTS throughout)

-- ── agent_loop_runs ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_loop_runs (
    id                          SERIAL PRIMARY KEY,
    tenant_id                   VARCHAR(128) NOT NULL,

    -- Trigger
    trigger_type                VARCHAR(64)  NOT NULL DEFAULT 'manual',
    trigger_ref_id              INTEGER      NULL,
    trigger_ref_type            VARCHAR(64)  NULL,
    trigger_asset_id            INTEGER      NULL,
    trigger_summary             TEXT         NOT NULL DEFAULT '',

    -- Lifecycle
    status                      VARCHAR(32)  NOT NULL DEFAULT 'pending',
    started_at                  TIMESTAMPTZ  NULL,
    completed_at                TIMESTAMPTZ  NULL,
    error_message               TEXT         NULL,

    -- Context gathered
    context_json                JSONB        NULL,
    context_gathered_at         TIMESTAMPTZ  NULL,

    -- AI Decision Brief
    brief_title                 VARCHAR(256) NULL,
    brief_severity              VARCHAR(32)  NULL,
    brief_confidence            INTEGER      NOT NULL DEFAULT 0,
    brief_summary               TEXT         NULL,
    brief_technical             TEXT         NULL,
    brief_mitre_tactic          VARCHAR(64)  NULL,
    brief_mitre_technique       VARCHAR(64)  NULL,
    brief_generated_at          TIMESTAMPTZ  NULL,
    ai_model_used               VARCHAR(128) NULL,

    -- Risk impact
    assessed_risk_score         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    affected_asset_count        INTEGER      NOT NULL DEFAULT 0,
    crown_jewels_at_risk        INTEGER      NOT NULL DEFAULT 0,

    -- Action counters
    total_actions               INTEGER      NOT NULL DEFAULT 0,
    auto_executed               INTEGER      NOT NULL DEFAULT 0,
    pending_approval            INTEGER      NOT NULL DEFAULT 0,
    approved_actions            INTEGER      NOT NULL DEFAULT 0,
    rejected_actions            INTEGER      NOT NULL DEFAULT 0,

    -- Linked records
    incident_id                 INTEGER      NULL,
    investigation_id            INTEGER      NULL,

    -- Reviewer
    reviewed_by                 VARCHAR(128) NULL,
    reviewed_at                 TIMESTAMPTZ  NULL,

    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_loop_runs_tenant_status
    ON agent_loop_runs (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_agent_loop_runs_trigger
    ON agent_loop_runs (tenant_id, trigger_type);

CREATE INDEX IF NOT EXISTS ix_agent_loop_runs_created
    ON agent_loop_runs (tenant_id, created_at DESC);

-- ── agent_loop_actions ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_loop_actions (
    id                          SERIAL PRIMARY KEY,
    tenant_id                   VARCHAR(128) NOT NULL,
    run_id                      INTEGER      NOT NULL,

    -- Action identity
    action_type                 VARCHAR(64)  NOT NULL,
    tier                        INTEGER      NOT NULL DEFAULT 0,
    title                       VARCHAR(256) NOT NULL,
    rationale                   TEXT         NOT NULL DEFAULT '',
    expected_outcome            TEXT         NOT NULL DEFAULT '',
    risk_reduction_estimate     DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    -- Target
    target_type                 VARCHAR(64)  NULL,
    target_id                   VARCHAR(128) NULL,
    target_name                 VARCHAR(256) NULL,
    action_params               JSONB        NULL,

    -- Status
    status                      VARCHAR(32)  NOT NULL DEFAULT 'pending',

    -- Execution
    executed_at                 TIMESTAMPTZ  NULL,
    execution_result            TEXT         NULL,
    execution_ref_id            VARCHAR(128) NULL,

    -- Human decision
    decided_by                  VARCHAR(128) NULL,
    decided_at                  TIMESTAMPTZ  NULL,
    decision_note               TEXT         NULL,

    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_loop_actions_run
    ON agent_loop_actions (run_id);

CREATE INDEX IF NOT EXISTS ix_agent_loop_actions_tenant_status
    ON agent_loop_actions (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_agent_loop_actions_tenant_tier
    ON agent_loop_actions (tenant_id, tier);

CREATE INDEX IF NOT EXISTS ix_agent_loop_actions_pending
    ON agent_loop_actions (tenant_id, status, tier)
    WHERE status = 'pending' AND tier > 0;

-- ── Done ──────────────────────────────────────────────────────────────────────
-- Verify:
--   SELECT COUNT(*) FROM agent_loop_runs;
--   SELECT COUNT(*) FROM agent_loop_actions;
