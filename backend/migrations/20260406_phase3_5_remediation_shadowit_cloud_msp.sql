-- =============================================================================
-- CyberAssetIQ Phase 3-5 Migration
-- Phases: Remediation Automation | Shadow IT | Cloud Posture | MSP Portfolio
-- Date:   2026-04-06
-- Safe:   All CREATE TABLE IF NOT EXISTS — idempotent, safe to re-run
-- Rollback: Uncomment DROP TABLE block at the bottom
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 3A: Remediation Automation Expansion
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS remediation_actions (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    asset_id              INTEGER,
    action_type           VARCHAR(64)   NOT NULL,
    parameters_json       JSONB,
    safety_level          VARCHAR(32)   NOT NULL DEFAULT 'informational',
    source                VARCHAR(64)   NOT NULL DEFAULT 'manual',
    trigger_finding_type  VARCHAR(64),
    trigger_severity      VARCHAR(16),
    created_by            VARCHAR(128)  NOT NULL DEFAULT 'system',
    status                VARCHAR(32)   NOT NULL DEFAULT 'pending',
    result_summary        TEXT,
    expected_score_gain   FLOAT         NOT NULL DEFAULT 0.0,
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    executed_at           TIMESTAMPTZ,
    -- TimestampMixin columns
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_remediation_actions_tenant_asset
    ON remediation_actions (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_remediation_actions_tenant_status
    ON remediation_actions (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_remediation_actions_action_type
    ON remediation_actions (tenant_id, action_type);


CREATE TABLE IF NOT EXISTS remediation_playbooks (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    playbook_name         VARCHAR(128)  NOT NULL,
    trigger_type          VARCHAR(64)   NOT NULL,
    trigger_condition_json JSONB,
    steps_json            JSONB,
    approval_required     BOOLEAN       NOT NULL DEFAULT TRUE,
    enabled               BOOLEAN       NOT NULL DEFAULT FALSE,
    run_count             INTEGER       NOT NULL DEFAULT 0,
    last_triggered_at     TIMESTAMPTZ,
    description           TEXT,
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_remediation_playbooks_tenant
    ON remediation_playbooks (tenant_id);
CREATE INDEX IF NOT EXISTS ix_remediation_playbooks_trigger
    ON remediation_playbooks (tenant_id, trigger_type);


CREATE TABLE IF NOT EXISTS remediation_runs (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    playbook_id           INTEGER,
    action_id             INTEGER,
    asset_id              INTEGER,
    result_status         VARCHAR(32)   NOT NULL DEFAULT 'running',
    execution_log_json    JSONB,
    triggered_by          VARCHAR(128)  NOT NULL DEFAULT 'system',
    started_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    ended_at              TIMESTAMPTZ,
    duration_seconds      INTEGER,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_remediation_runs_tenant
    ON remediation_runs (tenant_id);
CREATE INDEX IF NOT EXISTS ix_remediation_runs_playbook
    ON remediation_runs (tenant_id, playbook_id);
CREATE INDEX IF NOT EXISTS ix_remediation_runs_action
    ON remediation_runs (tenant_id, action_id);
CREATE INDEX IF NOT EXISTS ix_remediation_runs_status
    ON remediation_runs (tenant_id, result_status);


CREATE TABLE IF NOT EXISTS remediation_approvals (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    action_id             INTEGER       NOT NULL,
    requested_by          VARCHAR(128)  NOT NULL DEFAULT 'system',
    approved_by           VARCHAR(128),
    approval_status       VARCHAR(32)   NOT NULL DEFAULT 'pending',
    notes                 TEXT,
    expires_at            TIMESTAMPTZ,
    approved_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_remediation_approvals_tenant
    ON remediation_approvals (tenant_id);
CREATE INDEX IF NOT EXISTS ix_remediation_approvals_action
    ON remediation_approvals (tenant_id, action_id);
CREATE INDEX IF NOT EXISTS ix_remediation_approvals_status
    ON remediation_approvals (tenant_id, approval_status);


-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 3B: Shadow IT Detection
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS shadow_it_findings (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    source_asset_id       INTEGER,
    finding_type          VARCHAR(64)   NOT NULL,
    entity_name           VARCHAR(256)  NOT NULL,
    entity_category       VARCHAR(64),
    risk_score            FLOAT         NOT NULL DEFAULT 0.0,
    risk_rationale        TEXT,
    description           TEXT,
    evidence_json         JSONB,
    status                VARCHAR(32)   NOT NULL DEFAULT 'open',
    is_data_exfil_risk    BOOLEAN       NOT NULL DEFAULT FALSE,
    is_compliance_risk    BOOLEAN       NOT NULL DEFAULT FALSE,
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_shadow_it_findings_tenant
    ON shadow_it_findings (tenant_id);
CREATE INDEX IF NOT EXISTS ix_shadow_it_findings_type
    ON shadow_it_findings (tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS ix_shadow_it_findings_status
    ON shadow_it_findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_shadow_it_findings_risk
    ON shadow_it_findings (tenant_id, risk_score);


CREATE TABLE IF NOT EXISTS rogue_software_findings (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    asset_id              INTEGER       NOT NULL,
    software_name         VARCHAR(256)  NOT NULL,
    software_version      VARCHAR(64),
    publisher             VARCHAR(256),
    install_path          VARCHAR(512),
    category              VARCHAR(64),
    risk_score            FLOAT         NOT NULL DEFAULT 0.0,
    risk_flags            JSONB,
    approved_status       VARCHAR(32)   NOT NULL DEFAULT 'unapproved',
    cve_count             INTEGER       NOT NULL DEFAULT 0,
    has_known_cves        BOOLEAN       NOT NULL DEFAULT FALSE,
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_rogue_software_tenant_asset
    ON rogue_software_findings (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_rogue_software_tenant_name
    ON rogue_software_findings (tenant_id, software_name);
CREATE INDEX IF NOT EXISTS ix_rogue_software_status
    ON rogue_software_findings (tenant_id, approved_status);
CREATE INDEX IF NOT EXISTS ix_rogue_software_risk
    ON rogue_software_findings (tenant_id, risk_score);


CREATE TABLE IF NOT EXISTS unknown_device_findings (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    ip_address            VARCHAR(45)   NOT NULL,
    mac_address           VARCHAR(64),
    hostname              VARCHAR(256),
    network_segment       VARCHAR(64),
    device_type_guess     VARCHAR(64),
    open_ports            JSONB,
    vendor_oui            VARCHAR(128),
    risk_score            FLOAT         NOT NULL DEFAULT 5.0,
    risk_flags            JSONB,
    status                VARCHAR(32)   NOT NULL DEFAULT 'unresolved',
    source_scan_id        INTEGER,
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_unknown_device_tenant
    ON unknown_device_findings (tenant_id);
CREATE INDEX IF NOT EXISTS ix_unknown_device_ip
    ON unknown_device_findings (tenant_id, ip_address);
CREATE INDEX IF NOT EXISTS ix_unknown_device_risk
    ON unknown_device_findings (tenant_id, risk_score);
CREATE INDEX IF NOT EXISTS ix_unknown_device_status
    ON unknown_device_findings (tenant_id, status);


-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 4: Cloud / SaaS / Identity Posture
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cloud_accounts (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128)  NOT NULL,
    provider                VARCHAR(32)   NOT NULL,
    account_name            VARCHAR(256)  NOT NULL,
    account_identifier      VARCHAR(256),
    status                  VARCHAR(32)   NOT NULL DEFAULT 'pending',
    connection_metadata_json JSONB,
    posture_score           FLOAT         NOT NULL DEFAULT 0.0,
    findings_count          INTEGER       NOT NULL DEFAULT 0,
    critical_findings_count INTEGER       NOT NULL DEFAULT 0,
    last_synced_at          TIMESTAMPTZ,
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_cloud_accounts_tenant_provider
    ON cloud_accounts (tenant_id, provider);
CREATE INDEX IF NOT EXISTS ix_cloud_accounts_status
    ON cloud_accounts (tenant_id, status);


CREATE TABLE IF NOT EXISTS cloud_assets (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    cloud_account_id      INTEGER       NOT NULL,
    asset_type            VARCHAR(64)   NOT NULL,
    external_id           VARCHAR(512)  NOT NULL,
    name                  VARCHAR(256),
    region                VARCHAR(64),
    environment           VARCHAR(64),
    is_internet_facing    BOOLEAN       NOT NULL DEFAULT FALSE,
    is_public             BOOLEAN       NOT NULL DEFAULT FALSE,
    has_mfa               BOOLEAN,
    tags_json             JSONB,
    metadata_json         JSONB,
    discovered_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_cloud_assets_tenant_account
    ON cloud_assets (tenant_id, cloud_account_id);
CREATE INDEX IF NOT EXISTS ix_cloud_assets_type
    ON cloud_assets (tenant_id, asset_type);
CREATE INDEX IF NOT EXISTS ix_cloud_assets_external_id
    ON cloud_assets (tenant_id, external_id);


CREATE TABLE IF NOT EXISTS cloud_posture_findings (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    cloud_account_id      INTEGER       NOT NULL,
    cloud_asset_id        INTEGER,
    provider              VARCHAR(32)   NOT NULL,
    finding_type          VARCHAR(128)  NOT NULL,
    severity              VARCHAR(16)   NOT NULL DEFAULT 'medium',
    title                 VARCHAR(256)  NOT NULL,
    description           TEXT,
    recommendation        TEXT,
    resource_id           VARCHAR(512),
    resource_name         VARCHAR(256),
    compliance_controls   JSONB,
    status                VARCHAR(32)   NOT NULL DEFAULT 'open',
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    resolved_at           TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_cloud_posture_findings_tenant
    ON cloud_posture_findings (tenant_id);
CREATE INDEX IF NOT EXISTS ix_cloud_posture_findings_account
    ON cloud_posture_findings (tenant_id, cloud_account_id);
CREATE INDEX IF NOT EXISTS ix_cloud_posture_findings_severity
    ON cloud_posture_findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_cloud_posture_findings_type
    ON cloud_posture_findings (tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS ix_cloud_posture_findings_status
    ON cloud_posture_findings (tenant_id, status);


CREATE TABLE IF NOT EXISTS identity_posture_findings (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    cloud_account_id      INTEGER,
    provider              VARCHAR(32)   NOT NULL,
    identity_name         VARCHAR(256),
    identity_type         VARCHAR(32),
    finding_type          VARCHAR(128)  NOT NULL,
    severity              VARCHAR(16)   NOT NULL DEFAULT 'medium',
    title                 VARCHAR(256)  NOT NULL,
    description           TEXT,
    recommendation        TEXT,
    affected_count        INTEGER       NOT NULL DEFAULT 1,
    evidence_json         JSONB,
    status                VARCHAR(32)   NOT NULL DEFAULT 'open',
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_identity_posture_findings_tenant
    ON identity_posture_findings (tenant_id);
CREATE INDEX IF NOT EXISTS ix_identity_posture_findings_provider
    ON identity_posture_findings (tenant_id, provider);
CREATE INDEX IF NOT EXISTS ix_identity_posture_findings_severity
    ON identity_posture_findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_identity_posture_findings_type
    ON identity_posture_findings (tenant_id, finding_type);


CREATE TABLE IF NOT EXISTS saas_apps (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    app_name              VARCHAR(256)  NOT NULL,
    app_category          VARCHAR(64),
    vendor                VARCHAR(256),
    source                VARCHAR(64)   NOT NULL DEFAULT 'software_inventory',
    discovered_by         VARCHAR(128),
    risk_score            FLOAT         NOT NULL DEFAULT 0.0,
    risk_flags            JSONB,
    approved_status       VARCHAR(32)   NOT NULL DEFAULT 'unknown',
    user_count            INTEGER       NOT NULL DEFAULT 0,
    has_data_access       BOOLEAN       NOT NULL DEFAULT FALSE,
    data_classifications  JSONB,
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_saas_apps_tenant
    ON saas_apps (tenant_id);
CREATE INDEX IF NOT EXISTS ix_saas_apps_name
    ON saas_apps (tenant_id, app_name);
CREATE INDEX IF NOT EXISTS ix_saas_apps_status
    ON saas_apps (tenant_id, approved_status);
CREATE INDEX IF NOT EXISTS ix_saas_apps_risk
    ON saas_apps (tenant_id, risk_score);


CREATE TABLE IF NOT EXISTS saas_posture_findings (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    app_id                INTEGER       NOT NULL,
    finding_type          VARCHAR(128)  NOT NULL,
    severity              VARCHAR(16)   NOT NULL DEFAULT 'medium',
    description           TEXT,
    recommendation        TEXT,
    status                VARCHAR(32)   NOT NULL DEFAULT 'open',
    detected_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_saas_posture_findings_tenant
    ON saas_posture_findings (tenant_id);
CREATE INDEX IF NOT EXISTS ix_saas_posture_findings_app
    ON saas_posture_findings (tenant_id, app_id);
CREATE INDEX IF NOT EXISTS ix_saas_posture_findings_severity
    ON saas_posture_findings (tenant_id, severity);


CREATE TABLE IF NOT EXISTS connector_sync_logs (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    cloud_account_id      INTEGER,
    provider              VARCHAR(32)   NOT NULL,
    status                VARCHAR(32)   NOT NULL DEFAULT 'running',
    assets_discovered     INTEGER       NOT NULL DEFAULT 0,
    findings_created      INTEGER       NOT NULL DEFAULT 0,
    findings_resolved     INTEGER       NOT NULL DEFAULT 0,
    error_message         TEXT,
    summary_json          JSONB,
    started_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    finished_at           TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_connector_sync_logs_tenant_provider
    ON connector_sync_logs (tenant_id, provider);
CREATE INDEX IF NOT EXISTS ix_connector_sync_logs_status
    ON connector_sync_logs (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_connector_sync_logs_started
    ON connector_sync_logs (tenant_id, started_at);


-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 4B: Business Context (cross-cutting)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS data_classifications (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128)  NOT NULL,
    label                   VARCHAR(64)   NOT NULL,
    description             TEXT,
    sensitivity_level       INTEGER       NOT NULL DEFAULT 1,
    applicable_frameworks   JSONB,
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_data_classifications_tenant
    ON data_classifications (tenant_id);


CREATE TABLE IF NOT EXISTS asset_business_context (
    id                    SERIAL PRIMARY KEY,
    tenant_id             VARCHAR(128)  NOT NULL,
    asset_id              INTEGER       NOT NULL,
    asset_type_override   VARCHAR(64),
    owner_name            VARCHAR(256),
    owner_email           VARCHAR(256),
    business_unit         VARCHAR(128),
    location              VARCHAR(128),
    data_classifications  JSONB,
    is_internet_facing    BOOLEAN       NOT NULL DEFAULT FALSE,
    is_in_dmz             BOOLEAN       NOT NULL DEFAULT FALSE,
    is_production         BOOLEAN       NOT NULL DEFAULT TRUE,
    sla_tier              VARCHAR(16),
    custom_notes          TEXT,
    custom_tags_json      JSONB,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_asset_business_context_tenant_asset
    ON asset_business_context (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_asset_business_context_owner
    ON asset_business_context (tenant_id, owner_name);


-- ─────────────────────────────────────────────────────────────────────────────
-- PHASE 5: MSP Portfolio Management
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS msp_accounts (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128)  NOT NULL UNIQUE,
    name                    VARCHAR(256)  NOT NULL,
    contact_email           VARCHAR(256),
    phone                   VARCHAR(64),
    website                 VARCHAR(256),
    role                    VARCHAR(32)   NOT NULL DEFAULT 'msp',
    is_active               BOOLEAN       NOT NULL DEFAULT TRUE,
    managed_tenants_count   INTEGER       NOT NULL DEFAULT 0,
    plan                    VARCHAR(64)   NOT NULL DEFAULT 'msp_standard',
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_msp_accounts_tenant
    ON msp_accounts (tenant_id);


CREATE TABLE IF NOT EXISTS msp_tenant_map (
    id                    SERIAL PRIMARY KEY,
    msp_account_id        INTEGER       NOT NULL,
    managed_tenant_id     VARCHAR(128)  NOT NULL,
    client_name           VARCHAR(256),
    client_industry       VARCHAR(64),
    relationship_type     VARCHAR(32)   NOT NULL DEFAULT 'managed',
    is_active             BOOLEAN       NOT NULL DEFAULT TRUE,
    monthly_rate          FLOAT,
    contract_start        TIMESTAMPTZ,
    contract_end          TIMESTAMPTZ,
    notes                 TEXT,
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_msp_tenant_map_msp
    ON msp_tenant_map (msp_account_id);
CREATE INDEX IF NOT EXISTS ix_msp_tenant_map_managed
    ON msp_tenant_map (managed_tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_msp_tenant_map_pair
    ON msp_tenant_map (msp_account_id, managed_tenant_id);


CREATE TABLE IF NOT EXISTS tenant_health_scores (
    id                      SERIAL PRIMARY KEY,
    tenant_id               VARCHAR(128)  NOT NULL,
    msp_account_id          INTEGER,
    overall_score           FLOAT         NOT NULL DEFAULT 0.0,
    exposure_score          FLOAT         NOT NULL DEFAULT 0.0,
    resilience_score        FLOAT         NOT NULL DEFAULT 0.0,
    compliance_score        FLOAT         NOT NULL DEFAULT 0.0,
    identity_score          FLOAT         NOT NULL DEFAULT 0.0,
    patch_score             FLOAT         NOT NULL DEFAULT 0.0,
    drift_score             FLOAT         NOT NULL DEFAULT 0.0,
    severity_band           VARCHAR(16)   NOT NULL DEFAULT 'unknown',
    asset_count             INTEGER       NOT NULL DEFAULT 0,
    critical_findings_count INTEGER       NOT NULL DEFAULT 0,
    open_cves_count         INTEGER       NOT NULL DEFAULT 0,
    unresolved_drift_count  INTEGER       NOT NULL DEFAULT 0,
    last_scan_epoch         INTEGER,
    ce_compliance_pct       FLOAT         NOT NULL DEFAULT 0.0,
    delta_7d                FLOAT         NOT NULL DEFAULT 0.0,
    score_breakdown_json    JSONB,
    top_risks_json          JSONB,
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_tenant_health_scores_tenant
    ON tenant_health_scores (tenant_id);
CREATE INDEX IF NOT EXISTS ix_tenant_health_scores_updated
    ON tenant_health_scores (tenant_id, updated_at);
CREATE INDEX IF NOT EXISTS ix_tenant_health_scores_overall
    ON tenant_health_scores (tenant_id, overall_score);


CREATE TABLE IF NOT EXISTS portfolio_alerts (
    id                    SERIAL PRIMARY KEY,
    msp_account_id        INTEGER       NOT NULL,
    tenant_id             VARCHAR(128)  NOT NULL,
    alert_type            VARCHAR(64)   NOT NULL,
    severity              VARCHAR(16)   NOT NULL DEFAULT 'medium',
    title                 VARCHAR(256)  NOT NULL,
    summary               TEXT,
    evidence_json         JSONB,
    status                VARCHAR(32)   NOT NULL DEFAULT 'open',
    acknowledged_by       VARCHAR(128),
    acknowledged_at       TIMESTAMPTZ,
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    resolved_at           TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_portfolio_alerts_msp
    ON portfolio_alerts (msp_account_id);
CREATE INDEX IF NOT EXISTS ix_portfolio_alerts_tenant
    ON portfolio_alerts (tenant_id);
CREATE INDEX IF NOT EXISTS ix_portfolio_alerts_severity
    ON portfolio_alerts (msp_account_id, severity);
CREATE INDEX IF NOT EXISTS ix_portfolio_alerts_status
    ON portfolio_alerts (msp_account_id, status);
CREATE INDEX IF NOT EXISTS ix_portfolio_alerts_created
    ON portfolio_alerts (msp_account_id, created_at);


-- =============================================================================
-- ROLLBACK (uncomment to revert Phase 3-5 tables only)
-- =============================================================================
-- DROP TABLE IF EXISTS portfolio_alerts;
-- DROP TABLE IF EXISTS tenant_health_scores;
-- DROP TABLE IF EXISTS msp_tenant_map;
-- DROP TABLE IF EXISTS msp_accounts;
-- DROP TABLE IF EXISTS asset_business_context;
-- DROP TABLE IF EXISTS data_classifications;
-- DROP TABLE IF EXISTS connector_sync_logs;
-- DROP TABLE IF EXISTS saas_posture_findings;
-- DROP TABLE IF EXISTS saas_apps;
-- DROP TABLE IF EXISTS identity_posture_findings;
-- DROP TABLE IF EXISTS cloud_posture_findings;
-- DROP TABLE IF EXISTS cloud_assets;
-- DROP TABLE IF EXISTS cloud_accounts;
-- DROP TABLE IF EXISTS unknown_device_findings;
-- DROP TABLE IF EXISTS rogue_software_findings;
-- DROP TABLE IF EXISTS shadow_it_findings;
-- DROP TABLE IF EXISTS remediation_approvals;
-- DROP TABLE IF EXISTS remediation_runs;
-- DROP TABLE IF EXISTS remediation_playbooks;
-- DROP TABLE IF EXISTS remediation_actions;
