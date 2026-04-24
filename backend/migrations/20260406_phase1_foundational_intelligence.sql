-- =============================================================================
-- CyberAssetIQ Phase 1 Migration — Foundational Intelligence
-- Created: 2026-04-06
-- Safe to re-run: all statements use CREATE TABLE IF NOT EXISTS
-- Rollback: DROP TABLE statements at the bottom (commented out)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- A. Drift Detection
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS asset_state_snapshots (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    asset_id            INTEGER NOT NULL,
    snapshot_type       TEXT NOT NULL DEFAULT 'full',
    snapshot_hash       TEXT NOT NULL,
    state_json          TEXT NOT NULL DEFAULT '{}',
    collected_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_asset_state_snapshots_tenant_asset
    ON asset_state_snapshots(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_asset_state_snapshots_tenant_collected
    ON asset_state_snapshots(tenant_id, collected_at);
CREATE INDEX IF NOT EXISTS ix_asset_state_snapshots_hash
    ON asset_state_snapshots(snapshot_hash);

CREATE TABLE IF NOT EXISTS asset_drift_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    asset_id            INTEGER NOT NULL,
    drift_type          TEXT NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'medium',
    old_value           TEXT,
    new_value           TEXT,
    status              TEXT NOT NULL DEFAULT 'open',
    approved_change_id  INTEGER,
    detected_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_asset_drift_events_tenant_asset
    ON asset_drift_events(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_asset_drift_events_tenant_status
    ON asset_drift_events(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_asset_drift_events_tenant_severity
    ON asset_drift_events(tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_asset_drift_events_detected_at
    ON asset_drift_events(tenant_id, detected_at);

CREATE TABLE IF NOT EXISTS approved_changes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    asset_id            INTEGER,
    change_type         TEXT NOT NULL,
    requested_by        TEXT,
    approved_by         TEXT,
    valid_from          TIMESTAMP NOT NULL,
    valid_to            TIMESTAMP NOT NULL,
    notes               TEXT,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_approved_changes_tenant_asset
    ON approved_changes(tenant_id, asset_id);

CREATE TABLE IF NOT EXISTS drift_baselines (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    asset_id            INTEGER NOT NULL,
    baseline_json       TEXT NOT NULL DEFAULT '{}',
    baseline_version    INTEGER NOT NULL DEFAULT 1,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_drift_baselines_tenant_asset
    ON drift_baselines(tenant_id, asset_id);

-- -----------------------------------------------------------------------------
-- B. Asset Criticality
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS asset_criticality_profiles (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id               TEXT NOT NULL,
    asset_id                INTEGER NOT NULL,
    asset_role              TEXT,
    criticality_score       INTEGER NOT NULL DEFAULT 0,
    confidentiality_score   INTEGER NOT NULL DEFAULT 0,
    integrity_score         INTEGER NOT NULL DEFAULT 0,
    availability_score      INTEGER NOT NULL DEFAULT 0,
    confidence              REAL NOT NULL DEFAULT 0.5,
    reasoning_json          TEXT DEFAULT '{}',
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_asset_criticality_profiles_tenant_asset
    ON asset_criticality_profiles(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_asset_criticality_profiles_tenant_score
    ON asset_criticality_profiles(tenant_id, criticality_score);

CREATE TABLE IF NOT EXISTS business_services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    service_name    TEXT NOT NULL,
    owner_name      TEXT,
    business_unit   TEXT,
    impact_level    TEXT NOT NULL DEFAULT 'medium',
    description     TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_business_services_tenant
    ON business_services(tenant_id);

CREATE TABLE IF NOT EXISTS asset_service_map (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    asset_id        INTEGER NOT NULL,
    service_id      INTEGER NOT NULL,
    dependency_type TEXT NOT NULL DEFAULT 'hosts',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_asset_service_map_tenant_asset
    ON asset_service_map(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_asset_service_map_tenant_service
    ON asset_service_map(tenant_id, service_id);

CREATE TABLE IF NOT EXISTS crown_jewel_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id       TEXT NOT NULL,
    asset_id        INTEGER NOT NULL,
    reason          TEXT,
    designated_by   TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_crown_jewel_assets_tenant_asset
    ON crown_jewel_assets(tenant_id, asset_id);

-- -----------------------------------------------------------------------------
-- C. Risk Engine 2.0
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS risk_factor_scores (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    asset_id            INTEGER,
    factor_name         TEXT NOT NULL,
    factor_weight       REAL NOT NULL DEFAULT 1.0,
    raw_score           REAL NOT NULL DEFAULT 0.0,
    normalized_score    REAL NOT NULL DEFAULT 0.0,
    explanation         TEXT,
    computed_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_risk_factor_scores_tenant_asset
    ON risk_factor_scores(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_risk_factor_scores_tenant_factor
    ON risk_factor_scores(tenant_id, factor_name);
CREATE INDEX IF NOT EXISTS ix_risk_factor_scores_computed_at
    ON risk_factor_scores(tenant_id, computed_at);

CREATE TABLE IF NOT EXISTS risk_snapshots_v2 (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id                   TEXT NOT NULL,
    entity_type                 TEXT NOT NULL DEFAULT 'tenant',
    entity_id                   INTEGER,
    total_score                 INTEGER NOT NULL DEFAULT 0,
    severity_band               TEXT NOT NULL DEFAULT 'low',
    contributing_factors_json   TEXT DEFAULT '{}',
    computed_at                 TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_risk_snapshots_v2_tenant_entity
    ON risk_snapshots_v2(tenant_id, entity_type, entity_id);
CREATE INDEX IF NOT EXISTS ix_risk_snapshots_v2_computed_at
    ON risk_snapshots_v2(tenant_id, computed_at);

CREATE TABLE IF NOT EXISTS risk_recommendations (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id               TEXT NOT NULL,
    asset_id                INTEGER,
    recommendation_type     TEXT NOT NULL,
    title                   TEXT NOT NULL,
    expected_score_gain     INTEGER NOT NULL DEFAULT 0,
    priority_rank           INTEGER NOT NULL DEFAULT 99,
    status                  TEXT NOT NULL DEFAULT 'open',
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_risk_recommendations_tenant_asset
    ON risk_recommendations(tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_risk_recommendations_tenant_status
    ON risk_recommendations(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_risk_recommendations_tenant_priority
    ON risk_recommendations(tenant_id, priority_rank);

CREATE TABLE IF NOT EXISTS risk_score_explanations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id           TEXT NOT NULL,
    snapshot_id         INTEGER NOT NULL,
    explanation_text    TEXT,
    breakdown_json      TEXT DEFAULT '{}',
    generated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_risk_score_explanations_snapshot
    ON risk_score_explanations(snapshot_id);

-- =============================================================================
-- ROLLBACK SCRIPT (run these to undo Phase 1 completely)
-- =============================================================================
-- DROP TABLE IF EXISTS risk_score_explanations;
-- DROP TABLE IF EXISTS risk_recommendations;
-- DROP TABLE IF EXISTS risk_snapshots_v2;
-- DROP TABLE IF EXISTS risk_factor_scores;
-- DROP TABLE IF EXISTS crown_jewel_assets;
-- DROP TABLE IF EXISTS asset_service_map;
-- DROP TABLE IF EXISTS business_services;
-- DROP TABLE IF EXISTS asset_criticality_profiles;
-- DROP TABLE IF EXISTS drift_baselines;
-- DROP TABLE IF EXISTS approved_changes;
-- DROP TABLE IF EXISTS asset_drift_events;
-- DROP TABLE IF EXISTS asset_state_snapshots;
