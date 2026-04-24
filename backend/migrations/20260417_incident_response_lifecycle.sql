-- Incident Response Lifecycle Module — C3

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,

    title VARCHAR(256) NOT NULL,
    description TEXT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'high',

    phase VARCHAR(32) NOT NULL DEFAULT 'detected',
    phase_entered_at TIMESTAMPTZ NULL,

    source VARCHAR(64) NOT NULL DEFAULT 'manual',
    source_ref_id INTEGER NULL,
    source_ref_type VARCHAR(64) NULL,

    assigned_to_user_id INTEGER NULL,
    assigned_to_name VARCHAR(256) NULL,
    assigned_at TIMESTAMPTZ NULL,

    ai_investigation_id INTEGER NULL,
    ai_executive_summary TEXT NULL,
    ai_mitre_tactic VARCHAR(64) NULL,
    ai_mitre_technique VARCHAR(64) NULL,

    contain_command_ids JSONB NULL,
    remediation_action_ids JSONB NULL,

    rescan_job_id VARCHAR(128) NULL,
    rescan_verified_clean BOOLEAN NULL,
    rescan_completed_at TIMESTAMPTZ NULL,

    report_id INTEGER NULL,

    estimated_risk_score_impact DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    affected_asset_count INTEGER NOT NULL DEFAULT 0,

    closed_at TIMESTAMPTZ NULL,
    closed_by VARCHAR(128) NULL,
    closure_notes TEXT NULL,
    root_cause TEXT NULL,

    created_by VARCHAR(128) NOT NULL DEFAULT 'system',

    mitre_tags_json JSONB NULL,
    tags_json JSONB NULL,
    extra_json JSONB NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_incidents_tenant_phase
    ON incidents (tenant_id, phase);

CREATE INDEX IF NOT EXISTS ix_incidents_tenant_severity
    ON incidents (tenant_id, severity);

CREATE INDEX IF NOT EXISTS ix_incidents_tenant_assigned
    ON incidents (tenant_id, assigned_to_user_id);

CREATE INDEX IF NOT EXISTS ix_incidents_source
    ON incidents (tenant_id, source);

CREATE INDEX IF NOT EXISTS ix_incidents_created
    ON incidents (tenant_id, created_at);



CREATE TABLE IF NOT EXISTS incident_timeline (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,

    event_type VARCHAR(64) NOT NULL,
    from_phase VARCHAR(32) NULL,
    to_phase VARCHAR(32) NULL,
    summary TEXT NOT NULL,

    actor VARCHAR(128) NOT NULL DEFAULT 'system',
    actor_user_id INTEGER NULL,

    ref_type VARCHAR(64) NULL,
    ref_id VARCHAR(128) NULL,

    detail_json JSONB NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_incident_timeline_incident
    ON incident_timeline (incident_id);

CREATE INDEX IF NOT EXISTS ix_incident_timeline_tenant
    ON incident_timeline (tenant_id);

CREATE INDEX IF NOT EXISTS ix_incident_timeline_event_type
    ON incident_timeline (tenant_id, event_type);

CREATE INDEX IF NOT EXISTS ix_incident_timeline_created
    ON incident_timeline (incident_id, created_at);



CREATE TABLE IF NOT EXISTS incident_assets (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL,

    asset_role VARCHAR(64) NOT NULL DEFAULT 'affected',

    is_contained BOOLEAN NOT NULL DEFAULT FALSE,
    contained_at TIMESTAMPTZ NULL,
    contain_command_id VARCHAR(128) NULL,

    is_clean BOOLEAN NULL,
    verified_clean_at TIMESTAMPTZ NULL,

    notes TEXT NULL,

    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by VARCHAR(128) NOT NULL DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS ix_incident_assets_incident
    ON incident_assets (incident_id);

CREATE INDEX IF NOT EXISTS ix_incident_assets_asset
    ON incident_assets (asset_id);

CREATE INDEX IF NOT EXISTS ix_incident_assets_tenant
    ON incident_assets (tenant_id);



CREATE TABLE IF NOT EXISTS incident_reports (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,

    report_type VARCHAR(32) NOT NULL DEFAULT 'full',
    generated_by VARCHAR(128) NOT NULL DEFAULT 'system',

    pdf_path VARCHAR(512) NULL,

    report_json JSONB NULL,

    model_used VARCHAR(128) NULL,
    prompt_tokens INTEGER NULL,
    completion_tokens INTEGER NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_incident_reports_incident
    ON incident_reports (incident_id);

CREATE INDEX IF NOT EXISTS ix_incident_reports_tenant
    ON incident_reports (tenant_id);