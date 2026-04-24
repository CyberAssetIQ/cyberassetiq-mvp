-- 20260415_posture_record_core.sql
-- Canonical reusable cyber posture record for CyberAssetIQ.

CREATE TABLE IF NOT EXISTS posture_records (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL UNIQUE,
    record_uuid VARCHAR(255) NOT NULL UNIQUE,
    current_version_id INTEGER NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_posture_records_tenant_id ON posture_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_posture_records_record_uuid ON posture_records (record_uuid);

CREATE TABLE IF NOT EXISTS posture_record_versions (
    id SERIAL PRIMARY KEY,
    posture_record_id INTEGER NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    version_no INTEGER NOT NULL,
    schema_version VARCHAR(64) NOT NULL,
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    generated_by VARCHAR(255) NOT NULL,
    overall_score INTEGER NOT NULL DEFAULT 0,
    risk_band VARCHAR(64) NOT NULL DEFAULT 'Unknown',
    insurance_readiness_score INTEGER NOT NULL DEFAULT 0,
    supply_chain_score INTEGER NOT NULL DEFAULT 0,
    compliance_score INTEGER NOT NULL DEFAULT 0,
    identity_score INTEGER NOT NULL DEFAULT 0,
    exposure_score INTEGER NOT NULL DEFAULT 0,
    resilience_score INTEGER NOT NULL DEFAULT 0,
    patch_score INTEGER NOT NULL DEFAULT 0,
    drift_score INTEGER NOT NULL DEFAULT 0,
    asset_count INTEGER NOT NULL DEFAULT 0,
    critical_findings_count INTEGER NOT NULL DEFAULT 0,
    open_cves_count INTEGER NOT NULL DEFAULT 0,
    darkweb_findings_count INTEGER NOT NULL DEFAULT 0,
    attack_path_count INTEGER NOT NULL DEFAULT 0,
    crown_jewel_assets_count INTEGER NOT NULL DEFAULT 0,
    credential_exposure_count INTEGER NOT NULL DEFAULT 0,
    summary_json JSON NOT NULL DEFAULT '{}',
    score_breakdown_json JSON NOT NULL DEFAULT '{}',
    top_risks_json JSON NOT NULL DEFAULT '[]',
    evidence_summary_json JSON NOT NULL DEFAULT '{}',
    controls_json JSON NOT NULL DEFAULT '{}',
    metadata_json JSON NOT NULL DEFAULT '{}',
    signed_hash VARCHAR(255) NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (posture_record_id) REFERENCES posture_records(id)
);
CREATE INDEX IF NOT EXISTS ix_posture_record_versions_tenant_id ON posture_record_versions (tenant_id);
CREATE INDEX IF NOT EXISTS ix_posture_record_versions_current ON posture_record_versions (is_current);

CREATE TABLE IF NOT EXISTS posture_domains (
    id SERIAL PRIMARY KEY,
    posture_record_version_id INTEGER NOT NULL,
    domain_name VARCHAR(255) NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    risk_band VARCHAR(64) NOT NULL DEFAULT 'Unknown',
    summary TEXT NOT NULL DEFAULT '',
    evidence_count INTEGER NOT NULL DEFAULT 0,
    details_json JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (posture_record_version_id) REFERENCES posture_record_versions(id)
);
CREATE INDEX IF NOT EXISTS ix_posture_domains_version ON posture_domains (posture_record_version_id);
CREATE INDEX IF NOT EXISTS ix_posture_domains_name ON posture_domains (domain_name);

CREATE TABLE IF NOT EXISTS posture_evidence_items (
    id SERIAL PRIMARY KEY,
    posture_record_version_id INTEGER NOT NULL,
    evidence_type VARCHAR(128) NOT NULL,
    source_module VARCHAR(128) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity VARCHAR(64) NOT NULL DEFAULT 'info',
    asset_ref VARCHAR(255) NOT NULL DEFAULT '',
    control_ref VARCHAR(255) NOT NULL DEFAULT '',
    external_ref VARCHAR(255) NOT NULL DEFAULT '',
    raw_json JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (posture_record_version_id) REFERENCES posture_record_versions(id)
);
CREATE INDEX IF NOT EXISTS ix_posture_evidence_items_version ON posture_evidence_items (posture_record_version_id);
CREATE INDEX IF NOT EXISTS ix_posture_evidence_items_severity ON posture_evidence_items (severity);
