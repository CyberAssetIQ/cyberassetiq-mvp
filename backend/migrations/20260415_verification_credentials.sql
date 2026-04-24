CREATE TABLE IF NOT EXISTS verification_credentials (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    posture_record_version_id INTEGER NOT NULL,
    credential_uuid VARCHAR(255) NOT NULL UNIQUE,
    credential_type VARCHAR(64) NOT NULL,
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'valid',
    assurance_level VARCHAR(128) NOT NULL DEFAULT 'continuous-monitoring',
    trust_mark VARCHAR(128) NOT NULL DEFAULT 'CyberAssetIQ Verified',
    claims_json JSON NOT NULL DEFAULT '{}',
    verification_token VARCHAR(255) NOT NULL UNIQUE,
    signed_hash VARCHAR(255) NOT NULL,
    public_summary_json JSON NOT NULL DEFAULT '{}',
    FOREIGN KEY (posture_record_version_id) REFERENCES posture_record_versions(id)
);
CREATE INDEX IF NOT EXISTS ix_verification_credentials_tenant ON verification_credentials (tenant_id);

CREATE TABLE IF NOT EXISTS verification_events (
    id SERIAL PRIMARY KEY,
    credential_id INTEGER NOT NULL,
    verified_by_consumer_id INTEGER NULL,
    verification_result VARCHAR(64) NOT NULL,
    verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata_json JSON NOT NULL DEFAULT '{}',
    FOREIGN KEY (credential_id) REFERENCES verification_credentials(id),
    FOREIGN KEY (verified_by_consumer_id) REFERENCES posture_consumers(id)
);
