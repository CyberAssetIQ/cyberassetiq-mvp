CREATE TABLE IF NOT EXISTS posture_consumers (
    id SERIAL PRIMARY KEY,
    consumer_type VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    external_org_id VARCHAR(255) NOT NULL DEFAULT '',
    contact_email VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    metadata_json JSON NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_posture_consumers_type ON posture_consumers (consumer_type);

CREATE TABLE IF NOT EXISTS posture_access_grants (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    consumer_id INTEGER NOT NULL,
    grant_type VARCHAR(64) NOT NULL,
    scope_json JSON NOT NULL DEFAULT '{}',
    access_level VARCHAR(64) NOT NULL DEFAULT 'standard',
    status VARCHAR(64) NOT NULL DEFAULT 'pending',
    approved_by VARCHAR(255) NOT NULL DEFAULT '',
    approved_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    last_accessed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (consumer_id) REFERENCES posture_consumers(id)
);
CREATE INDEX IF NOT EXISTS ix_posture_access_grants_tenant ON posture_access_grants (tenant_id);
CREATE INDEX IF NOT EXISTS ix_posture_access_grants_consumer ON posture_access_grants (consumer_id);

CREATE TABLE IF NOT EXISTS posture_share_links (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    posture_record_version_id INTEGER NOT NULL,
    consumer_id INTEGER NULL,
    share_token VARCHAR(255) NOT NULL UNIQUE,
    share_type VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(255) NOT NULL DEFAULT 'system',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (posture_record_version_id) REFERENCES posture_record_versions(id),
    FOREIGN KEY (consumer_id) REFERENCES posture_consumers(id)
);
CREATE INDEX IF NOT EXISTS ix_posture_share_links_tenant ON posture_share_links (tenant_id);

CREATE TABLE IF NOT EXISTS posture_access_audit (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    consumer_id INTEGER NULL,
    grant_id INTEGER NULL,
    access_method VARCHAR(64) NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    resource_id VARCHAR(255) NOT NULL DEFAULT '',
    action VARCHAR(128) NOT NULL,
    ip_address VARCHAR(255) NOT NULL DEFAULT '',
    user_agent VARCHAR(500) NOT NULL DEFAULT '',
    accessed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (consumer_id) REFERENCES posture_consumers(id),
    FOREIGN KEY (grant_id) REFERENCES posture_access_grants(id)
);
CREATE INDEX IF NOT EXISTS ix_posture_access_audit_tenant ON posture_access_audit (tenant_id);
