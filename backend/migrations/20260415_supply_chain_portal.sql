CREATE TABLE IF NOT EXISTS buyer_accounts (
    id SERIAL PRIMARY KEY,
    consumer_id INTEGER NOT NULL,
    buyer_code VARCHAR(64) NOT NULL UNIQUE,
    industry VARCHAR(255) NOT NULL DEFAULT 'general',
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (consumer_id) REFERENCES posture_consumers(id)
);

CREATE TABLE IF NOT EXISTS supplier_relationships (
    id SERIAL PRIMARY KEY,
    buyer_account_id INTEGER NOT NULL,
    supplier_tenant_id VARCHAR(255) NOT NULL,
    supplier_name VARCHAR(255) NOT NULL,
    relationship_status VARCHAR(64) NOT NULL DEFAULT 'invited',
    tier VARCHAR(64) NOT NULL DEFAULT 'tier-1',
    criticality VARCHAR(64) NOT NULL DEFAULT 'medium',
    contract_ref VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (buyer_account_id) REFERENCES buyer_accounts(id)
);
CREATE INDEX IF NOT EXISTS ix_supplier_relationships_supplier_tenant ON supplier_relationships (supplier_tenant_id);

CREATE TABLE IF NOT EXISTS assurance_requests (
    id SERIAL PRIMARY KEY,
    buyer_account_id INTEGER NOT NULL,
    supplier_tenant_id VARCHAR(255) NOT NULL,
    request_type VARCHAR(64) NOT NULL DEFAULT 'initial',
    requested_controls_json JSON NOT NULL DEFAULT '{}',
    status VARCHAR(64) NOT NULL DEFAULT 'requested',
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    latest_version_id INTEGER NULL,
    FOREIGN KEY (buyer_account_id) REFERENCES buyer_accounts(id),
    FOREIGN KEY (latest_version_id) REFERENCES posture_record_versions(id)
);
CREATE INDEX IF NOT EXISTS ix_assurance_requests_supplier_tenant ON assurance_requests (supplier_tenant_id);

CREATE TABLE IF NOT EXISTS supplier_attestations (
    id SERIAL PRIMARY KEY,
    assurance_request_id INTEGER NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    attested_by VARCHAR(255) NOT NULL,
    attestation_text TEXT NOT NULL,
    answers_json JSON NOT NULL DEFAULT '{}',
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assurance_request_id) REFERENCES assurance_requests(id)
);

CREATE TABLE IF NOT EXISTS assurance_reviews (
    id SERIAL PRIMARY KEY,
    assurance_request_id INTEGER NOT NULL,
    buyer_account_id INTEGER NOT NULL,
    review_status VARCHAR(64) NOT NULL DEFAULT 'accepted',
    review_notes TEXT NOT NULL DEFAULT '',
    reviewed_by VARCHAR(255) NOT NULL,
    reviewed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assurance_request_id) REFERENCES assurance_requests(id),
    FOREIGN KEY (buyer_account_id) REFERENCES buyer_accounts(id)
);
