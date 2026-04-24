CREATE TABLE IF NOT EXISTS broker_accounts (
    id SERIAL PRIMARY KEY,
    consumer_id INTEGER NOT NULL,
    broker_code VARCHAR(64) NOT NULL UNIQUE,
    regulator_ref VARCHAR(255) NOT NULL DEFAULT '',
    plan VARCHAR(64) NOT NULL DEFAULT 'broker-standard',
    status VARCHAR(64) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (consumer_id) REFERENCES posture_consumers(id)
);
CREATE INDEX IF NOT EXISTS ix_broker_accounts_consumer_id ON broker_accounts (consumer_id);

CREATE TABLE IF NOT EXISTS broker_users (
    id SERIAL PRIMARY KEY,
    broker_account_id INTEGER NOT NULL,
    email VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (broker_account_id) REFERENCES broker_accounts(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_broker_users_account_email ON broker_users (broker_account_id, email);

CREATE TABLE IF NOT EXISTS broker_client_links (
    id SERIAL PRIMARY KEY,
    broker_account_id INTEGER NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL,
    relationship_status VARCHAR(64) NOT NULL DEFAULT 'invited',
    consent_grant_id INTEGER NULL,
    renewal_date VARCHAR(64) NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (broker_account_id) REFERENCES broker_accounts(id),
    FOREIGN KEY (consent_grant_id) REFERENCES posture_access_grants(id)
);
CREATE INDEX IF NOT EXISTS ix_broker_client_links_tenant ON broker_client_links (tenant_id);

CREATE TABLE IF NOT EXISTS broker_quote_requests (
    id SERIAL PRIMARY KEY,
    broker_account_id INTEGER NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    request_type VARCHAR(64) NOT NULL DEFAULT 'new_quote',
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(64) NOT NULL DEFAULT 'requested',
    snapshot_version_id INTEGER NULL,
    response_json JSON NOT NULL DEFAULT '{}',
    FOREIGN KEY (broker_account_id) REFERENCES broker_accounts(id),
    FOREIGN KEY (snapshot_version_id) REFERENCES posture_record_versions(id)
);
CREATE INDEX IF NOT EXISTS ix_broker_quote_requests_tenant ON broker_quote_requests (tenant_id);
