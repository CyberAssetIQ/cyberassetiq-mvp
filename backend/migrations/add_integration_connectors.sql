-- Migration: add_integration_connectors
-- Adds the integration_connectors table for managing third-party
-- EDR/SIEM/IAM/SOAR/MSP/ITSM connector configurations per tenant.
-- Safe to run multiple times (idempotent).

BEGIN;

CREATE TABLE IF NOT EXISTS integration_connectors (
    id                  SERIAL PRIMARY KEY,
    tenant_id           VARCHAR(100) NOT NULL,
    name                VARCHAR(200) NOT NULL,
    connector_type      VARCHAR(50)  NOT NULL,
    -- sentinel|splunk|qradar|elastic|
    -- crowdstrike|defender|sentinelone|
    -- entraid|okta|insightidr|
    -- xsoar|tines|splunk_soar|
    -- connectwise|datto|nable|
    -- jira|servicenow|freshservice
    category            VARCHAR(30)  NOT NULL,
    -- siem|edr|iam|soar|msp|itsm
    enabled             BOOLEAN      NOT NULL DEFAULT FALSE,
    config              JSONB        NOT NULL DEFAULT '{}',
    -- Credentials stored as JSON. Consider encrypting at application level
    -- or using PG pgcrypto extension for sensitive values.

    last_tested_at      TIMESTAMP    NULL,
    last_test_result    VARCHAR(20)  NULL,    -- ok | error
    last_test_message   TEXT         NULL,

    last_sent_at        TIMESTAMP    NULL,
    total_events_sent   INTEGER      NOT NULL DEFAULT 0,

    created_at          TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ic_tenant_id
    ON integration_connectors(tenant_id);

CREATE INDEX IF NOT EXISTS idx_ic_tenant_enabled
    ON integration_connectors(tenant_id, enabled);

CREATE INDEX IF NOT EXISTS idx_ic_connector_type
    ON integration_connectors(connector_type);

CREATE INDEX IF NOT EXISTS idx_ic_category
    ON integration_connectors(category);

-- updated_at auto-update trigger
CREATE OR REPLACE FUNCTION update_integration_connectors_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ic_updated_at ON integration_connectors;
CREATE TRIGGER trg_ic_updated_at
    BEFORE UPDATE ON integration_connectors
    FOR EACH ROW
    EXECUTE FUNCTION update_integration_connectors_updated_at();

COMMIT;

-- Rollback (keep as comment for reference):
-- DROP TABLE IF EXISTS integration_connectors;
-- DROP FUNCTION IF EXISTS update_integration_connectors_updated_at();
