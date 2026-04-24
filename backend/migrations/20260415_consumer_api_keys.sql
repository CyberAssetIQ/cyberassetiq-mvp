-- 20260415_consumer_api_keys.sql
-- External consumer API keys for broker and buyer authenticated access.
-- These are separate from tenant API keys — issued to external organisations.

CREATE TABLE IF NOT EXISTS consumer_api_keys (
    id               SERIAL PRIMARY KEY,
    consumer_id      INTEGER NOT NULL,
    key_hash         VARCHAR(128) NOT NULL UNIQUE,
    label            VARCHAR(255) NOT NULL DEFAULT '',
    permitted_tenants JSON NOT NULL DEFAULT '[]',
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    issued_at        TIMESTAMP NULL,
    expires_at       TIMESTAMP NULL,
    last_used_at     TIMESTAMP NULL,
    use_count        INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (consumer_id) REFERENCES posture_consumers(id)
);
CREATE INDEX IF NOT EXISTS ix_consumer_api_keys_consumer ON consumer_api_keys (consumer_id);
CREATE INDEX IF NOT EXISTS ix_consumer_api_keys_active ON consumer_api_keys (is_active);
