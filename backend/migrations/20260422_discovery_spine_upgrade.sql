-- Discovery spine upgrade for canonical_assets.
-- Safe to run multiple times.

ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS asset_uid VARCHAR(255);
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS primary_ip VARCHAR(64);
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS display_name VARCHAR(255);
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS management_state VARCHAR(32) DEFAULT 'managed';
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS source_confidence INTEGER DEFAULT 100;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS last_seen_source VARCHAR(32);
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS source_types_json JSONB;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS network_asset_ids_json JSONB;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS last_network_scan_job_id INTEGER;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS last_network_seen_epoch INTEGER;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS last_heartbeat_epoch INTEGER;

CREATE INDEX IF NOT EXISTS ix_canonical_assets_tenant_asset_uid
    ON canonical_assets (tenant_id, asset_uid);
