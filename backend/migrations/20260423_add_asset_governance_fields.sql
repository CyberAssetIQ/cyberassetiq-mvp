ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS asset_state VARCHAR(32) DEFAULT 'observed_unknown';
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS management_state VARCHAR(32) DEFAULT 'unmanaged';
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS ownership_status VARCHAR(32) DEFAULT 'unknown';
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS compliance_scope VARCHAR(32) DEFAULT 'pending_review';
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS source_of_truth VARCHAR(32) DEFAULT 'network_scan';
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS confidence_score DOUBLE PRECISION DEFAULT 0.0;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS agent_installed BOOLEAN DEFAULT FALSE;
ALTER TABLE canonical_assets ADD COLUMN IF NOT EXISTS agent_last_seen_epoch INTEGER;

CREATE INDEX IF NOT EXISTS ix_canonical_assets_asset_state ON canonical_assets(asset_state);
CREATE INDEX IF NOT EXISTS ix_canonical_assets_management_state ON canonical_assets(management_state);
CREATE INDEX IF NOT EXISTS ix_canonical_assets_compliance_scope ON canonical_assets(compliance_scope);
CREATE INDEX IF NOT EXISTS ix_canonical_assets_agent_installed ON canonical_assets(agent_installed);
CREATE INDEX IF NOT EXISTS ix_canonical_assets_agent_last_seen_epoch ON canonical_assets(agent_last_seen_epoch);