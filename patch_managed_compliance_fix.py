from pathlib import Path
from datetime import datetime

BASE = Path("backend")
TARGETS = [
    BASE / "services" / "asset_classification_service.py",
    BASE / "services" / "asset_correlation_service.py",
]

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

for path in TARGETS:
    if not path.exists():
        print(f"SKIPPED missing: {path}")
        continue

    original = path.read_text(encoding="utf-8")
    backup = path.with_suffix(path.suffix + f".bak_managed_compliance_{stamp}")
    backup.write_text(original, encoding="utf-8")

    updated = original.replace('"managed_agent"', '"managed"')
    updated = updated.replace("'managed_agent'", "'managed'")

    if path.name == "asset_classification_service.py":
        marker = "# --- CyberAssetIQ managed compliance override ---"
        if marker not in updated:
            override = r'''

# --- CyberAssetIQ managed compliance override ---
# Compliance service requires:
# asset_state="managed", management_state="managed",
# agent_installed=True, compliance_scope="in_scope".
# This override prevents agent-managed assets being excluded from CE assessment.
def backfill_asset_states(db, tenant_id: str | None = None):
    from sqlalchemy import text

    where_tenant = "WHERE tenant_id = :tenant_id" if tenant_id else ""
    params = {"tenant_id": tenant_id} if tenant_id else {}

    # 1. Mark real agent assets as managed for compliance.
    managed_sql = f"""
        UPDATE canonical_assets
        SET asset_state = 'managed',
            management_state = 'managed',
            agent_installed = true,
            agent_last_seen_epoch = COALESCE(agent_last_seen_epoch, last_heartbeat_epoch, last_snapshot_epoch),
            compliance_scope = 'in_scope',
            source_of_truth = 'agent'
        {where_tenant}
        AND (
            agent_id LIKE 'agent-%'
            OR management_state = 'managed'
            OR last_heartbeat_epoch IS NOT NULL
            OR last_snapshot_epoch IS NOT NULL
            OR security_posture_json IS NOT NULL
        )
    """ if tenant_id else """
        UPDATE canonical_assets
        SET asset_state = 'managed',
            management_state = 'managed',
            agent_installed = true,
            agent_last_seen_epoch = COALESCE(agent_last_seen_epoch, last_heartbeat_epoch, last_snapshot_epoch),
            compliance_scope = 'in_scope',
            source_of_truth = 'agent'
        WHERE (
            agent_id LIKE 'agent-%'
            OR management_state = 'managed'
            OR last_heartbeat_epoch IS NOT NULL
            OR last_snapshot_epoch IS NOT NULL
            OR security_posture_json IS NOT NULL
        )
    """

    result = db.execute(text(managed_sql), params)

    # 2. Keep network-only known devices as unmanaged_known unless already excluded/rogue/guest.
    network_sql = f"""
        UPDATE canonical_assets
        SET asset_state = CASE
                WHEN compliance_scope = 'excluded' THEN asset_state
                ELSE 'unmanaged_known'
            END,
            management_state = 'unmanaged',
            agent_installed = false,
            source_of_truth = COALESCE(source_of_truth, 'network_scan')
        {where_tenant}
        AND agent_id LIKE 'network:%'
        AND COALESCE(agent_installed, false) = false
        AND COALESCE(management_state, '') != 'managed'
    """ if tenant_id else """
        UPDATE canonical_assets
        SET asset_state = CASE
                WHEN compliance_scope = 'excluded' THEN asset_state
                ELSE 'unmanaged_known'
            END,
            management_state = 'unmanaged',
            agent_installed = false,
            source_of_truth = COALESCE(source_of_truth, 'network_scan')
        WHERE agent_id LIKE 'network:%'
        AND COALESCE(agent_installed, false) = false
        AND COALESCE(management_state, '') != 'managed'
    """

    db.execute(text(network_sql), params)
    db.commit()

    return result.rowcount or 0
# --- end CyberAssetIQ managed compliance override ---
'''
            updated = updated.rstrip() + "\n" + override + "\n"

    path.write_text(updated, encoding="utf-8")
    print(f"PATCHED: {path}")
    print(f"BACKUP:  {backup}")

print("Done.")