from __future__ import annotations

import time
from typing import Optional

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset

AGENT_FRESHNESS_SECONDS = 60 * 60 * 24 * 7  # 7 days


def _safe_lower(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def classify_canonical_asset(asset: CanonicalAsset) -> CanonicalAsset:
    """
    Enforce CyberAssetIQ core rule:
    Observed != Managed
    Managed requires live agent evidence.
    """
    now_epoch = int(time.time())

    last_seen = getattr(asset, "agent_last_seen_epoch", None)
    has_fresh_agent = bool(
        getattr(asset, "agent_installed", False)
        and last_seen
        and (now_epoch - int(last_seen) <= AGENT_FRESHNESS_SECONDS)
    )

    hostname = _safe_lower(getattr(asset, "hostname", None))
    owner_hint = _safe_lower(getattr(asset, "owner", None))
    domain_hint = _safe_lower(getattr(asset, "domain", None))

    if has_fresh_agent:
        asset.asset_state = "managed"
        asset.management_state = "managed"
        asset.source_of_truth = "agent"
        if asset.compliance_scope in (None, "", "pending_review"):
            asset.compliance_scope = "in_scope"
        if asset.ownership_status in (None, "", "unknown"):
            asset.ownership_status = "corporate"
        asset.confidence_score = max(float(getattr(asset, "confidence_score", 0.0) or 0.0), 0.95)
        return asset

    # no fresh agent => never managed
    asset.management_state = "unmanaged"

    # basic ownership heuristics
    corporate_indicators = any([
        hostname.startswith("corp-"),
        hostname.startswith("win-"),
        hostname.startswith("srv-"),
        bool(domain_hint),
        "it" in owner_hint,
        "finance" in owner_hint,
        "hr" in owner_hint,
    ])

    guest_indicators = any([
        "guest" in hostname,
        "iphone" in hostname,
        "android" in hostname,
        "ipad" in hostname,
    ])

    if guest_indicators:
        asset.asset_state = "guest"
        asset.ownership_status = "guest"
        asset.compliance_scope = "excluded"
        asset.confidence_score = max(float(getattr(asset, "confidence_score", 0.0) or 0.0), 0.30)
    elif corporate_indicators:
        asset.asset_state = "unmanaged_known"
        asset.ownership_status = "corporate"
        if asset.compliance_scope in (None, "", "pending_review"):
            asset.compliance_scope = "in_scope"
        asset.confidence_score = max(float(getattr(asset, "confidence_score", 0.0) or 0.0), 0.70)
    else:
        asset.asset_state = "observed_unknown"
        asset.ownership_status = "unknown"
        if asset.compliance_scope in (None, "", "pending_review"):
            asset.compliance_scope = "excluded"
        asset.confidence_score = max(float(getattr(asset, "confidence_score", 0.0) or 0.0), 0.40)

    if not getattr(asset, "source_of_truth", None):
        asset.source_of_truth = "merged"

    return asset


def classify_network_asset(net_asset: NetworkDiscoveredAsset) -> dict:
    """
    Network discovery alone never equals managed.
    """
    hostname = _safe_lower(getattr(net_asset, "hostname", None))
    nb = _safe_lower(getattr(net_asset, "netbios_name", None))
    mdns = _safe_lower(getattr(net_asset, "mdns_name", None))
    name = hostname or nb or mdns

    guest_indicators = any([
        "guest" in name,
        "iphone" in name,
        "android" in name,
        "ipad" in name,
    ])

    if guest_indicators:
        return {
            "asset_state": "guest",
            "management_state": "unmanaged",
            "ownership_status": "guest",
            "compliance_scope": "excluded",
            "source_of_truth": "network_scan",
            "confidence_score": 0.30,
        }

    return {
        "asset_state": "observed_unknown",
        "management_state": "unmanaged",
        "ownership_status": "unknown",
        "compliance_scope": "excluded",
        "source_of_truth": "network_scan",
        "confidence_score": 0.40,
    }


def backfill_asset_states(db: Session) -> dict:
    updated = 0

    for asset in db.query(CanonicalAsset).all():
        classify_canonical_asset(asset)
        updated += 1

    db.commit()
    return {"updated_assets": updated}


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

    return {"updated_assets": result.rowcount or 0}
# --- end CyberAssetIQ managed compliance override ---

