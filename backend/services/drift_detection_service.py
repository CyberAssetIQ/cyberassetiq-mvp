"""drift_detection_service.py

Compares the latest asset snapshot against the previous one and emits
AssetDriftEvent rows for every meaningful change detected.

Only reads from existing tables (asset_snapshot_events, canonical_assets,
canonical_software, security_posture_events). Writes only to the new
drift tables so existing functionality is completely unaffected.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.drift import (
    ApprovedChange,
    AssetDriftEvent,
    AssetStateSnapshot,
    DriftBaseline,
)
from models.telemetry import (
    AssetSnapshotEvent,
    CanonicalSoftware,
    SecurityPostureEvent,
)

logger = logging.getLogger("cyberassetiq.drift")

# ---------------------------------------------------------------------------
# Severity rules — what kind of change maps to what severity
# ---------------------------------------------------------------------------
_SEVERITY_MAP: dict[str, str] = {
    "new_local_admin": "high",
    "removed_local_admin": "medium",
    "new_exposed_port": "high",
    "removed_exposed_port": "low",
    "removed_backup_agent": "high",
    "new_unapproved_software": "medium",
    "removed_software": "low",
    "asset_disappeared": "high",
    "firewall_disabled": "high",
    "av_disabled": "high",
    "patch_regression": "medium",
    "exposure_status_change": "high",
    "os_version_change": "medium",
    "new_open_share": "medium",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_drift_summary(db: Session, tenant_id: str) -> dict:
    """Return high-level drift counts for the dashboard."""
    from sqlalchemy import func as sqlfunc

    counts = (
        db.query(AssetDriftEvent.severity, sqlfunc.count(AssetDriftEvent.id))
        .filter(
            AssetDriftEvent.tenant_id == tenant_id,
            AssetDriftEvent.status == "open",
        )
        .group_by(AssetDriftEvent.severity)
        .all()
    )
    severity_counts = {s: c for s, c in counts}

    total = sum(severity_counts.values())
    today_count = (
        db.query(AssetDriftEvent)
        .filter(
            AssetDriftEvent.tenant_id == tenant_id,
            AssetDriftEvent.status == "open",
            AssetDriftEvent.detected_at >= _today_start(),
        )
        .count()
    )

    return {
        "total_open": total,
        "today": today_count,
        "by_severity": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
    }


def get_drift_events(
    db: Session,
    tenant_id: str,
    asset_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Return drift events with optional filters."""
    q = db.query(AssetDriftEvent).filter(AssetDriftEvent.tenant_id == tenant_id)
    if asset_id:
        q = q.filter(AssetDriftEvent.asset_id == asset_id)
    if severity:
        q = q.filter(AssetDriftEvent.severity == severity)
    if status:
        q = q.filter(AssetDriftEvent.status == status)

    events = q.order_by(AssetDriftEvent.detected_at.desc()).offset(offset).limit(limit).all()
    return [_event_to_dict(e, db) for e in events]


def get_asset_drift(db: Session, tenant_id: str, asset_id: int) -> dict:
    """Return drift events + current baseline for a single asset."""
    baseline = (
        db.query(DriftBaseline)
        .filter(DriftBaseline.tenant_id == tenant_id, DriftBaseline.asset_id == asset_id)
        .order_by(DriftBaseline.baseline_version.desc())
        .first()
    )
    events = get_drift_events(db, tenant_id, asset_id=asset_id, limit=50)
    return {
        "asset_id": asset_id,
        "baseline_version": baseline.baseline_version if baseline else None,
        "baseline_at": baseline.created_at.isoformat() if baseline else None,
        "open_events": [e for e in events if e["status"] == "open"],
        "recent_events": events,
    }


def rebuild_baseline(db: Session, tenant_id: str, asset_id: int) -> dict:
    """Snapshot current state and store as the new baseline for an asset.

    Should be called after changes are reviewed and accepted.
    """
    state = _build_current_state(db, tenant_id, asset_id)
    if not state:
        return {"error": "no_data", "asset_id": asset_id}

    existing = (
        db.query(DriftBaseline)
        .filter(DriftBaseline.tenant_id == tenant_id, DriftBaseline.asset_id == asset_id)
        .order_by(DriftBaseline.baseline_version.desc())
        .first()
    )
    next_version = (existing.baseline_version + 1) if existing else 1

    baseline = DriftBaseline(
        tenant_id=tenant_id,
        asset_id=asset_id,
        baseline_json=state,
        baseline_version=next_version,
    )
    db.add(baseline)

    # Close all open events for this asset — they are now accepted
    (
        db.query(AssetDriftEvent)
        .filter(
            AssetDriftEvent.tenant_id == tenant_id,
            AssetDriftEvent.asset_id == asset_id,
            AssetDriftEvent.status == "open",
        )
        .update({"status": "approved"}, synchronize_session=False)
    )
    db.commit()

    return {"asset_id": asset_id, "baseline_version": next_version}


def approve_change(
    db: Session,
    tenant_id: str,
    asset_id: int | None,
    change_type: str,
    requested_by: str,
    approved_by: str,
    valid_from: datetime,
    valid_to: datetime,
    notes: str | None = None,
) -> dict:
    """Create an approved-change window to suppress expected drift events."""
    ac = ApprovedChange(
        tenant_id=tenant_id,
        asset_id=asset_id,
        change_type=change_type,
        requested_by=requested_by,
        approved_by=approved_by,
        valid_from=valid_from,
        valid_to=valid_to,
        notes=notes,
    )
    db.add(ac)
    db.commit()
    db.refresh(ac)
    return {"id": ac.id, "change_type": change_type, "valid_from": valid_from.isoformat(), "valid_to": valid_to.isoformat()}


def run_drift_detection_for_asset(db: Session, tenant_id: str, asset_id: int) -> int:
    """Compare latest snapshot to previous, emit drift events. Returns events created."""
    snapshots = (
        db.query(AssetStateSnapshot)
        .filter(
            AssetStateSnapshot.tenant_id == tenant_id,
            AssetStateSnapshot.asset_id == asset_id,
        )
        .order_by(AssetStateSnapshot.collected_at.desc())
        .limit(2)
        .all()
    )

    if len(snapshots) < 2:
        return 0  # Not enough history to compare

    current = snapshots[0]
    previous = snapshots[1]

    if current.snapshot_hash == previous.snapshot_hash:
        return 0  # Identical — no drift

    changes = _diff_states(previous.state_json, current.state_json)
    now = datetime.now(timezone.utc)
    created = 0

    for change in changes:
        drift_type = change["drift_type"]
        severity = _SEVERITY_MAP.get(drift_type, "medium")

        # Check for an active approved change window
        approved = (
            db.query(ApprovedChange)
            .filter(
                ApprovedChange.tenant_id == tenant_id,
                ApprovedChange.change_type == drift_type,
                ApprovedChange.valid_from <= now,
                ApprovedChange.valid_to >= now,
            )
            .filter(
                (ApprovedChange.asset_id == asset_id) | (ApprovedChange.asset_id.is_(None))
            )
            .first()
        )

        event = AssetDriftEvent(
            tenant_id=tenant_id,
            asset_id=asset_id,
            drift_type=drift_type,
            severity=severity,
            old_value=str(change.get("old", "")) if change.get("old") is not None else None,
            new_value=str(change.get("new", "")) if change.get("new") is not None else None,
            status="approved" if approved else "open",
            approved_change_id=approved.id if approved else None,
        )
        db.add(event)
        created += 1

    if created:
        db.commit()

    return created


def run_drift_detection_for_tenant(db: Session, tenant_id: str) -> dict:
    """Run drift detection across all assets for a tenant. Called by scheduler."""
    assets = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id)
        .all()
    )
    total_events = 0
    for asset in assets:
        try:
            _ingest_snapshot_for_asset(db, tenant_id, asset)
            events = run_drift_detection_for_asset(db, tenant_id, asset.id)
            total_events += events
        except Exception as exc:
            logger.warning("Drift detection failed for asset %d: %s", asset.id, exc)

    return {"assets_checked": len(assets), "events_created": total_events}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ingest_snapshot_for_asset(db: Session, tenant_id: str, asset: CanonicalAsset) -> None:
    """Build and persist a fresh AssetStateSnapshot from latest telemetry."""
    state = _build_current_state(db, tenant_id, asset.id)
    if not state:
        return

    state_str = json.dumps(state, sort_keys=True)
    snap_hash = hashlib.sha256(state_str.encode()).hexdigest()

    # Only write if different from latest stored hash
    latest = (
        db.query(AssetStateSnapshot)
        .filter(
            AssetStateSnapshot.tenant_id == tenant_id,
            AssetStateSnapshot.asset_id == asset.id,
        )
        .order_by(AssetStateSnapshot.collected_at.desc())
        .first()
    )
    if latest and latest.snapshot_hash == snap_hash:
        return  # Unchanged

    snap = AssetStateSnapshot(
        tenant_id=tenant_id,
        asset_id=asset.id,
        snapshot_type="full",
        snapshot_hash=snap_hash,
        state_json=state,
    )
    db.add(snap)
    db.commit()


def _build_current_state(db: Session, tenant_id: str, asset_id: int) -> dict | None:
    """Assemble a normalised state dict from the latest telemetry rows."""
    asset = db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == tenant_id,
        CanonicalAsset.id == asset_id,
    ).first()
    if not asset:
        return None

    # Software inventory
    software = db.query(CanonicalSoftware).filter(
        CanonicalSoftware.tenant_id == tenant_id,
        CanonicalSoftware.asset_id == asset_id,
    ).all()
    software_names = sorted({s.name.lower() for s in software})

    # Security posture (latest event)
    posture_event = (
        db.query(SecurityPostureEvent)
        .filter(
            SecurityPostureEvent.tenant_id == tenant_id,
            SecurityPostureEvent.agent_id == asset.agent_id,
        )
        .order_by(SecurityPostureEvent.created_at.desc())
        .first()
    )
    posture = posture_event.payload_json if posture_event else {}

    # Raw asset metadata
    meta = asset.raw_metadata_json or {}
    security = asset.security_posture_json or {}

    local_admins = sorted(security.get("local_admins", []))
    open_ports = sorted(meta.get("open_ports", posture.get("open_ports", [])))
    firewall_enabled = security.get("firewall_enabled", posture.get("firewall_enabled"))
    av_enabled = security.get("av_enabled", posture.get("av_enabled"))

    # Detect backup agents from software names
    backup_keywords = {"veeam", "acronis", "backupexec", "carbonite", "backblaze", "dpm", "commvault", "shadow"}
    has_backup = any(any(kw in s for kw in backup_keywords) for s in software_names)

    return {
        "hostname": asset.hostname,
        "os_version": asset.os_version,
        "local_admins": local_admins,
        "open_ports": open_ports,
        "software": software_names,
        "firewall_enabled": firewall_enabled,
        "av_enabled": av_enabled,
        "has_backup_agent": has_backup,
        "ips": sorted(asset.ips or []),
    }


def _diff_states(old: dict, new: dict) -> list[dict[str, Any]]:
    """Return list of detected changes between two state dicts."""
    changes: list[dict] = []

    # Local admins
    old_admins = set(old.get("local_admins", []))
    new_admins = set(new.get("local_admins", []))
    for a in new_admins - old_admins:
        changes.append({"drift_type": "new_local_admin", "new": a})
    for a in old_admins - new_admins:
        changes.append({"drift_type": "removed_local_admin", "old": a})

    # Open ports
    old_ports = set(old.get("open_ports", []))
    new_ports = set(new.get("open_ports", []))
    for p in new_ports - old_ports:
        changes.append({"drift_type": "new_exposed_port", "new": p})
    for p in old_ports - new_ports:
        changes.append({"drift_type": "removed_exposed_port", "old": p})

    # Backup agent
    if old.get("has_backup_agent") and not new.get("has_backup_agent"):
        changes.append({"drift_type": "removed_backup_agent", "old": "present", "new": "absent"})

    # Firewall
    if old.get("firewall_enabled") is True and new.get("firewall_enabled") is False:
        changes.append({"drift_type": "firewall_disabled", "old": True, "new": False})

    # AV
    if old.get("av_enabled") is True and new.get("av_enabled") is False:
        changes.append({"drift_type": "av_disabled", "old": True, "new": False})

    # Software
    old_sw = set(old.get("software", []))
    new_sw = set(new.get("software", []))
    for sw in new_sw - old_sw:
        changes.append({"drift_type": "new_unapproved_software", "new": sw})
    for sw in old_sw - new_sw:
        changes.append({"drift_type": "removed_software", "old": sw})

    # OS version
    if old.get("os_version") and new.get("os_version") and old["os_version"] != new["os_version"]:
        changes.append({"drift_type": "os_version_change", "old": old["os_version"], "new": new["os_version"]})

    return changes


def _event_to_dict(e: AssetDriftEvent, db: Session) -> dict:
    asset = db.query(CanonicalAsset).filter(CanonicalAsset.id == e.asset_id).first()
    return {
        "id": e.id,
        "asset_id": e.asset_id,
        "asset_hostname": asset.hostname if asset else None,
        "drift_type": e.drift_type,
        "severity": e.severity,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "status": e.status,
        "detected_at": e.detected_at.isoformat() if e.detected_at else None,
    }


def _today_start() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)
