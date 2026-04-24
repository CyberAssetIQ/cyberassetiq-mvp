from __future__ import annotations

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.telemetry import CanonicalSoftware


def upsert_canonical_asset_from_snapshot(db: Session, payload: dict) -> CanonicalAsset:
    tenant_id = payload["tenant_id"]
    agent_id = payload["agent_id"]
    asset = payload.get("asset", {})

    record = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.agent_id == agent_id)
        .first()
    )

    if not record:
        record = CanonicalAsset(tenant_id=tenant_id, agent_id=agent_id)
        db.add(record)

    record.hostname = asset.get("hostname")
    record.fqdn = asset.get("fqdn")
    record.os_family = asset.get("os_family")
    record.os_version = asset.get("os_version")
    record.domain = asset.get("domain")
    record.serial_number = asset.get("serial_number")
    record.device_id = asset.get("device_id")
    record.ips = asset.get("ips", [])
    record.macs = asset.get("macs", [])
    record.last_snapshot_epoch = payload.get("timestamp")
    record.raw_metadata_json = payload

    db.commit()
    db.refresh(record)
    return record


def merge_security_posture_into_asset(db: Session, tenant_id: str, agent_id: str, security_posture: dict, timestamp: int | None = None) -> None:
    asset = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.agent_id == agent_id)
        .first()
    )
    if not asset:
        asset = CanonicalAsset(tenant_id=tenant_id, agent_id=agent_id, last_snapshot_epoch=timestamp)
        db.add(asset)

    asset.security_posture_json = security_posture
    if timestamp is not None:
        asset.last_snapshot_epoch = timestamp

    db.commit()


def replace_software_inventory(db: Session, tenant_id: str, agent_id: str, software_items: list[dict]) -> None:
    asset = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.agent_id == agent_id)
        .first()
    )

    db.query(CanonicalSoftware).filter(
        CanonicalSoftware.tenant_id == tenant_id,
        CanonicalSoftware.agent_id == agent_id,
    ).delete(synchronize_session=False)

    for item in software_items:
        if not item.get("name"):
            continue
        db.add(
            CanonicalSoftware(
                tenant_id=tenant_id,
                agent_id=agent_id,
                asset_id=asset.id if asset else None,
                name=item.get("name"),
                version=item.get("version"),
                publisher=item.get("publisher"),
                install_date=item.get("install_date"),
            )
        )

    db.commit()
