from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset
from models.telemetry import CanonicalSoftware
from services.asset_correlation_service import invalidate_unified_cache


SOURCE_CONFIDENCE = {
    "agent": 100,
    "asset_snapshot": 100,
    "security_posture": 98,
    "heartbeat": 96,
    "network_scan": 60,
    "manual": 40,
}


BAD_STRINGS = {None, "", "unknown", "Unknown", "Unknown Device"}


def _norm(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _norm_lower(value: str | None) -> str | None:
    v = _norm(value)
    return v.lower() if v else None


def _norm_mac(value: str | None) -> str | None:
    v = _norm_lower(value)
    if not v:
        return None
    compact = re.sub(r"[^0-9a-f]", "", v)
    if len(compact) != 12:
        return None
    return ":".join(compact[i:i+2] for i in range(0, 12, 2))


def _safe_ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except Exception:
        return None


def _safe_ips(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        ip = _safe_ip(value)
        if ip:
            out.append(ip)
    return sorted(set(out))


def _extract_domain(*values: str | None) -> str | None:
    for raw in values:
        value = _norm_lower(raw)
        if not value:
            continue
        if "@" in value:
            return value.split("@", 1)[1]
        if "." in value:
            parts = value.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
    return None


def _epoch_now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _friendly_uid(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode()).hexdigest()[:14]
    return f"asset-{digest}"


def _source_confidence(source: str | None) -> int:
    return SOURCE_CONFIDENCE.get((source or "").strip().lower(), 50)


def _merge_string(existing: str | None, incoming: str | None, *, prefer_incoming: bool) -> str | None:
    if incoming in BAD_STRINGS:
        return existing
    if existing in BAD_STRINGS:
        return incoming
    return incoming if prefer_incoming else existing


def _append_unique(values: list[Any] | None, *incoming: Any) -> list[Any]:
    out = list(values or [])
    seen = {repr(item) for item in out}
    for item in incoming:
        if item is None:
            continue
        key = repr(item)
        if key in seen:
            continue
        out.append(item)
        seen.add(key)
    return out


def _ensure_raw_metadata(asset: CanonicalAsset) -> dict[str, Any]:
    meta = dict(asset.raw_metadata_json or {})
    meta.setdefault("discovery_sources", [])
    meta.setdefault("source_evidence", {})
    return meta


def _recompute_display(asset: CanonicalAsset) -> None:
    asset.display_name = asset.hostname or asset.fqdn or asset.primary_ip or asset.agent_id or asset.asset_uid


def _recompute_asset_uid(asset: CanonicalAsset) -> None:
    strong = (
        _norm(asset.serial_number)
        or _norm(asset.device_id)
        or (_norm(asset.agent_id) if asset.agent_id and asset.agent_id != "unknown-agent" else None)
        or next(iter(asset.macs or []), None)
        or _norm(asset.fqdn)
        or _norm(asset.hostname)
        or _norm(asset.primary_ip)
    )
    if strong:
        asset.asset_uid = _friendly_uid(asset.tenant_id, strong)


def _find_existing_canonical_asset(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str | None = None,
    serial_number: str | None = None,
    device_id: str | None = None,
    macs: list[str] | None = None,
    hostname: str | None = None,
    fqdn: str | None = None,
    ips: list[str] | None = None,
) -> CanonicalAsset | None:
    if agent_id and agent_id != "unknown-agent":
        row = (
            db.query(CanonicalAsset)
            .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.agent_id == agent_id)
            .first()
        )
        if row:
            return row

    if serial_number:
        row = (
            db.query(CanonicalAsset)
            .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.serial_number == serial_number)
            .first()
        )
        if row:
            return row

    if device_id:
        row = (
            db.query(CanonicalAsset)
            .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.device_id == device_id)
            .first()
        )
        if row:
            return row

    for mac in macs or []:
        row = (
            db.query(CanonicalAsset)
            .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.macs.isnot(None))
            .all()
        )
        for candidate in row:
            if mac in (_norm_mac(x) for x in (candidate.macs or [])):
                return candidate

    names = {_norm_lower(hostname), _norm_lower(fqdn)} - {None}
    if names:
        for candidate in db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all():
            candidate_names = {_norm_lower(candidate.hostname), _norm_lower(candidate.fqdn)} - {None}
            if candidate_names.intersection(names):
                cand_ips = set(_safe_ips(candidate.ips or []))
                if not ips or not cand_ips or cand_ips.intersection(set(ips)):
                    return candidate

    if ips:
        ipset = set(ips)
        for candidate in db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all():
            cand_ips = set(_safe_ips(candidate.ips or []))
            if cand_ips.intersection(ipset):
                return candidate

    return None


def _touch_sources(asset: CanonicalAsset, source: str, confidence: int) -> None:
    asset.source_types_json = sorted(set((asset.source_types_json or []) + [source]))
    asset.last_seen_source = source
    current = asset.source_confidence or 0
    asset.source_confidence = max(current, confidence)


def _finalise_asset(asset: CanonicalAsset) -> None:
    asset.ips = _safe_ips(asset.ips or [])
    asset.macs = sorted(set([m for m in (_norm_mac(v) for v in (asset.macs or [])) if m]))
    asset.primary_ip = (asset.ips or [None])[0]
    asset.domain = asset.domain or _extract_domain(asset.fqdn, asset.hostname)
    _recompute_asset_uid(asset)
    _recompute_display(asset)


def record_agent_heartbeat(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    hostname: str | None,
    platform: str | None,
    timestamp: int | None,
) -> CanonicalAsset:
    record = _find_existing_canonical_asset(
        db,
        tenant_id=tenant_id,
        agent_id=agent_id,
        hostname=hostname,
    )
    if not record:
        record = CanonicalAsset(tenant_id=tenant_id, agent_id=agent_id)
        db.add(record)

    record.hostname = _merge_string(record.hostname, hostname, prefer_incoming=False)
    record.os_family = _merge_string(record.os_family, platform, prefer_incoming=False)
    record.last_heartbeat_epoch = timestamp or record.last_heartbeat_epoch or _epoch_now()
    record.management_state = "managed"
    _touch_sources(record, "heartbeat", _source_confidence("heartbeat"))
    _finalise_asset(record)
    db.commit()
    db.refresh(record)
    invalidate_unified_cache(tenant_id)
    return record


def upsert_canonical_asset_from_snapshot(db: Session, payload: dict) -> CanonicalAsset:
    tenant_id = payload["tenant_id"]
    agent_id = payload["agent_id"]
    asset = payload.get("asset", {})
    ips = _safe_ips(asset.get("ips", []))
    macs = [_norm_mac(v) for v in asset.get("macs", [])]
    macs = [v for v in macs if v]

    record = _find_existing_canonical_asset(
        db,
        tenant_id=tenant_id,
        agent_id=agent_id,
        serial_number=_norm(asset.get("serial_number")),
        device_id=_norm(asset.get("device_id")),
        macs=macs,
        hostname=asset.get("hostname"),
        fqdn=asset.get("fqdn"),
        ips=ips,
    )

    if not record:
        record = CanonicalAsset(tenant_id=tenant_id, agent_id=agent_id)
        db.add(record)

    record.agent_id = agent_id
    record.hostname = _merge_string(record.hostname, asset.get("hostname"), prefer_incoming=True)
    record.fqdn = _merge_string(record.fqdn, asset.get("fqdn"), prefer_incoming=True)
    record.os_family = _merge_string(record.os_family, asset.get("os_family"), prefer_incoming=True)
    record.os_version = _merge_string(record.os_version, asset.get("os_version"), prefer_incoming=True)
    record.domain = _merge_string(record.domain, asset.get("domain"), prefer_incoming=True)
    record.serial_number = _merge_string(record.serial_number, asset.get("serial_number"), prefer_incoming=True)
    record.device_id = _merge_string(record.device_id, asset.get("device_id"), prefer_incoming=True)
    record.ips = sorted(set((record.ips or []) + ips))
    record.macs = sorted(set((record.macs or []) + macs))
    record.last_snapshot_epoch = payload.get("timestamp") or record.last_snapshot_epoch
    record.management_state = "managed"

    meta = _ensure_raw_metadata(record)
    meta["last_asset_snapshot"] = payload
    meta["source_evidence"]["asset_snapshot"] = {
        "timestamp": payload.get("timestamp"),
        "hostname": asset.get("hostname"),
        "fqdn": asset.get("fqdn"),
        "ips": ips,
        "macs": macs,
    }
    if asset.get("device_id"):
        meta["device_id"] = asset.get("device_id")
    record.raw_metadata_json = meta
    _touch_sources(record, "asset_snapshot", _source_confidence("asset_snapshot"))
    _finalise_asset(record)

    db.commit()
    db.refresh(record)
    invalidate_unified_cache(tenant_id)
    return record


def merge_security_posture_into_asset(db: Session, tenant_id: str, agent_id: str, security_posture: dict, timestamp: int | None = None) -> None:
    asset = _find_existing_canonical_asset(db, tenant_id=tenant_id, agent_id=agent_id)
    if not asset:
        asset = CanonicalAsset(tenant_id=tenant_id, agent_id=agent_id)
        db.add(asset)

    asset.security_posture_json = security_posture
    if timestamp is not None:
        asset.last_snapshot_epoch = timestamp
    asset.management_state = "managed"

    meta = _ensure_raw_metadata(asset)
    meta["source_evidence"]["security_posture"] = {
        "timestamp": timestamp,
        "keys": sorted((security_posture or {}).keys()),
    }
    asset.raw_metadata_json = meta
    _touch_sources(asset, "security_posture", _source_confidence("security_posture"))
    _finalise_asset(asset)

    db.commit()
    invalidate_unified_cache(tenant_id)


def replace_software_inventory(db: Session, tenant_id: str, agent_id: str, software_items: list[dict]) -> None:
    asset = _find_existing_canonical_asset(db, tenant_id=tenant_id, agent_id=agent_id)
    if not asset:
        asset = CanonicalAsset(tenant_id=tenant_id, agent_id=agent_id)
        db.add(asset)
        db.flush()

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
                asset_id=asset.id,
                name=item.get("name"),
                version=item.get("version"),
                publisher=item.get("publisher"),
                install_date=item.get("install_date"),
                source=item.get("source") or "agent",
            )
        )

    meta = _ensure_raw_metadata(asset)
    meta["source_evidence"]["software_inventory"] = {
        "count": len([i for i in software_items if i.get("name")]),
    }
    asset.raw_metadata_json = meta
    asset.management_state = "managed"
    _touch_sources(asset, "agent", _source_confidence("agent"))
    _finalise_asset(asset)

    db.commit()
    invalidate_unified_cache(tenant_id)


def sync_network_discovery_to_canonical_asset(
    db: Session,
    *,
    tenant_id: str,
    network_asset: NetworkDiscoveredAsset,
) -> CanonicalAsset:
    network_ip = _safe_ip(network_asset.ip_address)
    network_mac = _norm_mac(network_asset.mac_address)
    network_name = network_asset.hostname or getattr(network_asset, "fqdn", None) or getattr(network_asset, "netbios_name", None) or getattr(network_asset, "mdns_name", None)

    record = _find_existing_canonical_asset(
        db,
        tenant_id=tenant_id,
        macs=[network_mac] if network_mac else None,
        hostname=network_name,
        fqdn=getattr(network_asset, "fqdn", None),
        ips=[network_ip] if network_ip else None,
    )
    if not record:
        synthetic_agent_id = f"network:{network_asset.id}"
        record = CanonicalAsset(tenant_id=tenant_id, agent_id=synthetic_agent_id)
        db.add(record)

    prefer_incoming = (record.source_confidence or 0) <= _source_confidence("network_scan")
    record.hostname = _merge_string(record.hostname, network_name, prefer_incoming=prefer_incoming)
    record.fqdn = _merge_string(record.fqdn, getattr(network_asset, "fqdn", None), prefer_incoming=prefer_incoming)
    record.os_family = _merge_string(record.os_family, network_asset.os_guess, prefer_incoming=prefer_incoming)
    record.os_version = _merge_string(record.os_version, network_asset.os_version, prefer_incoming=prefer_incoming)
    record.domain = _merge_string(record.domain, _extract_domain(getattr(network_asset, "fqdn", None), network_name), prefer_incoming=prefer_incoming)
    record.ips = sorted(set((record.ips or []) + ([network_ip] if network_ip else [])))
    record.macs = sorted(set((record.macs or []) + ([network_mac] if network_mac else [])))
    record.management_state = "managed" if record.agent_id and not str(record.agent_id).startswith("network:") else "unmanaged"
    record.network_asset_ids_json = _append_unique(record.network_asset_ids_json, network_asset.id)
    record.last_network_scan_job_id = network_asset.scan_job_id
    record.last_network_seen_epoch = _epoch_now()

    meta = _ensure_raw_metadata(record)
    meta["source_evidence"].setdefault("network_scan", [])
    evidence_row = {
        "network_asset_id": network_asset.id,
        "scan_job_id": network_asset.scan_job_id,
        "ip_address": network_asset.ip_address,
        "mac_address": network_asset.mac_address,
        "hostname": network_asset.hostname,
        "device_type": network_asset.device_type,
        "vendor": network_asset.vendor,
        "risk_level": network_asset.risk_level,
        "asset_confidence": getattr(network_asset, "asset_confidence", None),
    }
    existing = [row for row in meta["source_evidence"].get("network_scan", []) if row.get("network_asset_id") != network_asset.id]
    existing.append(evidence_row)
    meta["source_evidence"]["network_scan"] = existing[-20:]
    meta["network_summary"] = {
        "open_ports": network_asset.open_ports or [],
        "device_type": network_asset.device_type,
        "vendor": network_asset.vendor,
        "risk_level": network_asset.risk_level,
        "risk_score": network_asset.risk_score,
        "is_rogue": network_asset.is_rogue,
        "managed": network_asset.managed,
        "agent_installed": network_asset.agent_installed,
        "last_seen": getattr(network_asset, "last_seen", None),
    }
    record.raw_metadata_json = meta
    _touch_sources(record, "network_scan", _source_confidence("network_scan"))
    _finalise_asset(record)
    return record


def sync_network_discoveries_batch(
    db: Session,
    *,
    tenant_id: str,
    network_assets: list[NetworkDiscoveredAsset],
) -> int:
    count = 0
    for network_asset in network_assets:
        sync_network_discovery_to_canonical_asset(db, tenant_id=tenant_id, network_asset=network_asset)
        count += 1
    db.commit()
    invalidate_unified_cache(tenant_id)
    return count
