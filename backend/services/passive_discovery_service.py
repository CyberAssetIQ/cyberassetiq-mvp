from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy.orm import Session

from models.network import NetworkDiscoveredAsset
from models.network_extensions import ExtensionServiceJob, PassiveDiscoveryResult


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update_job(db, job, *, status=None, stage=None, pct=None, current_target=None, findings_count=None, summary=None):
    if status is not None: job.status = status
    if stage is not None: job.current_stage = stage
    if pct is not None: job.progress_percent = pct
    if current_target is not None: job.current_target = current_target
    if findings_count is not None: job.findings_count = findings_count
    if summary is not None: job.summary_json = summary
    db.commit()


# Device type classification from MAC/vendor hints
def _classify_device(asset: NetworkDiscoveredAsset) -> str:
    vendor = (asset.vendor or "").lower()
    device_type = (asset.device_type or "").lower()
    os_guess = (asset.os_guess or "").lower()

    if asset.agent_installed:
        return "managed_endpoint"
    if any(x in vendor for x in ["apple", "samsung", "xiaomi", "huawei", "oneplus", "oppo", "google"]):
        return "mobile_device"
    if any(x in vendor for x in ["cisco", "netgear", "tp-link", "ubiquiti", "zyxel", "draytek", "mikrotik"]):
        return "network_device"
    if any(x in vendor for x in ["sonos", "roku", "amazon", "philips", "lg electronics", "samsung"]):
        return "smart_device"
    if any(x in device_type for x in ["router", "switch", "access_point", "firewall"]):
        return "network_device"
    if any(x in device_type for x in ["mobile", "phone", "tablet"]):
        return "mobile_device"
    if any(x in device_type for x in ["printer"]):
        return "printer"
    if any(x in os_guess for x in ["android", "ios", "iphone", "ipad"]):
        return "mobile_device"
    if any(x in os_guess for x in ["windows", "linux", "macos"]):
        return "unmanaged_endpoint"
    return "unknown_device"


def run_passive_discovery_job(
    db: Session,
    *,
    tenant_id: str,
    target: str | None,
    requested_by: str | None,
    job_id: int,
) -> dict:
    job = db.query(ExtensionServiceJob).filter(ExtensionServiceJob.id == job_id).first()
    if not job:
        return {"status": "missing_job"}

    _update_job(db, job, status="running", stage="querying_agent_arp_data", pct=10,
                summary={"service": "Passive Discovery", "started_at": _now_iso(),
                         "progress": {"phase": "Querying agent ARP data", "pct": 10}})

    # Pull ALL network assets — agent ARP table is the source of truth
    assets = (
        db.query(NetworkDiscoveredAsset)
        .filter(
            NetworkDiscoveredAsset.tenant_id == tenant_id,
            NetworkDiscoveredAsset.is_active == True,
        )
        .order_by(NetworkDiscoveredAsset.ip_address)
        .all()
    )

    _update_job(db, job, stage="classifying_devices", pct=30,
                summary={"service": "Passive Discovery",
                         "progress": {"phase": "Classifying devices", "pct": 30}})

    stored = 0
    unmanaged = 0
    total = len(assets)

    for idx, asset in enumerate(assets, start=1):
        pct = 30 + min(60, int((idx / max(total, 1)) * 60))
        _update_job(db, job, stage="storing_results", pct=pct, current_target=asset.ip_address)

        # Skip if already stored for this job
        existing = (
            db.query(PassiveDiscoveryResult)
            .filter(
                PassiveDiscoveryResult.tenant_id == tenant_id,
                PassiveDiscoveryResult.job_id == job_id,
                PassiveDiscoveryResult.ip_address == asset.ip_address,
            )
            .first()
        )
        if existing:
            continue

        device_class = _classify_device(asset)
        source_method = "agent_arp" if asset.mac_address else "network_scan"
        confidence = "high" if asset.mac_address else "medium"

        if not asset.agent_installed:
            unmanaged += 1

        db.add(PassiveDiscoveryResult(
            tenant_id=tenant_id,
            job_id=job_id,
            ip_address=asset.ip_address or "unknown",
            mac_address=asset.mac_address,
            hostname=asset.hostname or asset.ip_address,
            vendor=asset.vendor or "Unknown vendor",
            source_method=source_method,
            confidence=confidence,
            metadata_json={
                "device_class": device_class,
                "device_type": asset.device_type,
                "os_guess": asset.os_guess,
                "agent_installed": asset.agent_installed,
                "is_active": asset.is_active,
                "managed": asset.agent_installed,
                "open_ports_count": len(asset.open_ports or []),
                "risk_score": asset.risk_score,
            },
        ))
        stored += 1

    db.commit()

    _update_job(
        db, job,
        status="completed", stage="completed", pct=100, findings_count=stored,
        summary={
            "service": "Passive Discovery",
            "finished_at": _now_iso(),
            "total_devices": stored,
            "unmanaged_devices": unmanaged,
            "managed_devices": stored - unmanaged,
            "total_assets_checked": total,
            "progress": {"phase": "Completed", "pct": 100},
        },
    )

    return {"status": "completed", "stored": stored, "unmanaged": unmanaged}
