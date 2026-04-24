"""shadow_it_service.py

Shadow IT Detection (Phase 3).

Reads from:  canonical_software, network_discovered_assets, canonical_assets,
             vulnerability_findings, darkweb_findings.
Writes to:   shadow_it_findings, rogue_software_findings, unknown_device_findings.

Detection sources:
  1. Rogue software    — software in canonical_software that matches high-risk categories
  2. Unknown devices   — network_discovered_assets with no matching canonical_asset
  3. Shadow SaaS       — SaaS-category software installed on endpoints
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset
from models.shadow_it import RogueSoftwareFinding, ShadowITFinding, UnknownDeviceFinding
from models.telemetry import CanonicalSoftware

logger = logging.getLogger("cyberassetiq.shadow_it")

# ---------------------------------------------------------------------------
# Software risk classification catalogue
# ---------------------------------------------------------------------------

# (category, risk_score, risk_flags)
_HIGH_RISK_SOFTWARE: dict[str, tuple[str, float, list[str]]] = {
    # Remote access tools often used as RATs
    "anydesk":         ("remote_access", 7.5, ["remote_access_capable", "known_rat_vector"]),
    "teamviewer":      ("remote_access", 6.0, ["remote_access_capable"]),
    "ultraviewer":     ("remote_access", 8.0, ["remote_access_capable", "known_rat_vector"]),
    "ammyy admin":     ("remote_access", 9.0, ["remote_access_capable", "known_rat_vector"]),
    "logmein":         ("remote_access", 5.5, ["remote_access_capable"]),
    "connectwise":     ("remote_access", 5.0, ["remote_access_capable"]),
    # VPN bypass
    "hotspot shield":  ("vpn", 6.5, ["policy_bypass_risk", "data_residency_risk"]),
    "expressvpn":      ("vpn", 6.0, ["policy_bypass_risk", "data_residency_risk"]),
    "nordvpn":         ("vpn", 5.5, ["policy_bypass_risk"]),
    "protonvpn":       ("vpn", 5.0, ["policy_bypass_risk"]),
    # P2P / torrents
    "bittorrent":      ("p2p", 8.5, ["data_exfil_risk", "malware_delivery_risk"]),
    "utorrent":        ("p2p", 8.5, ["data_exfil_risk", "malware_delivery_risk"]),
    "qbittorrent":     ("p2p", 7.0, ["data_exfil_risk"]),
    # Cryptocurrency
    "nicehash":        ("cryptocurrency", 7.0, ["resource_abuse_risk", "policy_violation"]),
    "exodus":          ("cryptocurrency", 6.0, ["policy_violation"]),
    # Hacking tools
    "nmap":            ("hacking_tool", 7.0, ["recon_capable", "policy_violation"]),
    "wireshark":       ("hacking_tool", 5.0, ["packet_capture_capable"]),
    "metasploit":      ("hacking_tool", 9.5, ["exploit_framework", "policy_violation"]),
    "mimikatz":        ("hacking_tool", 10.0, ["credential_harvesting", "policy_violation"]),
    "cobalt strike":   ("hacking_tool", 10.0, ["attack_framework", "policy_violation"]),
    # AI tools with potential data leakage
    "claude":          ("ai_tool", 3.0, ["potential_data_exfil"]),
    "chatgpt":         ("ai_tool", 3.5, ["potential_data_exfil"]),
    "copilot":         ("ai_tool", 3.0, ["potential_data_exfil"]),
    # Screen capture / monitoring (potential insider threat vector)
    "obs studio":      ("screen_capture", 4.0, ["potential_data_exfil"]),
    "sharex":          ("screen_capture", 4.5, ["potential_data_exfil"]),
}

# SaaS-like applications installed locally
_SAAS_INDICATORS: list[str] = [
    "dropbox", "google drive", "onedrive personal", "box drive",
    "slack", "discord", "telegram", "whatsapp",
    "zoom", "teams personal", "skype",
    "trello", "notion", "asana", "monday.com",
]

# Admin ports that signal an unknown device warrants attention
_HIGH_RISK_PORTS: set[int] = {22, 23, 25, 445, 3389, 5985, 5986, 8080, 8443, 4444, 9001}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_shadow_it_summary(db: Session, tenant_id: str) -> dict:
    rogue_count = db.query(RogueSoftwareFinding).filter(
        RogueSoftwareFinding.tenant_id == tenant_id,
        RogueSoftwareFinding.approved_status == "unapproved",
    ).count()
    unknown_devices = db.query(UnknownDeviceFinding).filter(
        UnknownDeviceFinding.tenant_id == tenant_id,
        UnknownDeviceFinding.status == "unresolved",
    ).count()
    shadow_saas = db.query(ShadowITFinding).filter(
        ShadowITFinding.tenant_id == tenant_id,
        ShadowITFinding.finding_type == "unapproved_saas",
        ShadowITFinding.status == "open",
    ).count()
    high_risk = db.query(RogueSoftwareFinding).filter(
        RogueSoftwareFinding.tenant_id == tenant_id,
        RogueSoftwareFinding.risk_score >= 7.0,
        RogueSoftwareFinding.approved_status == "unapproved",
    ).count()
    return {
        "rogue_software_count": rogue_count,
        "unknown_devices_count": unknown_devices,
        "shadow_saas_count": shadow_saas,
        "high_risk_findings": high_risk,
        "total_open": rogue_count + unknown_devices + shadow_saas,
    }


def scan_rogue_software(db: Session, tenant_id: str) -> dict:
    """
    Scan all canonical_software rows for this tenant and create/update
    rogue_software_findings.  Returns counts of new and updated findings.
    """
    software_rows = db.query(CanonicalSoftware).filter(
        CanonicalSoftware.tenant_id == tenant_id,
    ).all()

    new_count = 0
    seen_keys: set[tuple] = set()

    for sw in software_rows:
        name_lower = (sw.name or "").lower().strip()
        match_key, match_data = _classify_software(name_lower)
        if not match_data:
            continue

        category, risk_score, risk_flags = match_data
        key = (sw.asset_id, sw.name)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Upsert: check if finding already exists
        existing = db.query(RogueSoftwareFinding).filter(
            RogueSoftwareFinding.tenant_id == tenant_id,
            RogueSoftwareFinding.asset_id == sw.asset_id,
            RogueSoftwareFinding.software_name == sw.name,
        ).first()

        if existing:
            existing.last_seen_at = datetime.now(timezone.utc)
            existing.risk_score = risk_score
        else:
            finding = RogueSoftwareFinding(
                tenant_id=tenant_id,
                asset_id=sw.asset_id,
                software_name=sw.name,
                software_version=sw.version,
                publisher=sw.publisher,
                category=category,
                risk_score=risk_score,
                risk_flags=risk_flags,
                approved_status="unapproved",
                last_seen_at=datetime.now(timezone.utc),
            )
            db.add(finding)
            new_count += 1

            # Also create a general shadow_it_finding for SaaS-category items
            if category in ("ai_tool",) or name_lower in _SAAS_INDICATORS:
                _upsert_saas_finding(db, tenant_id, sw.asset_id, sw.name, risk_score)

    db.commit()
    logger.info(
        "Shadow IT rogue scan: tenant=%s new=%d software_rows=%d",
        tenant_id, new_count, len(software_rows),
    )
    return {"new_findings": new_count, "software_scanned": len(software_rows)}


def scan_unknown_devices(db: Session, tenant_id: str) -> dict:
    """
    Compare network_discovered_assets against canonical_assets.
    Assets with no matching canonical record become unknown_device_findings.
    """
    # Collect all known IPs from canonical assets
    known_ips: set[str] = set()
    for asset in db.query(CanonicalAsset).filter(
        CanonicalAsset.tenant_id == tenant_id
    ).all():
        for ip in (asset.ips or []):
            known_ips.add(str(ip).strip())

    network_assets = db.query(NetworkDiscoveredAsset).filter(
        NetworkDiscoveredAsset.tenant_id == tenant_id,
    ).all()

    new_count = 0
    for na in network_assets:
        if not na.ip_address:
            continue
        if na.ip_address in known_ips:
            continue

        # Already recorded?
        existing = db.query(UnknownDeviceFinding).filter(
            UnknownDeviceFinding.tenant_id == tenant_id,
            UnknownDeviceFinding.ip_address == na.ip_address,
        ).first()

        open_ports: list[int] = []
        if na.open_ports:
            try:
                raw = na.open_ports or []
                open_ports = [int(p.get('port', p) if isinstance(p, dict) else p) for p in raw]
            except (TypeError, ValueError):
                open_ports = []

        risky_ports = [p for p in open_ports if p in _HIGH_RISK_PORTS]
        risk_score = 5.0 + min(len(risky_ports) * 1.5, 4.5)
        risk_flags = []
        if risky_ports:
            risk_flags.append(f"admin_ports_open:{risky_ports}")
        if not na.hostname:
            risk_flags.append("no_hostname")

        if existing:
            existing.last_seen_at = datetime.now(timezone.utc)
            existing.risk_score = risk_score
            existing.open_ports = open_ports
        else:
            finding = UnknownDeviceFinding(
                tenant_id=tenant_id,
                ip_address=na.ip_address,
                mac_address=na.mac_address,
                hostname=na.hostname,
                open_ports=open_ports,
                risk_score=risk_score,
                risk_flags=risk_flags,
                status="unresolved",
                last_seen_at=datetime.now(timezone.utc),
            )
            db.add(finding)
            new_count += 1

    db.commit()
    logger.info(
        "Shadow IT unknown devices: tenant=%s new=%d network_assets=%d",
        tenant_id, new_count, len(network_assets),
    )
    return {"new_findings": new_count, "network_assets_checked": len(network_assets)}


def run_full_scan(db: Session, tenant_id: str) -> dict:
    """Convenience wrapper that runs all Shadow IT detection passes."""
    software_result = scan_rogue_software(db, tenant_id)
    device_result = scan_unknown_devices(db, tenant_id)
    return {
        "rogue_software": software_result,
        "unknown_devices": device_result,
        "summary": get_shadow_it_summary(db, tenant_id),
    }


def list_rogue_software(db: Session, tenant_id: str,
                        min_risk: float = 0.0, limit: int = 100) -> list[dict]:
    rows = db.query(RogueSoftwareFinding).filter(
        RogueSoftwareFinding.tenant_id == tenant_id,
        RogueSoftwareFinding.risk_score >= min_risk,
    ).order_by(RogueSoftwareFinding.risk_score.desc()).limit(limit).all()
    return [_rogue_to_dict(r) for r in rows]


def list_unknown_devices(db: Session, tenant_id: str, limit: int = 100) -> list[dict]:
    rows = db.query(UnknownDeviceFinding).filter(
        UnknownDeviceFinding.tenant_id == tenant_id,
        UnknownDeviceFinding.status == "unresolved",
    ).order_by(UnknownDeviceFinding.risk_score.desc()).limit(limit).all()
    return [_device_to_dict(d) for d in rows]


def update_finding_status(db: Session, tenant_id: str, finding_id: int,
                          finding_table: str, new_status: str) -> dict:
    """Update the status of a rogue software or unknown device finding."""
    model_map = {
        "rogue_software": RogueSoftwareFinding,
        "unknown_device": UnknownDeviceFinding,
        "shadow_it": ShadowITFinding,
    }
    model = model_map.get(finding_table)
    if not model:
        return {"error": "Invalid finding_table"}

    row = db.query(model).filter(
        model.id == finding_id,
        model.tenant_id == tenant_id,
    ).first()
    if not row:
        return {"error": "Finding not found"}

    if finding_table == "rogue_software":
        row.approved_status = new_status
    else:
        row.status = new_status

    db.commit()
    return {"id": finding_id, "new_status": new_status}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _classify_software(name_lower: str) -> tuple[str, tuple | None]:
    for keyword, data in _HIGH_RISK_SOFTWARE.items():
        if keyword in name_lower:
            return keyword, data
    return "", None


def _upsert_saas_finding(db: Session, tenant_id: str, asset_id: int,
                         app_name: str, risk_score: float) -> None:
    existing = db.query(ShadowITFinding).filter(
        ShadowITFinding.tenant_id == tenant_id,
        ShadowITFinding.entity_name == app_name,
        ShadowITFinding.finding_type == "unapproved_saas",
    ).first()
    if not existing:
        finding = ShadowITFinding(
            tenant_id=tenant_id,
            source_asset_id=asset_id,
            finding_type="unapproved_saas",
            entity_name=app_name,
            entity_category="ai_tool" if "ai" in app_name.lower() else "productivity",
            risk_score=risk_score,
            is_data_exfil_risk=True,
            status="open",
        )
        db.add(finding)


def _rogue_to_dict(r: RogueSoftwareFinding) -> dict:
    return {
        "id": r.id,
        "asset_id": r.asset_id,
        "software_name": r.software_name,
        "software_version": r.software_version,
        "publisher": r.publisher,
        "category": r.category,
        "risk_score": r.risk_score,
        "risk_flags": r.risk_flags or [],
        "approved_status": r.approved_status,
        "has_known_cves": r.has_known_cves,
        "detected_at": r.detected_at.isoformat() if r.detected_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
    }


def _device_to_dict(d: UnknownDeviceFinding) -> dict:
    return {
        "id": d.id,
        "ip_address": d.ip_address,
        "mac_address": d.mac_address,
        "hostname": d.hostname,
        "network_segment": d.network_segment,
        "device_type_guess": d.device_type_guess,
        "open_ports": d.open_ports or [],
        "risk_score": d.risk_score,
        "risk_flags": d.risk_flags or [],
        "status": d.status,
        "detected_at": d.detected_at.isoformat() if d.detected_at else None,
        "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
    }
