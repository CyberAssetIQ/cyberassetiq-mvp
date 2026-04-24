from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any, Optional
from collections import Counter
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_agent, require_read
from db.session import get_db
from models.network import NetworkDiscoveredAsset, NetworkScanJob
from models.agent import Agent
from models.asset import CanonicalAsset
from schemas.network import NetworkScanRequest, NetworkScanResponse
from services.network_scan_service import run_network_scan_job

logger = logging.getLogger(__name__)
router = APIRouter()


def _safe_len(value: Any) -> int:
    return len(value) if isinstance(value, (list, tuple, set, dict)) else 0


def _port_numbers(open_ports: Any) -> list[int | str]:
    if not isinstance(open_ports, list):
        return []
    ports: list[int | str] = []
    for item in open_ports:
        if isinstance(item, dict):
            port = item.get("port") or item.get("number") or item.get("value")
            if port is not None:
                ports.append(port)
        elif item is not None:
            ports.append(item)
    return ports


def _service_names(services: Any) -> list[str]:
    if not isinstance(services, list):
        return []
    names: list[str] = []
    for item in services:
        if isinstance(item, dict):
            name = item.get("service") or item.get("name") or item.get("product") or item.get("banner")
            if name:
                names.append(str(name))
        elif item:
            names.append(str(item))
    return names


def _sort_ip_text(value: str | None) -> tuple[int, str]:
    if not value:
        return (1, "")
    try:
        return (0, str(ip_address(value)))
    except ValueError:
        return (1, value)


def _risk_level_text(asset: NetworkDiscoveredAsset) -> str:
    return getattr(asset, "risk_level", None) or getattr(asset, "risk_hint", None) or "INFO"

def _hostname_sources(asset: NetworkDiscoveredAsset) -> list[str]:
    sources: list[str] = []
    if getattr(asset, "hostname", None):
        sources.append("reverse_dns")
    if getattr(asset, "netbios_name", None):
        sources.append("netbios")
    if getattr(asset, "mdns_name", None):
        sources.append("mdns")
    if getattr(asset, "fqdn", None):
        sources.append("fqdn")
    return sources


def _discovery_quality(asset: NetworkDiscoveredAsset, port_numbers: list[int | str]) -> str:
    score = 0
    if getattr(asset, "mac_address", None):
        score += 1
    if _hostname_sources(asset):
        score += 1
    if port_numbers:
        score += 1
    if getattr(asset, "vendor", None):
        score += 1
    if getattr(asset, "os_guess", None):
        score += 1
    return {
        0: "Observed only",
        1: "Low confidence",
        2: "Basic fingerprint",
        3: "Good fingerprint",
        4: "Rich fingerprint",
        5: "High fidelity",
    }.get(score, "Rich fingerprint")


def _asset_confidence_score(asset: NetworkDiscoveredAsset, port_numbers: list[int | str]) -> int:
    score = 20
    if getattr(asset, "mac_address", None):
        score += 20
    if _hostname_sources(asset):
        score += 20
    if port_numbers:
        score += 20
    if getattr(asset, "vendor", None):
        score += 10
    if getattr(asset, "os_guess", None):
        score += 10
    if getattr(asset, "agent_installed", False) or getattr(asset, "managed", False):
        score += 20
    return min(score, 100)


def _recommended_action(asset: NetworkDiscoveredAsset, port_numbers: list[int | str]) -> str:
    risk = str(_risk_level_text(asset) or "INFO").upper()
    if getattr(asset, "is_rogue", False):
        return "investigate_and_isolate"
    if getattr(asset, "agent_installed", False) or getattr(asset, "managed", False):
        if risk in {"CRITICAL", "HIGH"}:
            return "patch_and_harden"
        return "monitor_managed_asset"
    if 445 in port_numbers or 3389 in port_numbers:
        return "enrol_or_harden_host"
    if risk == "CRITICAL":
        return "contain_and_triage"
    if risk == "HIGH":
        return "investigate_and_reduce_exposure"
    if risk == "MEDIUM":
        return "review_and_harden"
    return "monitor_only"


def _classification_reasons(asset: NetworkDiscoveredAsset, port_numbers: list[int | str], service_names: list[str]) -> list[str]:
    reasons: list[str] = []
    vendor = getattr(asset, "vendor", None)
    if vendor:
        reasons.append(f"MAC vendor identified as {vendor}.")
    if getattr(asset, "os_guess", None):
        reasons.append(f"OS fingerprint suggests {asset.os_guess}.")
    device_family = getattr(asset, "device_family", None) or getattr(asset, "device_type", None)
    if device_family:
        reasons.append(f"Classified as {device_family} from ports, banners, and vendor signals.")
    if port_numbers:
        reasons.append(f"Open ports observed: {', '.join(str(p) for p in port_numbers[:8])}{'…' if len(port_numbers) > 8 else ''}.")
    if service_names:
        reasons.append(f"Services identified: {', '.join(service_names[:5])}{'…' if len(service_names) > 5 else ''}.")
    for factor in (getattr(asset, "risk_factors", None) or [])[:5]:
        reasons.append(f"Risk factor detected: {factor}.")
    return reasons




def _norm_ip_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return str(ip_address(value))
    except Exception:
        return value.lower()


def _norm_mac_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower().replace('-', ':')
    if not value:
        return None
    value = ''.join(ch for ch in value if ch in '0123456789abcdef:')
    parts = [p.zfill(2) for p in value.split(':') if p]
    return ':'.join(parts) if parts else None


def _norm_name_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower()
    return value or None


def _is_agent_live(agent: Agent | None, stale_after_seconds: int = 1800) -> bool:
    if not agent or getattr(agent, 'status', None) not in {None, '', 'active'}:
        return False
    last_seen_epoch = getattr(agent, 'last_seen_epoch', None)
    if not last_seen_epoch:
        return False
    try:
        import time
        return (int(time.time()) - int(last_seen_epoch)) <= stale_after_seconds
    except Exception:
        return False


def _annotate_network_rows_with_managed_state(db: Session, tenant_id: str, rows: list[NetworkDiscoveredAsset]) -> None:
    canonical_assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()

    canonical_by_ip: dict[str, CanonicalAsset] = {}
    canonical_by_mac: dict[str, CanonicalAsset] = {}
    canonical_by_name: dict[str, CanonicalAsset] = {}
    for asset in canonical_assets:
        for ip in (asset.ips or []):
            norm = _norm_ip_text(ip)
            if norm:
                canonical_by_ip.setdefault(norm, asset)
        for mac in (asset.macs or []):
            norm = _norm_mac_text(mac)
            if norm:
                canonical_by_mac.setdefault(norm, asset)
        for name in [asset.hostname, asset.fqdn]:
            norm = _norm_name_text(name)
            if norm:
                canonical_by_name.setdefault(norm, asset)

    agents_by_id = {a.agent_id: a for a in agents}
    live_agents_by_ip: dict[str, Agent] = {}
    live_agents_by_mac: dict[str, Agent] = {}
    live_agents_by_name: dict[str, Agent] = {}
    for asset in canonical_assets:
        agent = agents_by_id.get(asset.agent_id)
        if not _is_agent_live(agent):
            continue
        for ip in (asset.ips or []):
            norm = _norm_ip_text(ip)
            if norm:
                live_agents_by_ip.setdefault(norm, agent)
        for mac in (asset.macs or []):
            norm = _norm_mac_text(mac)
            if norm:
                live_agents_by_mac.setdefault(norm, agent)
        for name in [asset.hostname, asset.fqdn, getattr(agent, 'hostname', None)]:
            norm = _norm_name_text(name)
            if norm:
                live_agents_by_name.setdefault(norm, agent)

    for row in rows:
        row_ip = _norm_ip_text(getattr(row, 'ip_address', None))
        row_mac = _norm_mac_text(getattr(row, 'mac_address', None))
        row_names = [
            _norm_name_text(getattr(row, 'hostname', None)),
            _norm_name_text(getattr(row, 'netbios_name', None)),
            _norm_name_text(getattr(row, 'mdns_name', None)),
            _norm_name_text(getattr(row, 'fqdn', None)),
        ]
        row_names = [x for x in row_names if x]

        matched_asset = None
        matched_agent = None

        if row_ip and row_ip in canonical_by_ip:
            matched_asset = canonical_by_ip[row_ip]
        if row_mac and row_mac in canonical_by_mac and matched_asset is None:
            matched_asset = canonical_by_mac[row_mac]
        if matched_asset is None:
            for name in row_names:
                if name in canonical_by_name:
                    matched_asset = canonical_by_name[name]
                    break

        if row_ip and row_ip in live_agents_by_ip:
            matched_agent = live_agents_by_ip[row_ip]
        if row_mac and row_mac in live_agents_by_mac and matched_agent is None:
            matched_agent = live_agents_by_mac[row_mac]
        if matched_agent is None:
            for name in row_names:
                if name in live_agents_by_name:
                    matched_agent = live_agents_by_name[name]
                    break

        if matched_asset is not None:
            row.managed = True
            meta = getattr(row, 'raw_metadata_json', None) or {}
            if isinstance(meta, dict):
                meta['matched_agent_id'] = matched_asset.agent_id
                meta['managed_source'] = 'canonical_asset_match'
                if matched_agent is not None:
                    meta['live_agent_status'] = 'live'
                    meta['live_agent_hostname'] = getattr(matched_agent, 'hostname', None)
                row.raw_metadata_json = meta

        if matched_agent is not None:
            row.agent_installed = True
            if not getattr(row, 'managed', False):
                row.managed = True

def _network_asset_summary_row(asset: NetworkDiscoveredAsset) -> dict[str, Any]:
    hostname = asset.hostname or getattr(asset, "netbios_name", None) or getattr(asset, "mdns_name", None)
    open_ports = asset.open_ports or []
    services = getattr(asset, "services", []) or []
    port_numbers = _port_numbers(open_ports)
    service_names = _service_names(services)
    hostname_sources = _hostname_sources(asset)
    confidence_score = _asset_confidence_score(asset, port_numbers)
    vulnerabilities = getattr(asset, "vulnerabilities", None) or []
    return {
        "id": asset.id,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "netbios_name": getattr(asset, "netbios_name", None),
        "mdns_name": getattr(asset, "mdns_name", None),
        "fqdn": getattr(asset, "fqdn", None),
        "display_name": hostname or asset.ip_address,
        "mac_address": asset.mac_address,
        "vendor": asset.vendor,
        "device_model": getattr(asset, "device_model", None),
        "device_type": asset.device_type,
        "device_family": getattr(asset, "device_family", None),
        "os_guess": asset.os_guess,
        "os": asset.os_guess,
        "os_family": asset.os_guess,
        "os_version": getattr(asset, "os_version", None),
        "os_confidence": getattr(asset, "os_confidence", None),
        "network_segment": getattr(asset, "network_segment", None),
        "vlan": getattr(asset, "vlan", None),
        "gateway": getattr(asset, "gateway", None),
        "risk_score": getattr(asset, "risk_score", None),
        "risk_level": _risk_level_text(asset),
        "risk_hint": getattr(asset, "risk_hint", None),
        "risk_factors": getattr(asset, "risk_factors", []) or [],
        "recommended_action": _recommended_action(asset, port_numbers),
        "open_ports": open_ports,
        "ports_display": port_numbers,
        "open_port_count": len(port_numbers),
        "services": services,
        "services_display": service_names,
        "service_count": len(service_names),
        "http_headers": getattr(asset, "http_headers", None),
        "tls_info": getattr(asset, "tls_info", None),
        "smb_info": getattr(asset, "smb_info", None),
        "snmp_data": getattr(asset, "snmp_data", None),
        "banner_data": getattr(asset, "banner_data", None),
        "ce_issues": getattr(asset, "ce_issues", []) or [],
        "managed": getattr(asset, "managed", False),
        "is_managed": getattr(asset, "managed", False),
        "agent_installed": getattr(asset, "agent_installed", False),
        "is_rogue": getattr(asset, "is_rogue", False),
        "is_internet_facing": getattr(asset, "is_internet_facing", False),
        "asset_confidence": getattr(asset, "asset_confidence", None),
        "confidence_score": confidence_score,
        "discovery_quality": _discovery_quality(asset, port_numbers),
        "classification_reasons": _classification_reasons(asset, port_numbers, service_names),
        "hostname_sources": hostname_sources,
        "vulnerabilities": vulnerabilities[:20],
        "cve_count": getattr(asset, "cve_count", 0),
        "critical_cve_count": getattr(asset, "critical_cve_count", 0),
        "high_cve_count": getattr(asset, "high_cve_count", 0),
        "medium_cve_count": getattr(asset, "medium_cve_count", 0),
        "first_seen": getattr(asset, "first_seen", None),
        "last_seen": getattr(asset, "last_seen", None),
        "scan_job_id": asset.scan_job_id,
        "raw_metadata_json": getattr(asset, "raw_metadata_json", None),
    }


def _network_assets_rollup(items: list[dict[str, Any]]) -> dict[str, Any]:
    risk_counter = Counter(str(i.get("risk_level") or "INFO").upper() for i in items)
    device_counter = Counter((i.get("device_family") or i.get("device_type") or "unknown") for i in items)
    return {
        "total": len(items),
        "managed": sum(1 for i in items if i.get("managed") or i.get("agent_installed")),
        "rogue": sum(1 for i in items if i.get("is_rogue")),
        "internet_facing": sum(1 for i in items if i.get("is_internet_facing")),
        "critical": risk_counter.get("CRITICAL", 0),
        "high": risk_counter.get("HIGH", 0),
        "medium": risk_counter.get("MEDIUM", 0),
        "low": risk_counter.get("LOW", 0),
        "info": risk_counter.get("INFO", 0),
        "open_ports": sum(int(i.get("open_port_count") or 0) for i in items),
        "services": sum(int(i.get("service_count") or 0) for i in items),
        "device_types": [{"name": name, "count": count} for name, count in device_counter.most_common(8)],
    }



class AgentNetworkScanResult(BaseModel):
    tenant_id:        str
    agent_id:         str
    target:           str
    engine:           str = "nmap_agent"
    discovered_count: int = 0
    results:          list[dict[str, Any]] = []
    summary:          dict[str, Any] = {}


class ArpEnrichPayload(BaseModel):
    tenant_id: str
    agent_id:  str
    arp_table: list[dict]


def _detect_local_interfaces() -> list[dict]:
    """Best-effort IPv4 interface discovery with CIDR."""
    results: list[dict] = []

    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        seen: set[str] = set()

        for info in infos:
            ip = info[4][0]
            if not ip or ip.startswith("127."):
                continue
            if ip in seen:
                continue
            seen.add(ip)
            try:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                results.append({
                    "name": f"auto-{len(results)+1}",
                    "ip": ip,
                    "cidr": str(net),
                    "display": f"{ip} ({net})",
                })
            except Exception:
                continue
    except Exception:
        pass

    # Fallback: outbound route detection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("127."):
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            cidr = str(net)
            if not any(x["cidr"] == cidr for x in results):
                results.insert(0, {
                    "name": "primary",
                    "ip": ip,
                    "cidr": cidr,
                    "display": f"{ip} ({cidr})",
                })
    except Exception:
        pass

    return results


def _resolve_scan_target(raw_target: Optional[str], interface_name: Optional[str] = None) -> str:
    """Resolve target from explicit input, selected interface, or auto-detect."""
    target = (raw_target or "").strip()

    if target:
        try:
            if "/" in target:
                return str(ipaddress.ip_network(target, strict=False))
            return str(ipaddress.ip_network(f"{target}/32", strict=False))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid target subnet/IP: {target}") from exc

    interfaces = _detect_local_interfaces()
    if not interfaces:
        raise HTTPException(status_code=400, detail="Could not auto-detect a local subnet. Enter a subnet manually.")

    if interface_name:
        for item in interfaces:
            if item["name"] == interface_name:
                return item["cidr"]

    return interfaces[0]["cidr"]


@router.get("/interfaces")
def list_local_interfaces(
    auth: AuthenticatedRequest = Depends(require_read),
) -> dict:
    interfaces = _detect_local_interfaces()
    return {
        "items": interfaces,
        "default": interfaces[0]["cidr"] if interfaces else None,
    }


@router.post("/jobs", response_model=NetworkScanResponse)
def run_network_scan(
    payload: NetworkScanRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> NetworkScanResponse:
    """
    Launch a network scan asynchronously.
    Returns job_id immediately — scan runs in background thread.
    Frontend polls /jobs/{id}/progress for real-time updates.
    """
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")

    resolved_target = _resolve_scan_target(payload.target, payload.interface_name)

    # Create job row immediately and return to frontend
    job = NetworkScanJob(
        tenant_id    = payload.tenant_id,
        target       = resolved_target,
        requested_by = payload.requested_by,
        status       = "queued",
        engine       = None,
        summary_json = {
            "progress": {"phase": "Queued", "pct": 0, "msg": "Waiting to start"},
            "requested_target": payload.target,
            "resolved_target": resolved_target,
            "selected_interface": payload.interface_name,
            "auto_detected": not bool((payload.target or "").strip()),
        },
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id

    from threading import Thread
    from db.session import SessionLocal

    def _worker(jid: int, tenant_id: str, target: str, requested_by: str | None):
        import traceback as _tb
        print(f"[worker] starting job {jid} for {target}", flush=True)
        worker_db = SessionLocal()
        try:
            run_network_scan_job(
                worker_db,
                tenant_id    = tenant_id,
                target       = target,
                requested_by = requested_by,
                job_id       = jid,
            )
            print(f"[worker] job {jid} completed OK", flush=True)
        except Exception as exc:
            print(f"[worker] job {jid} FAILED: {exc}", flush=True)
            _tb.print_exc()
            try:
                failed = (worker_db.query(NetworkScanJob)
                          .filter(NetworkScanJob.id == jid).first())
                if failed:
                    failed.status = "failed"
                    failed.summary_json = {
                        **(failed.summary_json or {}),
                        "error":    str(exc),
                        "progress": {"phase": "Failed", "pct": 100, "msg": str(exc)},
                    }
                    worker_db.commit()
            except Exception as inner:
                print(f"[worker] could not update job status: {inner}", flush=True)
            logger.exception("Network scan job %s failed: %s", jid, exc)
        finally:
            worker_db.close()

    Thread(
        target = _worker,
        args   = (job_id, payload.tenant_id, resolved_target, payload.requested_by),
        daemon = True,
    ).start()

    return NetworkScanResponse(
        job_id           = job_id,
        tenant_id        = job.tenant_id,
        status           = job.status,   # "queued" — returned immediately
        target           = job.target,
        engine           = "pending",
        discovered_count = 0,
    )


@router.post("/agent-results")
def receive_agent_network_scan(
    payload: AgentNetworkScanResult,
    auth: AuthenticatedRequest = Depends(require_agent),
    db: Session = Depends(get_db),
) -> dict:
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")
    job = NetworkScanJob(
        tenant_id     = payload.tenant_id,
        target        = payload.target,
        requested_by  = f"agent:{payload.agent_id}",
        status        = "completed",
        engine        = payload.engine,
        summary_json  = {
            **(payload.summary or {}),
            "source":          "windows_agent",
            "agent_id":        payload.agent_id,
            "discovered_count": payload.discovered_count or len(payload.results or []),
            "progress": {"phase": "Completed", "pct": 100, "msg": "Agent scan complete"},
        },
    )
    db.add(job); db.commit(); db.refresh(job)
    # Mark all existing assets inactive before agent results
    # (same pattern as main scan — agent results ARE a scan)
    try:
        db.query(NetworkDiscoveredAsset).filter_by(
            tenant_id=payload.tenant_id
        ).update({"is_active": False}, synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()

    stored = 0
    for result in payload.results:
        try:
            # MAC-first identity — same as main scan service
            from services.network_scan_service import _norm_mac, _norm_name, _best_name
            mac       = _norm_mac(result.get("mac_address"))
            best_name = _norm_name(_best_name(result))
            ip        = result.get("ip_address")
            existing  = None

            # 1. MAC first
            if mac:
                existing = db.query(NetworkDiscoveredAsset).filter(
                    NetworkDiscoveredAsset.tenant_id  == payload.tenant_id,
                    NetworkDiscoveredAsset.mac_address == mac,
                ).first()

            # 2. Hostname fallback
            if existing is None and best_name:
                existing = db.query(NetworkDiscoveredAsset).filter(
                    NetworkDiscoveredAsset.tenant_id == payload.tenant_id,
                    (NetworkDiscoveredAsset.hostname     == best_name) |
                    (NetworkDiscoveredAsset.netbios_name == best_name) |
                    (NetworkDiscoveredAsset.mdns_name    == best_name),
                ).first()

            # 3. IP fallback
            if existing is None and ip:
                existing = db.query(NetworkDiscoveredAsset).filter(
                    NetworkDiscoveredAsset.tenant_id  == payload.tenant_id,
                    NetworkDiscoveredAsset.ip_address == ip,
                ).first()

            update_fields = [
                "hostname","netbios_name","fqdn","mac_address","vendor",
                "device_type","device_family","os_guess","network_segment",
                "open_ports","services","http_headers","tls_info","smb_info",
                "risk_score","risk_level","risk_hint","risk_factors",
                "ce_issues","ce_asset_registered","managed","agent_installed",
                "is_rogue","last_seen","raw_metadata_json",
            ]
            if existing:
                existing.ip_address = ip  # update IP in case device moved
                if mac and not existing.mac_address:
                    existing.mac_address = mac
                for field in update_fields:
                    if field in result and result[field] is not None:
                        setattr(existing, field, result[field])
                existing.scan_job_id = job.id
                try: existing.is_active = True
                except AttributeError: pass
            else:
                row = NetworkDiscoveredAsset(
                    tenant_id=payload.tenant_id, scan_job_id=job.id,
                    **{k: v for k, v in result.items() if hasattr(NetworkDiscoveredAsset, k)})
                try: row.is_active = True
                except AttributeError: pass
                db.add(row)
            stored += 1
        except Exception as e:
            logger.warning("Failed upsert %s: %s", result.get("ip_address"), e)
            db.rollback()
    db.commit()

    # Build active count + frozen snapshot — same as main scan
    try:
        active_count = db.query(NetworkDiscoveredAsset).filter(
            NetworkDiscoveredAsset.tenant_id == payload.tenant_id,
            NetworkDiscoveredAsset.is_active == True,
        ).count()
    except Exception:
        active_count = db.query(NetworkDiscoveredAsset).filter(
            NetworkDiscoveredAsset.tenant_id == payload.tenant_id
        ).count()

    snapshot = []
    for r in payload.results or []:
        snapshot.append({
            "ip":          r.get("ip_address"),
            "hostname":    r.get("hostname") or r.get("netbios_name") or r.get("mdns_name"),
            "mac":         r.get("mac_address"),
            "vendor":      r.get("vendor"),
            "device_type": r.get("device_type"),
            "os_guess":    r.get("os_guess"),
            "risk_level":  r.get("risk_level"),
            "risk_score":  r.get("risk_score"),
            "open_ports":  [p.get("port") for p in (r.get("open_ports") or [])
                            if isinstance(p, dict)],
            "ce_issues":   r.get("ce_issues") or [],
            "confidence":  r.get("asset_confidence", "confirmed_asset"),
        })

    job.summary_json = {
        **(job.summary_json or {}),
        "discovered_count":      payload.discovered_count or len(payload.results or []),
        "total_inventory_count": active_count,
        "snapshot":              snapshot,
    }
    db.commit()

    return {
        "status": "accepted", "job_id": job.id, "stored": stored,
        "target": payload.target, "engine": payload.engine,
    }


@router.post("/arp-enrich")
def arp_enrich(
    payload: ArpEnrichPayload,
    auth: AuthenticatedRequest = Depends(require_agent),
    db: Session = Depends(get_db),
) -> dict:
    """
    Receives ARP table from Windows agent and enriches discovered assets
    with MAC addresses and vendor info. Called automatically every 5 min.
    """
    if payload.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant ID mismatch.")

    updated = 0
    for entry in payload.arp_table:
        ip  = entry.get("ip")
        mac = entry.get("mac")
        if not ip or not mac:
            continue
        asset = (db.query(NetworkDiscoveredAsset)
                 .filter(NetworkDiscoveredAsset.tenant_id == payload.tenant_id,
                         NetworkDiscoveredAsset.ip_address == ip)
                 .first())
        if asset:
            asset.mac_address = mac
            vendor = entry.get("vendor")
            if vendor:
                asset.vendor = vendor
            # Re-classify device now we have vendor info
            vendor_lower = (vendor or "").lower()
            if asset.device_type in ("unknown", "iot_device", None):
                if any(w in vendor_lower for w in ["apple", "iphone", "ipad"]):
                    asset.device_type   = "mobile_device"
                    asset.device_family = "Mobile / Phone (Apple)"
                elif any(w in vendor_lower for w in ["samsung", "huawei", "xiaomi", "oneplus", "oppo"]):
                    asset.device_type   = "mobile_device"
                    asset.device_family = "Mobile / Phone (Android)"
                elif any(w in vendor_lower for w in ["tp-link", "netgear", "asus", "d-link", "linksys", "ubiquiti"]):
                    asset.device_type   = "network_device"
                    asset.device_family = "Network Infrastructure"
                elif any(w in vendor_lower for w in ["amazon", "google", "roku", "sonos", "ring"]):
                    asset.device_type   = "smart_device"
                    asset.device_family = "Smart Home Device"
                elif any(w in vendor_lower for w in ["canon", "epson", "brother", "hp", "xerox", "ricoh"]):
                    asset.device_type   = "printer"
                    asset.device_family = "Network Printer"
                elif any(w in vendor_lower for w in ["synology", "qnap", "drobo"]):
                    asset.device_type   = "nas_device"
                    asset.device_family = "Storage"
            updated += 1

    db.commit()
    logger.info("ARP enrichment: updated %d assets from agent %s", updated, payload.agent_id)

    # Also create new assets for IPs discovered by ARP that don't exist yet
    created = 0
    for entry in payload.arp_table:
        ip  = entry.get("ip")
        mac = entry.get("mac")
        if not ip or not mac:
            continue
        # Check if already exists
        exists = db.query(NetworkDiscoveredAsset).filter(
            NetworkDiscoveredAsset.tenant_id  == auth.tenant_id,
            NetworkDiscoveredAsset.ip_address == ip,
        ).first()
        if not exists:
            from services.network_scan_service import _norm_mac
            norm_mac = _norm_mac(mac)
            # Check by MAC too
            if norm_mac:
                exists = db.query(NetworkDiscoveredAsset).filter(
                    NetworkDiscoveredAsset.tenant_id   == auth.tenant_id,
                    NetworkDiscoveredAsset.mac_address == norm_mac,
                ).first()
            if not exists:
                new_asset = NetworkDiscoveredAsset(
                    tenant_id    = auth.tenant_id,
                    ip_address   = ip,
                    mac_address  = norm_mac or mac,
                    vendor       = entry.get("vendor"),
                    device_type  = "unknown",
                    network_segment = ip.rsplit(".", 1)[0] + ".0/24",
                    first_seen   = __import__("datetime").datetime.utcnow().isoformat(),
                    last_seen    = __import__("datetime").datetime.utcnow().isoformat(),
                    open_ports   = [],
                    services     = [],
                    risk_level   = "INFO",
                    risk_score   = 0.0,
                    managed      = False,
                    is_rogue     = False,
                    ce_issues    = [],
                    raw_metadata_json = {"engine": "arp", "source": "agent_arp_table"},
                )
                try: new_asset.is_active = True
                except AttributeError: pass
                db.add(new_asset)
                created += 1

    if created:
        db.commit()

    return {"status": "ok", "updated": updated, "created": created,
            "received": len(payload.arp_table)}


@router.get("/jobs")
def list_network_jobs(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = (
        db.query(NetworkScanJob)
        .filter(NetworkScanJob.tenant_id == auth.tenant_id)
        .order_by(NetworkScanJob.id.desc())
        .limit(50)
        .all()
    )
    items: list[dict[str, Any]] = []
    for r in rows:
        summary = r.summary_json or {}
        progress = summary.get("progress", {}) if isinstance(summary, dict) else {}
        risk_breakdown = summary.get("risk_breakdown", {}) if isinstance(summary, dict) else {}
        items.append(
            {
                "job_id": r.id,
                "target": r.target,
                "status": r.status,
                "engine": r.engine or summary.get("engine") or "nmap",
                "summary": summary,
                "created_at": str(r.created_at),
                "progress_pct": progress.get("pct", 0),
                "phase": progress.get("phase", "Queued"),
                "hosts_found": summary.get("discovered_count", 0),
                "assets_found": summary.get("discovered_count", 0),
                "critical_hosts": risk_breakdown.get("critical", 0),
                "high_hosts": risk_breakdown.get("high", 0),
            }
        )
    return items


@router.get("/assets")
def list_network_assets(
    latest: bool = Query(default=True),
    job_id: int | None = Query(default=None),
    active_only: bool = Query(default=True),
    include_summary: bool = Query(default=False),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict] | dict:
    """
    Returns network discovered assets.
    active_only=true (default): Only assets from the latest scan (enterprise mode).
    job_id=X: Snapshot of a specific scan job.
    active_only=false: Full historical inventory.
    include_summary=true: Return enterprise rollup + items.
    """
    query = db.query(NetworkDiscoveredAsset).filter(
        NetworkDiscoveredAsset.tenant_id == auth.tenant_id
    )

    if job_id is not None:
        query = query.filter(NetworkDiscoveredAsset.scan_job_id == job_id)
    elif active_only:
        try:
            query = query.filter(NetworkDiscoveredAsset.is_active == True)
        except Exception:
            latest_job = (
                db.query(NetworkScanJob)
                .filter(
                    NetworkScanJob.tenant_id == auth.tenant_id,
                    NetworkScanJob.status == "completed",
                )
                .order_by(NetworkScanJob.id.desc())
                .first()
            )
            if latest_job:
                query = query.filter(NetworkDiscoveredAsset.scan_job_id == latest_job.id)

    rows = query.all()
    _annotate_network_rows_with_managed_state(db, auth.tenant_id, rows)
    rows = sorted(rows, key=lambda r: _sort_ip_text(r.ip_address))
    items = [_network_asset_summary_row(r) for r in rows]

    if include_summary:
        return {"summary": _network_assets_rollup(items), "items": items}
    return items


@router.get("/jobs/{job_id}/snapshot")
def get_scan_snapshot(
    job_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """
    Return the frozen snapshot of a completed scan job.
    This is what "View" on scan history shows — the exact state
    of every asset at the time that scan ran (immutable archive).
    """
    job = (db.query(NetworkScanJob)
           .filter(NetworkScanJob.id == job_id,
                   NetworkScanJob.tenant_id == auth.tenant_id)
           .first())
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    summary = job.summary_json or {}
    snapshot = summary.get("snapshot")

    if snapshot:
        # New format — frozen snapshot stored at scan time
        return {
            "job_id":     job_id,
            "target":     job.target,
            "engine":     job.engine,
            "created_at": str(job.created_at),
            "summary": {
                "discovered_count":  summary.get("discovered_count", len(snapshot)),
                "risk_breakdown":    summary.get("risk_breakdown", {}),
                "device_types":      summary.get("device_types", []),
            },
            "assets": snapshot,
            "snapshot_type": "frozen",
        }
    else:
        # Legacy format — query current DB state filtered by job_id
        rows = (db.query(NetworkDiscoveredAsset)
                .filter(NetworkDiscoveredAsset.tenant_id  == auth.tenant_id,
                        NetworkDiscoveredAsset.scan_job_id == job_id)
                .order_by(NetworkDiscoveredAsset.ip_address.asc())
                .all())
        assets = [{
            "ip":          r.ip_address,
            "hostname":    r.hostname or r.netbios_name or r.mdns_name,
            "mac":         r.mac_address,
            "vendor":      r.vendor,
            "device_type": r.device_type,
            "os_guess":    r.os_guess,
            "risk_level":  r.risk_level,
            "open_ports":  [p.get("port") for p in (r.open_ports or [])],
        } for r in rows]
        return {
            "job_id":     job_id,
            "target":     job.target,
            "engine":     job.engine,
            "created_at": str(job.created_at),
            "summary":    summary,
            "assets":     assets,
            "snapshot_type": "legacy",
        }


@router.get("/jobs/{job_id}/progress")
def get_scan_progress(
    job_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> dict:
    """Poll scan progress during an active scan."""
    job = (
        db.query(NetworkScanJob)
        .filter(NetworkScanJob.id == job_id, NetworkScanJob.tenant_id == auth.tenant_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    summary = job.summary_json or {}
    progress = summary.get("progress", {}) if isinstance(summary, dict) else {}
    return {
        "job_id": job_id,
        "status": job.status,
        "phase": progress.get("phase", "Running"),
        "pct": progress.get("pct", 0),
        "progress_pct": progress.get("pct", 0),
        "msg": progress.get("msg", ""),
        "hosts_found": summary.get("discovered_count", 0),
        "discovered_count": summary.get("discovered_count", 0),
    }


@router.post("/jobs/{job_id}/cancel")
def cancel_network_job(
    job_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    job = (db.query(NetworkScanJob)
           .filter(NetworkScanJob.id == job_id,
                   NetworkScanJob.tenant_id == auth.tenant_id).first())
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    if job.status not in ("running", "queued"):
        raise HTTPException(status_code=400,
                            detail=f"Job is already '{job.status}' — cannot cancel.")
    job.status = "cancelled"
    job.summary_json = {**(job.summary_json or {}), "cancelled_by": "user"}
    db.commit()
    logger.info("Network scan job %d cancelled by user", job_id)
    return {"status": "cancelled", "job_id": job_id}


@router.post("/resolve-hostnames")
def resolve_hostnames(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Best-effort hostname enrichment for network-discovered assets
    that have no hostname, NetBIOS name, or mDNS name yet.
    Uses six discovery techniques: NetBIOS/NBNS, LLMNR, mDNS/Bonjour,
    UPnP friendlyName, SNMP sysName, SSH banner.
    """
    try:
        from services.device_name_discovery import batch_discover_device_names

        assets = (
            db.query(NetworkDiscoveredAsset)
            .filter(
                NetworkDiscoveredAsset.tenant_id == auth.tenant_id,
                NetworkDiscoveredAsset.is_active.is_(True),
            )
            .all()
        )

        blank_assets = [
            a for a in assets
            if a.ip_address and not (
                getattr(a, "hostname", None) or
                getattr(a, "netbios_name", None) or
                getattr(a, "mdns_name", None)
            )
        ]

        if not blank_assets:
            return {
                "status": "ok",
                "message": "No hostname enrichment required — all active assets already have a name.",
                "total_assets": len(assets),
                "enriched": 0,
            }

        ips = [a.ip_address for a in blank_assets]
        results = batch_discover_device_names(ips, max_workers=16)
        updated = 0

        for asset in blank_assets:
            result = results.get(asset.ip_address)
            if not result or not result.get("name"):
                continue

            name   = result["name"]
            source = result.get("source", "")
            extra  = result.get("extra") or {}

            if "NetBIOS" in source:
                if not getattr(asset, "netbios_name", None):
                    setattr(asset, "netbios_name", name)
                if not getattr(asset, "hostname", None):
                    setattr(asset, "hostname", name)
            elif "mDNS" in source:
                if not getattr(asset, "mdns_name", None):
                    setattr(asset, "mdns_name", name)
                if not getattr(asset, "hostname", None):
                    setattr(asset, "hostname", extra.get("fqdn") or name)
            else:
                if not getattr(asset, "hostname", None):
                    setattr(asset, "hostname", name)

            updated += 1

        db.commit()

        return {
            "status": "ok",
            "message": f"Hostname enrichment completed. {updated} asset(s) updated.",
            "total_checked": len(blank_assets),
            "enriched": updated,
        }

    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Hostname enrichment failed: {exc}",
        )
