from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any, Optional
from collections import Counter, defaultdict
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_admin, require_agent, require_read
from db.session import get_db
from models.agent import Agent
from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset, NetworkScanJob
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


def _norm_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower()
    return value or None


def _norm_mac(value: str | None) -> str | None:
    value = _norm_text(value)
    if not value:
        return None
    return ''.join(ch for ch in value if ch in '0123456789abcdef')


def _safe_ip_text(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _hostname_sources(asset: NetworkDiscoveredAsset, canonical: CanonicalAsset | None = None, agent: Agent | None = None) -> list[str]:
    sources: list[str] = []
    if getattr(asset, 'hostname', None):
        sources.append('scan_hostname')
    if getattr(asset, 'netbios_name', None):
        sources.append('netbios')
    if getattr(asset, 'mdns_name', None):
        sources.append('mdns')
    if getattr(asset, 'fqdn', None):
        sources.append('fqdn')
    if canonical and (canonical.hostname or canonical.fqdn):
        sources.append('canonical_asset')
    if agent and getattr(agent, 'hostname', None):
        sources.append('agent')
    return sources


def _agent_state(agent: Agent | None, canonical: CanonicalAsset | None = None) -> str:
    if not agent and not canonical:
        return 'not_installed'
    if not agent:
        return 'installed'
    last_seen = getattr(agent, 'last_seen_epoch', None)
    if not last_seen and canonical is not None:
        last_seen = getattr(canonical, 'last_snapshot_epoch', None)
    if not last_seen:
        return 'installed'
    import time
    age = max(0, int(time.time()) - int(last_seen))
    if age <= 900:
        return 'live'
    if age <= 86400:
        return 'offline'
    return 'stale'


def _discovery_quality(asset: NetworkDiscoveredAsset, matched: bool = False) -> tuple[str, int]:
    score = 0
    if getattr(asset, 'mac_address', None):
        score += 30
    if any(getattr(asset, f, None) for f in ('hostname', 'netbios_name', 'mdns_name', 'fqdn')):
        score += 20
    if getattr(asset, 'open_ports', None):
        score += 20
    if getattr(asset, 'vendor', None):
        score += 10
    if getattr(asset, 'os_guess', None):
        score += 10
    if matched:
        score += 25
    if score >= 80:
        return 'high', min(score, 100)
    if score >= 45:
        return 'medium', min(score, 100)
    return 'low', min(score, 100)


def _recommended_action(asset: NetworkDiscoveredAsset, is_managed: bool, agent_state: str) -> str:
    risk = str(_risk_level_text(asset) or 'INFO').upper()
    cves = int(getattr(asset, 'cve_count', 0) or 0)
    if not is_managed:
        if risk in {'CRITICAL', 'HIGH'} or cves > 0:
            return 'install_agent_and_investigate'
        return 'install_agent'
    if agent_state in {'offline', 'stale'}:
        return 'restore_agent_connectivity'
    if risk == 'CRITICAL':
        return 'immediate_containment_and_patch'
    if risk == 'HIGH' or cves > 0:
        return 'prioritise_patching'
    return 'monitor_only'


def _build_managed_indexes(db: Session, tenant_id: str) -> dict[str, Any]:
    canonical_assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    agents_by_id = {a.agent_id: a for a in db.query(Agent).filter(Agent.tenant_id == tenant_id).all()}

    ip_map: dict[str, list[CanonicalAsset]] = defaultdict(list)
    mac_map: dict[str, list[CanonicalAsset]] = defaultdict(list)
    name_map: dict[str, list[CanonicalAsset]] = defaultdict(list)
    agent_name_map: dict[str, list[Agent]] = defaultdict(list)

    for ca in canonical_assets:
        for raw_ip in (ca.ips or []):
            ip = _safe_ip_text(raw_ip)
            if ip:
                ip_map[ip].append(ca)
        for raw_mac in (ca.macs or []):
            mac = _norm_mac(raw_mac)
            if mac:
                mac_map[mac].append(ca)
        for raw_name in (ca.hostname, ca.fqdn):
            nm = _norm_text(raw_name)
            if nm:
                name_map[nm].append(ca)
                if '.' in nm:
                    name_map[nm.split('.', 1)[0]].append(ca)

    for ag in agents_by_id.values():
        nm = _norm_text(ag.hostname)
        if nm:
            agent_name_map[nm].append(ag)
            if '.' in nm:
                agent_name_map[nm.split('.', 1)[0]].append(ag)

    return {
        'canonical_assets': canonical_assets,
        'agents_by_id': agents_by_id,
        'ip_map': ip_map,
        'mac_map': mac_map,
        'name_map': name_map,
        'agent_name_map': agent_name_map,
    }


def _match_managed_asset(asset: NetworkDiscoveredAsset, indexes: dict[str, Any]) -> dict[str, Any] | None:
    candidates: dict[int, dict[str, Any]] = {}

    def ensure_candidate(ca: CanonicalAsset) -> dict[str, Any]:
        key = int(ca.id)
        if key not in candidates:
            candidates[key] = {'canonical': ca, 'score': 0, 'reasons': []}
        return candidates[key]

    ip = _safe_ip_text(getattr(asset, 'ip_address', None))
    if ip:
        for ca in indexes['ip_map'].get(ip, []):
            item = ensure_candidate(ca)
            item['score'] += 70
            item['reasons'].append('ip')

    mac = _norm_mac(getattr(asset, 'mac_address', None))
    if mac:
        for ca in indexes['mac_map'].get(mac, []):
            item = ensure_candidate(ca)
            item['score'] += 95
            item['reasons'].append('mac')

    for raw_name in (getattr(asset, 'hostname', None), getattr(asset, 'netbios_name', None), getattr(asset, 'mdns_name', None), getattr(asset, 'fqdn', None)):
        nm = _norm_text(raw_name)
        if not nm:
            continue
        keys = [nm]
        if '.' in nm:
            keys.append(nm.split('.', 1)[0])
        for key in keys:
            for ca in indexes['name_map'].get(key, []):
                item = ensure_candidate(ca)
                item['score'] += 45
                item['reasons'].append('hostname')

    if candidates:
        best = max(candidates.values(), key=lambda item: item['score'])
        canonical = best['canonical']
        agent = indexes['agents_by_id'].get(canonical.agent_id)
        return {
            'canonical': canonical,
            'agent': agent,
            'score': best['score'],
            'reasons': sorted(set(best['reasons'])),
        }

    for raw_name in (getattr(asset, 'hostname', None), getattr(asset, 'netbios_name', None), getattr(asset, 'mdns_name', None), getattr(asset, 'fqdn', None)):
        nm = _norm_text(raw_name)
        if not nm:
            continue
        keys = [nm]
        if '.' in nm:
            keys.append(nm.split('.', 1)[0])
        for key in keys:
            agents = indexes['agent_name_map'].get(key, [])
            if agents:
                agent = agents[0]
                return {'canonical': None, 'agent': agent, 'score': 45, 'reasons': ['agent_hostname']}
    return None


def _classification_reasons(asset: NetworkDiscoveredAsset, matched: dict[str, Any] | None = None) -> list[str]:
    reasons: list[str] = []
    if getattr(asset, 'device_family', None) or getattr(asset, 'device_type', None):
        reasons.append(f"classified as {(getattr(asset, 'device_family', None) or getattr(asset, 'device_type', None))} from observed vendor/ports")
    if getattr(asset, 'vendor', None):
        reasons.append(f"vendor identified as {asset.vendor}")
    if getattr(asset, 'os_guess', None):
        reasons.append(f"OS fingerprint suggests {asset.os_guess}")
    ports = _port_numbers(getattr(asset, 'open_ports', None) or [])
    if ports:
        reasons.append(f"open ports observed: {', '.join(str(p) for p in ports[:6])}")
    if matched and matched.get('reasons'):
        reasons.append(f"matched to managed inventory by {', '.join(matched['reasons'])}")
    if getattr(asset, 'cve_count', 0):
        reasons.append(f"{int(asset.cve_count)} CVE(s) linked to this asset")
    if getattr(asset, 'risk_factors', None):
        factors = getattr(asset, 'risk_factors', None) or []
        reasons.append(f"risk factors: {', '.join(str(x) for x in factors[:4])}")
    return reasons


def _network_asset_summary_row(asset: NetworkDiscoveredAsset, managed_match: dict[str, Any] | None = None) -> dict[str, Any]:
    canonical = (managed_match or {}).get('canonical')
    agent = (managed_match or {}).get('agent')
    hostname = asset.hostname or getattr(asset, 'netbios_name', None) or getattr(asset, 'mdns_name', None) or (canonical.hostname if canonical else None) or (agent.hostname if agent else None)
    open_ports = asset.open_ports or []
    services = getattr(asset, 'services', []) or []
    port_numbers = _port_numbers(open_ports)
    service_names = _service_names(services)
    is_managed = bool(canonical or agent)
    agent_state = _agent_state(agent, canonical)
    discovery_quality, confidence_score = _discovery_quality(asset, matched=is_managed)
    hostname_sources = _hostname_sources(asset, canonical, agent)
    classification_reasons = _classification_reasons(asset, managed_match)
    meta = getattr(asset, 'raw_metadata_json', None) or {}
    return {
        'id': asset.id,
        'ip_address': asset.ip_address,
        'hostname': asset.hostname or (canonical.hostname if canonical else None) or (agent.hostname if agent else None),
        'netbios_name': getattr(asset, 'netbios_name', None),
        'mdns_name': getattr(asset, 'mdns_name', None),
        'fqdn': getattr(asset, 'fqdn', None) or (canonical.fqdn if canonical else None),
        'display_name': hostname or asset.ip_address,
        'mac_address': asset.mac_address or ((canonical.macs or [None])[0] if canonical and canonical.macs else None),
        'vendor': asset.vendor,
        'os_guess': asset.os_guess or (canonical.os_family if canonical else None),
        'os': asset.os_guess or (canonical.os_family if canonical else None),
        'os_family': canonical.os_family if canonical else None,
        'os_version': asset.os_version or (canonical.os_version if canonical else None),
        'device_type': asset.device_type,
        'device_family': getattr(asset, 'device_family', None),
        'risk_score': getattr(asset, 'risk_score', None),
        'risk_level': _risk_level_text(asset),
        'risk_hint': getattr(asset, 'risk_hint', None),
        'risk_factors': getattr(asset, 'risk_factors', []) or [],
        'open_ports': open_ports,
        'ports_display': port_numbers,
        'open_port_count': len(port_numbers),
        'services': services,
        'services_display': service_names,
        'service_count': len(service_names),
        'http_headers': getattr(asset, 'http_headers', None),
        'tls_info': getattr(asset, 'tls_info', None),
        'smb_info': getattr(asset, 'smb_info', None),
        'ce_issues': getattr(asset, 'ce_issues', []) or [],
        'managed': is_managed,
        'is_managed': is_managed,
        'agent_installed': is_managed,
        'agent_state': agent_state,
        'agent_id': (agent.agent_id if agent else (canonical.agent_id if canonical else None)),
        'management_source': 'agent' if agent else ('canonical_asset' if canonical else 'scan_only'),
        'management_match_reasons': (managed_match or {}).get('reasons', []),
        'management_match_score': (managed_match or {}).get('score', 0),
        'is_rogue': getattr(asset, 'is_rogue', False) and not is_managed,
        'is_internet_facing': getattr(asset, 'is_internet_facing', False),
        'asset_confidence': getattr(asset, 'asset_confidence', None) or meta.get('asset_confidence') or 'observed_host',
        'confidence_score': confidence_score,
        'discovery_quality': discovery_quality,
        'classification_reasons': classification_reasons,
        'hostname_sources': hostname_sources,
        'recommended_action': _recommended_action(asset, is_managed, agent_state),
        'cve_count': getattr(asset, 'cve_count', 0),
        'critical_cve_count': getattr(asset, 'critical_cve_count', 0),
        'high_cve_count': getattr(asset, 'high_cve_count', 0),
        'medium_cve_count': getattr(asset, 'medium_cve_count', 0),
        'first_seen': getattr(asset, 'first_seen', None),
        'last_seen': getattr(asset, 'last_seen', None),
        'scan_job_id': asset.scan_job_id,
        'canonical_hostname': canonical.hostname if canonical else None,
        'canonical_fqdn': canonical.fqdn if canonical else None,
        'canonical_ips': canonical.ips if canonical else [],
        'canonical_macs': canonical.macs if canonical else [],
        'last_snapshot_epoch': canonical.last_snapshot_epoch if canonical else None,
        'raw_metadata_json': meta,
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
    rows = sorted(rows, key=lambda r: _sort_ip_text(r.ip_address))
    managed_indexes = _build_managed_indexes(db, auth.tenant_id)
    items = [_network_asset_summary_row(r, _match_managed_asset(r, managed_indexes)) for r in rows]

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
