from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from models.agent import Agent
from models.asset import CanonicalAsset
from models.darkweb import DarkWebFinding
from models.network import NetworkDiscoveredAsset
from models.telemetry import CanonicalSoftware, LocalFindingsEvent, VulnerabilityFinding
from services.compliance_service import assess_asset
from services.risk_service import compute_asset_risk


@dataclass
class ManagedContext:
    asset: CanonicalAsset
    agent: Agent | None
    software: list[CanonicalSoftware]
    open_vulns: list[VulnerabilityFinding]
    local_findings: list[dict[str, Any]]
    compliance_score: float | None
    compliance_status: str | None


def _norm(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().lower()
    return value or None


def _norm_mac(value: str | None) -> str | None:
    value = _norm(value)
    if not value:
        return None
    return re.sub(r"[^0-9a-f]", "", value)


def _safe_ips(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        try:
            out.append(str(ipaddress.ip_address(str(value).strip())))
        except Exception:
            continue
    return sorted(set(out))


def _extract_domain(*values: str | None) -> str | None:
    for value in values:
        item = _norm(value)
        if not item:
            continue
        if "@" in item:
            return item.split("@", 1)[1]
        if "." in item:
            parts = item.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:]) if len(parts[-1]) <= 3 else ".".join(parts[-2:])
    return None


def _friendly_uid(*parts: str) -> str:
    digest = hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]
    return f"asset-{digest}"


def _managed_contexts(db: Session, tenant_id: str) -> dict[str, ManagedContext]:
    assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    agents = {
        row.agent_id: row
        for row in db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
    }

    software_by_agent: dict[str, list[CanonicalSoftware]] = defaultdict(list)
    for row in db.query(CanonicalSoftware).filter(CanonicalSoftware.tenant_id == tenant_id).limit(50).all():
        software_by_agent[row.agent_id].append(row)

    vulns_by_agent: dict[str, list[VulnerabilityFinding]] = defaultdict(list)
    for row in db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.tenant_id == tenant_id,
        VulnerabilityFinding.status == "open",
    ).limit(200).all():
        vulns_by_agent[row.agent_id].append(row)

    findings_by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    local_rows = (
        db.query(LocalFindingsEvent)
        .filter(LocalFindingsEvent.tenant_id == tenant_id)
        .order_by(LocalFindingsEvent.id.desc())
        .limit(20)
        .all()
    )
    seen_agents: set[str] = set()
    for row in local_rows:
        if row.agent_id in seen_agents:
            continue
        payload = row.payload_json or {}
        findings_by_agent[row.agent_id] = payload.get("findings", []) or []
        seen_agents.add(row.agent_id)

    contexts: dict[str, ManagedContext] = {}
    _compliance_memo: dict[str, Any] = {}

    for asset in assets:
        contexts[asset.agent_id] = ManagedContext(
            asset=asset,
            agent=agents.get(asset.agent_id),
            software=software_by_agent.get(asset.agent_id, []),
            open_vulns=vulns_by_agent.get(asset.agent_id, []),
            local_findings=findings_by_agent.get(asset.agent_id, []),
            compliance_score=None,
            compliance_status=None,
        )
    return contexts


def _network_match_score(managed: ManagedContext, network: NetworkDiscoveredAsset) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    managed_ips = set(_safe_ips(managed.asset.ips))
    network_ip = _safe_ips([network.ip_address])
    if managed_ips and network_ip and network_ip[0] in managed_ips:
        score += 70
        reasons.append("ip")

    managed_macs = {_norm_mac(v) for v in (managed.asset.macs or []) if _norm_mac(v)}
    network_mac = _norm_mac(network.mac_address)
    if managed_macs and network_mac and network_mac in managed_macs:
        score += 95
        reasons.append("mac")

    managed_names = {_norm(managed.asset.hostname), _norm(managed.asset.fqdn)} - {None}
    network_names = {_norm(network.hostname)} - {None}
    if managed_names and network_names and managed_names.intersection(network_names):
        score += 45
        reasons.append("hostname")

    if network.hostname and managed.asset.fqdn and _norm(network.hostname) == _norm(managed.asset.fqdn.split(".")[0]):
        score += 20
        reasons.append("short-hostname")

    return score, reasons


def _darkweb_links_for_asset(unified_asset: dict[str, Any], findings: list[DarkWebFinding]) -> list[dict[str, Any]]:
    hostname_tokens = {
        _norm(unified_asset.get("hostname")),
        _norm(unified_asset.get("fqdn")),
    } - {None}
    domain_tokens = {_norm(unified_asset.get("domain")), _extract_domain(unified_asset.get("fqdn"))} - {None}
    ip_tokens = set(_safe_ips(unified_asset.get("ip_addresses") or []))
    source_tokens = {_norm(s) for s in unified_asset.get("source_types", []) if _norm(s)}

    linked: list[dict[str, Any]] = []
    for row in findings:
        value = _norm(row.matched_value) or ""
        strategies: list[str] = []
        score = 0

        if row.finding_type == "domain":
            if value in domain_tokens:
                score += 80
                strategies.append("domain")
        elif row.finding_type == "email":
            if "@" in value:
                local, domain = value.split("@", 1)
                if domain in domain_tokens:
                    score += 45
                    strategies.append("email-domain")
                if local in hostname_tokens:
                    score += 35
                    strategies.append("email-localpart-hostname")
        elif row.finding_type == "keyword":
            if value and (
                value in hostname_tokens
                or value in domain_tokens
                or any(value in token for token in hostname_tokens | domain_tokens | source_tokens)
            ):
                score += 55
                strategies.append("keyword")
        elif row.finding_type == "regex":
            haystack = " ".join([*(hostname_tokens or []), *(domain_tokens or []), *ip_tokens])
            try:
                if re.search(value, haystack, re.IGNORECASE):
                    score += 65
                    strategies.append("regex")
            except re.error:
                pass

        metadata = row.raw_metadata_json or {}
        for related_ip in metadata.get("linked_ips", []) or []:
            if related_ip in ip_tokens:
                score += 40
                strategies.append("linked-ip")
        for related_name in metadata.get("linked_hostnames", []) or []:
            if _norm(related_name) in hostname_tokens:
                score += 40
                strategies.append("linked-hostname")
        for related_domain in metadata.get("linked_domains", []) or []:
            if _norm(related_domain) in domain_tokens:
                score += 40
                strategies.append("linked-domain")

        if score >= 45:
            linked.append(
                {
                    "id": row.id,
                    "finding_type": row.finding_type,
                    "matched_value": row.matched_value,
                    "severity": row.severity,
                    "status": row.status,
                    "source": metadata.get("source_name"),
                    "title": metadata.get("title"),
                    "context_snippet": row.context_snippet,
                    "link_score": score,
                    "link_strategies": sorted(set(strategies)),
                }
            )
    linked.sort(key=lambda item: (item["link_score"], item["severity"]), reverse=True)
    return linked


def _correlate_findings_metadata(db: Session, tenant_id: str) -> None:
    managed = _managed_contexts(db, tenant_id)
    network_assets = db.query(NetworkDiscoveredAsset).filter(NetworkDiscoveredAsset.tenant_id == tenant_id).all()
    findings = db.query(DarkWebFinding).filter(DarkWebFinding.tenant_id == tenant_id).all()

    managed_domains = defaultdict(list)
    managed_names = defaultdict(list)
    managed_ips = defaultdict(list)
    for ctx in managed.values():
        if ctx.asset.domain:
            managed_domains[_norm(ctx.asset.domain)].append(ctx.asset)
        if ctx.asset.hostname:
            managed_names[_norm(ctx.asset.hostname)].append(ctx.asset)
        if ctx.asset.fqdn:
            managed_names[_norm(ctx.asset.fqdn)].append(ctx.asset)
        for ip in _safe_ips(ctx.asset.ips):
            managed_ips[ip].append(ctx.asset)

    network_names = defaultdict(list)
    network_ips = defaultdict(list)
    for asset in network_assets:
        if asset.hostname:
            network_names[_norm(asset.hostname)].append(asset)
        network_ips[asset.ip_address].append(asset)

    for row in findings:
        value = _norm(row.matched_value) or ""
        linked_hostnames: set[str] = set()
        linked_domains: set[str] = set()
        linked_ips: set[str] = set()
        linked_agent_ids: set[str] = set()
        strategies: set[str] = set()

        if row.finding_type == "email" and "@" in value:
            local, domain = value.split("@", 1)
            for asset in managed_domains.get(domain, []):
                linked_agent_ids.add(asset.agent_id)
                if asset.hostname:
                    linked_hostnames.add(asset.hostname)
                linked_domains.add(domain)
                strategies.add("email-domain")
            for asset in managed_names.get(local, []):
                linked_agent_ids.add(asset.agent_id)
                if asset.hostname:
                    linked_hostnames.add(asset.hostname)
                strategies.add("email-localpart-hostname")
        elif row.finding_type == "domain":
            for asset in managed_domains.get(value, []):
                linked_agent_ids.add(asset.agent_id)
                if asset.hostname:
                    linked_hostnames.add(asset.hostname)
                linked_domains.add(value)
                strategies.add("domain")
        else:
            for asset in managed_names.get(value, []):
                linked_agent_ids.add(asset.agent_id)
                if asset.hostname:
                    linked_hostnames.add(asset.hostname)
                strategies.add("hostname")
            for asset in network_names.get(value, []):
                if asset.hostname:
                    linked_hostnames.add(asset.hostname)
                if asset.ip_address:
                    linked_ips.add(asset.ip_address)
                strategies.add("network-hostname")
            if value in managed_ips:
                for asset in managed_ips[value]:
                    linked_agent_ids.add(asset.agent_id)
                    if asset.hostname:
                        linked_hostnames.add(asset.hostname)
                    linked_ips.add(value)
                    strategies.add("ip")
            if value in network_ips:
                for asset in network_ips[value]:
                    linked_ips.add(asset.ip_address)
                    if asset.hostname:
                        linked_hostnames.add(asset.hostname)
                    strategies.add("network-ip")

        metadata = dict(row.raw_metadata_json or {})
        metadata.update(
            {
                "linked_agent_ids": sorted(linked_agent_ids),
                "linked_hostnames": sorted(linked_hostnames),
                "linked_domains": sorted(linked_domains),
                "linked_ips": sorted(linked_ips),
                "link_strategies": sorted(strategies),
            }
        )
        row.raw_metadata_json = metadata
    db.commit()


_unified_cache: dict = {}
_unified_cache_ts: dict = {}
_CACHE_TTL = 60  # seconds

def list_unified_assets(db: Session, tenant_id: str, refresh_darkweb_metadata: bool = False) -> list[dict[str, Any]]:
    import time
    global _unified_cache, _unified_cache_ts
    cache_key = tenant_id
    now = time.time()
    if not refresh_darkweb_metadata and cache_key in _unified_cache:
        if now - _unified_cache_ts.get(cache_key, 0) < _CACHE_TTL:
            return _unified_cache[cache_key]
    if refresh_darkweb_metadata:
        _correlate_findings_metadata(db, tenant_id)

    managed_contexts = _managed_contexts(db, tenant_id)
    network_assets = db.query(NetworkDiscoveredAsset).filter(NetworkDiscoveredAsset.tenant_id == tenant_id).all()
    darkweb_findings = db.query(DarkWebFinding).filter(
        DarkWebFinding.tenant_id == tenant_id,
        DarkWebFinding.status == "open",
    ).all()

    unified: list[dict[str, Any]] = []
    network_matched_ids: set[int] = set()

    for ctx in managed_contexts.values():
        best_network = None
        best_score = 0
        best_reasons: list[str] = []
        for net in network_assets:
            if net.id in network_matched_ids:
                continue
            score, reasons = _network_match_score(ctx, net)
            if score > best_score:
                best_score = score
                best_reasons = reasons
                best_network = net

        merged_networks: list[NetworkDiscoveredAsset] = []
        if best_network and best_score >= 45:
            merged_networks.append(best_network)
            network_matched_ids.add(best_network.id)

        asset_uid = _friendly_uid(tenant_id, ctx.asset.agent_id, ctx.asset.hostname or "managed")
        ip_addresses = set(_safe_ips(ctx.asset.ips))
        mac_addresses = {_norm_mac(v) for v in (ctx.asset.macs or []) if _norm_mac(v)}
        open_ports: list[dict[str, Any]] = []
        device_types: set[str] = set()
        vendors: set[str] = set()
        risk_hints: set[str] = set()
        source_types = ["agent"]
        for net in merged_networks:
            ip_addresses.update(_safe_ips([net.ip_address]))
            if _norm_mac(net.mac_address):
                mac_addresses.add(_norm_mac(net.mac_address))
            if net.open_ports:
                open_ports.extend(net.open_ports)
            if net.device_type:
                device_types.add(net.device_type)
            if net.vendor:
                vendors.add(net.vendor)
            if net.risk_hint:
                risk_hints.add(net.risk_hint)
            source_types.append("network")

        linked_darkweb = _darkweb_links_for_asset(
            {
                "hostname": ctx.asset.hostname,
                "fqdn": ctx.asset.fqdn,
                "domain": ctx.asset.domain,
                "ip_addresses": sorted(ip_addresses),
                "source_types": source_types,
            },
            darkweb_findings,
        )
        risk = compute_asset_risk(
            managed=True,
            agent_id=ctx.asset.agent_id,
            hostname=ctx.asset.hostname,
            fqdn=ctx.asset.fqdn,
            domain=ctx.asset.domain,
            os_family=ctx.asset.os_family,
            os_version=ctx.asset.os_version,
            ip_addresses=sorted(ip_addresses),
            open_ports=open_ports,
            security_posture=ctx.asset.security_posture_json or {},
            network_risk_hints=sorted(risk_hints),
            vulnerabilities=ctx.open_vulns,
            linked_darkweb_findings=linked_darkweb,
            last_seen_epoch=ctx.agent.last_seen_epoch if ctx.agent and ctx.agent.last_seen_epoch else ctx.asset.last_snapshot_epoch,
            software_count=len(ctx.software),
            compliance_score=None,  # skipped in unified view for performance
            local_findings=ctx.local_findings,
        )
        unified.append(
            {
                "asset_uid": asset_uid,
                "display_name": ctx.asset.hostname or ctx.asset.fqdn or ctx.asset.agent_id,
                "managed": True,
                "source_types": source_types,
                "source_count": len(source_types),
                "match_confidence": best_score,
                "match_reasons": best_reasons,
                "agent_id": ctx.asset.agent_id,
                "network_asset_ids": [row.id for row in merged_networks],
                "hostname": ctx.asset.hostname,
                "fqdn": ctx.asset.fqdn,
                "domain": ctx.asset.domain,
                "os_family": ctx.asset.os_family,
                "os_version": ctx.asset.os_version,
                "device_type": next(iter(device_types), None),
                "vendor": next(iter(vendors), None),
                "ip_addresses": sorted(ip_addresses),
                "mac_addresses": sorted(v for v in mac_addresses if v),
                "software_count": len(ctx.software),
                "open_cve_count": len(ctx.open_vulns),
                "critical_cve_count": sum(1 for row in ctx.open_vulns if (row.severity or "").upper() == "CRITICAL"),
                "linked_darkweb_findings": linked_darkweb,
                "darkweb_findings_count": len(linked_darkweb),
                "last_seen_epoch": ctx.agent.last_seen_epoch if ctx.agent and ctx.agent.last_seen_epoch else ctx.asset.last_snapshot_epoch,
                "compliance_score": ctx.compliance_score,
                "compliance_status": ctx.compliance_status,
                "security_posture": ctx.asset.security_posture_json or {},
                "open_ports": open_ports,
                "local_findings": ctx.local_findings,
                "software": [
                    {"name": row.name, "version": row.version, "publisher": row.publisher, "install_date": row.install_date}
                    for row in sorted(ctx.software, key=lambda item: (item.name or "").lower())
                ],
                "top_risks": risk["top_risks"],
                "risk_breakdown": risk["risk_breakdown"],
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
                "risk_increase_from_darkweb": risk["risk_increase_from_darkweb"],
                "recommended_actions": risk["recommended_actions"],
            }
        )

    for net in network_assets:
        if net.id in network_matched_ids:
            continue
        ip_addresses = _safe_ips([net.ip_address])
        linked_darkweb = _darkweb_links_for_asset(
            {
                "hostname": net.hostname,
                "fqdn": net.hostname,
                "domain": _extract_domain(net.hostname),
                "ip_addresses": ip_addresses,
                "source_types": ["network"],
            },
            darkweb_findings,
        )
        risk = compute_asset_risk(
            managed=False,
            agent_id=None,
            hostname=net.hostname,
            fqdn=net.hostname,
            domain=_extract_domain(net.hostname),
            os_family=net.os_guess,
            os_version=None,
            ip_addresses=ip_addresses,
            open_ports=net.open_ports or [],
            security_posture={},
            network_risk_hints=[net.risk_hint] if net.risk_hint else [],
            vulnerabilities=[],
            linked_darkweb_findings=linked_darkweb,
            last_seen_epoch=None,
            software_count=0,
            compliance_score=None,
            local_findings=[],
        )
        unified.append(
            {
                "asset_uid": _friendly_uid(tenant_id, f"network:{net.id}", net.ip_address),
                "display_name": net.hostname or net.ip_address,
                "managed": False,
                "source_types": ["network"],
                "source_count": 1,
                "match_confidence": 0,
                "match_reasons": [],
                "agent_id": None,
                "network_asset_ids": [net.id],
                "hostname": net.hostname,
                "fqdn": net.hostname,
                "domain": _extract_domain(net.hostname),
                "os_family": net.os_guess,
                "os_version": None,
                "device_type": net.device_type,
                "vendor": net.vendor,
                "ip_addresses": ip_addresses,
                "mac_addresses": [net.mac_address] if net.mac_address else [],
                "software_count": 0,
                "open_cve_count": 0,
                "critical_cve_count": 0,
                "linked_darkweb_findings": linked_darkweb,
                "darkweb_findings_count": len(linked_darkweb),
                "last_seen_epoch": None,
                "compliance_score": None,
                "compliance_status": "NOT_ASSESSED",
                "security_posture": {},
                "open_ports": net.open_ports or [],
                "local_findings": [],
                "software": [],
                "top_risks": risk["top_risks"],
                "risk_breakdown": risk["risk_breakdown"],
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
                "risk_increase_from_darkweb": risk["risk_increase_from_darkweb"],
                "recommended_actions": risk["recommended_actions"],
            }
        )

    unified.sort(
        key=lambda item: (
            item.get("risk_score", 0),
            item.get("darkweb_findings_count", 0),
            0 if item.get("managed") else 1,
            item.get("display_name") or "",
        ),
        reverse=True,
    )
    _unified_cache[cache_key] = unified
    _unified_cache_ts[cache_key] = now
    return unified


def get_unified_asset(db: Session, tenant_id: str, asset_uid: str) -> dict[str, Any] | None:
    for asset in list_unified_assets(db, tenant_id):
        if asset["asset_uid"] == asset_uid:
            return asset
    return None


def build_dashboard_storylines(unified_assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stories: list[dict[str, Any]] = []
    for asset in unified_assets:
        if asset.get("linked_darkweb_findings"):
            finding = asset["linked_darkweb_findings"][0]
            stories.append(
                {
                    "type": "darkweb_to_asset",
                    "title": f"Leaked identity raises {asset['display_name']} risk",
                    "summary": (
                        f"{finding['matched_value']} matched dark web monitoring and was correlated to "
                        f"{asset['display_name']}. Asset risk increased by +{asset['risk_increase_from_darkweb']}."
                    ),
                    "asset_uid": asset["asset_uid"],
                    "asset_name": asset["display_name"],
                    "risk_score": asset["risk_score"],
                    "severity": finding["severity"],
                }
            )
        elif not asset.get("managed") and asset.get("open_ports"):
            sample_port = asset["open_ports"][0].get("port") if asset["open_ports"] else None
            stories.append(
                {
                    "type": "shadow_it",
                    "title": f"Unmanaged asset detected: {asset['display_name']}",
                    "summary": (
                        f"Network discovery found an unmanaged device on {', '.join(asset.get('ip_addresses')[:1]) or 'the network'}"
                        + (f" with port {sample_port} open." if sample_port else ".")
                    ),
                    "asset_uid": asset["asset_uid"],
                    "asset_name": asset["display_name"],
                    "risk_score": asset["risk_score"],
                    "severity": asset["risk_level"],
                }
            )
        if len(stories) >= 3:
            break
    return stories
