from __future__ import annotations

"""
NVD (National Vulnerability Database) CVE correlation service.

Architecture — immutable scan history model:
  vuln_scan_runs          ← one immutable row per scan execution
  vulnerability_findings  ← one immutable row per CVE per scan run (linked via scan_run_id)
  vuln_annotations        ← user actions — separate mutable concern

Two sources are scanned in every run:
  1. Agent-managed devices  — CanonicalSoftware rows (exact software inventory)
  2. Network-discovered     — NetworkDiscoveredAsset rows (agentless: services,
                              vendor, OS fingerprint — printers, routers, switches, TVs)

NVD API v2 docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits: 5 req/30s without API key; 50 req/30s with NVD_API_KEY env var.
"""

import logging
import os
import time
from typing import Any

import requests
from sqlalchemy.orm import Session

from models.network import NetworkDiscoveredAsset
from models.telemetry import CanonicalSoftware, VulnerabilityFinding
from models.vuln_scan import VulnAnnotation, VulnScanRun

import asyncio as _asyncio
from integrations.dispatcher import dispatch_critical_finding as _dispatch_cve

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_TTL_SECONDS = int(os.getenv("NVD_CACHE_TTL", str(24 * 3600)))
_NVD_API_KEY = os.getenv("NVD_API_KEY")
_CACHE_MAX_ENTRIES = int(os.getenv("NVD_CACHE_MAX_ENTRIES", "2000"))

_cache: dict[tuple[str, str], tuple[int, list[dict[str, Any]]]] = {}

_IGNORED_SERVICE_PRODUCTS = frozenset({
    "", "unknown", "tcpwrapped", "filtered", "closed", "generic",
})

# Map internal device_type labels → NVD-searchable product category terms
_DEVICE_TYPE_TO_NVD = {
    "router":               "router",
    "server_or_web_device": "router",      # most likely a router/gateway on LAN
    "windows_host":         "Windows",
    "linux_host":           "Linux",
    "mobile_device":        "Android",     # most common; refined below if Apple detected
    "printer":              "printer firmware",
    "network_switch":       "switch firmware",
    "access_point":         "access point firmware",
    "firewall":             "firewall firmware",
    "nas":                  "NAS firmware",
    "voip":                 "VoIP",
    "camera":               "IP camera firmware",
    "iot":                  "firmware",
    "unknown":              None,          # skip — no useful NVD keyword
}

# Vendors whose OUI label contains noise — strip to clean searchable name
_VENDOR_CLEAN = {
    "Liteon (Laptop)":              "Liteon",
    "Murata (IoT)":                 None,   # Murata makes chips, not products — skip
    "Mobile Device (Randomised MAC)": None, # Not a real vendor name
    "TP-Link":                      "TP-Link",
    "Gigabyte":                     "Gigabyte",
    "Intel":                        "Intel",
}


# ---------------------------------------------------------------------------
# NVD fetch helpers
# ---------------------------------------------------------------------------

def _build_headers() -> dict[str, str]:
    h = {"Accept": "application/json"}
    if _NVD_API_KEY:
        h["apiKey"] = _NVD_API_KEY
    return h


def _fetch_cves_for_keyword(keyword: str, version: str | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": 20}
    if version:
        params["virtualMatchString"] = (
            f"cpe:2.3:a:*:{keyword.lower().replace(' ', '_')}:{version}:*"
        )
    try:
        resp = requests.get(_NVD_BASE, params=params, headers=_build_headers(), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.warning("NVD fetch failed for '%s': %s", keyword, exc)
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
                break
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:300]
                break
        if cve_id:
            results.append({
                "cve_id": cve_id,
                "severity": severity.upper(),
                "cvss_score": cvss_score,
                "description": description,
                "published": published,
            })
    return results


def lookup_cves(name: str, version: str | None) -> list[dict[str, Any]]:
    cache_key = (name.lower()[:80], (version or "").lower()[:40])
    now = int(time.time())
    cached = _cache.get(cache_key)
    if cached and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]
    cves = _fetch_cves_for_keyword(name, version)
    if len(_cache) >= _CACHE_MAX_ENTRIES:
        oldest = sorted(_cache, key=lambda k: _cache[k][0])
        for old_key in oldest[: max(1, _CACHE_MAX_ENTRIES // 10)]:
            _cache.pop(old_key, None)
    _cache[cache_key] = (now, cves)
    return cves


# ---------------------------------------------------------------------------
# Keyword extraction — network assets (agentless)
# ---------------------------------------------------------------------------

def _keywords_for_network_asset(asset: NetworkDiscoveredAsset) -> list[tuple[str, str | None]]:
    """
    Build a prioritised list of (keyword, version) NVD search terms for a
    network-discovered asset without a software agent.

    Priority:
      1. Service banners  — specific products on open ports (OpenSSH, Apache, etc.)
      2. Vendor + model   — TP-Link Archer, HP LaserJet M404
      3. Vendor + NVD category — TP-Link router, HP printer firmware
      4. Clean vendor alone — TP-Link, Gigabyte
      5. OS fingerprint   — Windows 10, pfSense, Linux
    """
    terms: list[tuple[str, str | None]] = []
    seen: set[str] = set()

    def _add(keyword: str, version: str | None = None) -> None:
        k = keyword.strip().lower()
        if k and k not in seen and len(k) > 2 and k not in _IGNORED_SERVICE_PRODUCTS:
            seen.add(k)
            terms.append((keyword.strip(), version or None))

    # 1. Services — most specific signal (product + version from nmap -sV)
    for svc in (asset.services or []):
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip() or None
        if product and product.lower() not in _IGNORED_SERVICE_PRODUCTS:
            _add(product, version)

    # Resolve clean vendor name (strip OUI noise like "(Laptop)", "(IoT)" etc.)
    raw_vendor = (asset.vendor or "").strip()
    clean_vendor: str | None
    if raw_vendor in _VENDOR_CLEAN:
        clean_vendor = _VENDOR_CLEAN[raw_vendor]
    elif raw_vendor:
        # Strip anything in parentheses e.g. "Liteon (Laptop)" → "Liteon"
        import re
        clean_vendor = re.sub(r"\s*\(.*?\)", "", raw_vendor).strip() or None
    else:
        clean_vendor = None

    # Resolve NVD category from device_type
    dtype = (asset.device_type or "unknown").lower()
    nvd_category = _DEVICE_TYPE_TO_NVD.get(dtype)

    # 2. Vendor + model (most precise hardware match)
    if clean_vendor and asset.device_model:
        _add(f"{clean_vendor} {asset.device_model}")
    elif clean_vendor and asset.device_family:
        _add(f"{clean_vendor} {asset.device_family}")

    # 3. Vendor + NVD category (e.g. "TP-Link router", "HP printer firmware")
    if clean_vendor and nvd_category:
        _add(f"{clean_vendor} {nvd_category}")

    # 4. Clean vendor alone (catches firmware CVEs indexed only by brand)
    if clean_vendor:
        _add(clean_vendor)

    # 5. OS fingerprint
    if asset.os_guess:
        _add(asset.os_guess, asset.os_version or None)

    return terms[:8]  # cap at 8 NVD queries per device


def _network_asset_id(asset: NetworkDiscoveredAsset) -> str:
    """Synthetic agent_id for network assets — prefixed with 'net:' for easy identification."""
    return f"net:{asset.ip_address}"


def _network_asset_label(asset: NetworkDiscoveredAsset) -> str:
    """Human-readable label used as software_name when no specific product is known."""
    parts = []
    if asset.vendor:
        parts.append(asset.vendor)
    if asset.device_type:
        parts.append(asset.device_type)
    return (" ".join(parts) or "Network Device") + f" ({asset.ip_address})"


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------

def _add_finding(db: Session, *, scan_run_id: int, tenant_id: str,
                 agent_id: str, software_name: str, software_version: str | None,
                 cve: dict, scan_epoch: int, source: str) -> tuple[int, int, int, int]:
    """Insert one immutable VulnerabilityFinding. Returns (crit, high, med, low) increment."""
    sev = cve["severity"]
    db.add(VulnerabilityFinding(
        scan_run_id=scan_run_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        software_name=software_name,
        software_version=software_version,
        cve_id=cve["cve_id"],
        severity=sev,
        cvss_score=cve["cvss_score"],
        description=cve["description"],
        published=cve["published"],
        scan_epoch=scan_epoch,
        status="open",
        source=source,
    ))
    return (
        1 if sev == "CRITICAL" else 0,
        1 if sev == "HIGH" else 0,
        1 if sev == "MEDIUM" else 0,
        1 if sev not in ("CRITICAL", "HIGH", "MEDIUM") else 0,
    )


def run_vuln_scan_for_tenant(db: Session, tenant_id: str) -> dict[str, Any]:
    """
    Scan all assets for a tenant against NVD — agent-managed AND agentless.

    Agent devices:   full software inventory via CanonicalSoftware
    Network devices: OS/service fingerprints via NetworkDiscoveredAsset
                     (printers, routers, switches, TVs, APs — no agent needed)
    """
    scan_epoch = int(time.time())

    scan_run = VulnScanRun(tenant_id=tenant_id, scan_epoch=scan_epoch, status="running")
    db.add(scan_run)
    db.flush()
    scan_run_id = scan_run.id

    total_cves = critical = high = medium = low = 0
    scanned_agent: set[str] = set()
    scanned_network: set[int] = set()

    # ------------------------------------------------------------------
    # SOURCE 1: Agent-managed software inventory
    # ------------------------------------------------------------------
    software_rows = (
        db.query(CanonicalSoftware)
        .filter(CanonicalSoftware.tenant_id == tenant_id)
        .all()
    )

    for row in software_rows:
        if not row.name:
            continue
        dedup_key = f"{row.name}|{row.version or ''}"
        if dedup_key in scanned_agent:
            continue
        scanned_agent.add(dedup_key)
        time.sleep(0.7 if not _NVD_API_KEY else 0.07)

        for cve in lookup_cves(row.name, row.version):
            total_cves += 1
            c, h, m, lo = _add_finding(
                db, scan_run_id=scan_run_id, tenant_id=tenant_id,
                agent_id=row.agent_id, software_name=row.name,
                software_version=row.version, cve=cve,
                scan_epoch=scan_epoch, source="agent",
            )
            critical += c; high += h; medium += m; low += lo

    # ------------------------------------------------------------------
    # SOURCE 2: Network-discovered assets (agentless)
    # ------------------------------------------------------------------
    network_assets = (
        db.query(NetworkDiscoveredAsset)
        .filter(
            NetworkDiscoveredAsset.tenant_id == tenant_id,
            NetworkDiscoveredAsset.is_active == True,
        )
        .all()
    )

    for asset in network_assets:
        keywords = _keywords_for_network_asset(asset)
        if not keywords:
            continue  # ping-only host, no fingerprint data

        scanned_network.add(asset.id)
        asset_id_str = _network_asset_id(asset)

        for keyword, version in keywords:
            dedup_key = f"{keyword}|{version or ''}"
            # Use cache if already queried from agent source — no extra NVD call
            if dedup_key in scanned_agent:
                cves = lookup_cves(keyword, version)
            else:
                time.sleep(0.7 if not _NVD_API_KEY else 0.07)
                cves = lookup_cves(keyword, version)
                scanned_agent.add(dedup_key)  # mark as queried

            for cve in cves:
                total_cves += 1
                c, h, m, lo = _add_finding(
                    db, scan_run_id=scan_run_id, tenant_id=tenant_id,
                    agent_id=asset_id_str, software_name=keyword,
                    software_version=version, cve=cve,
                    scan_epoch=scan_epoch, source="network",
                )
                critical += c; high += h; medium += m; low += lo

    # ------------------------------------------------------------------
    # Guard: 0 CVEs on non-empty inventory = rate-limited
    # ------------------------------------------------------------------
    total_packages = len(software_rows) + len(network_assets)
    packages_scanned = len(scanned_agent) + len(scanned_network)

    if total_cves == 0 and packages_scanned > 0:
        scan_run.status = "rate_limited"
        scan_run.warning = (
            "0 CVEs returned — NVD may be rate-limiting. "
            "Wait 60s and retry, or verify NVD_API_KEY in .env."
        )
        scan_run.packages_scanned = packages_scanned
        scan_run.total_packages = total_packages
        db.commit()
        return {
            "scan_run_id": scan_run_id, "tenant_id": tenant_id,
            "packages_scanned": packages_scanned,
            "total_packages_in_inventory": total_packages,
            "agent_packages_scanned": len(scanned_agent),
            "network_assets_scanned": len(scanned_network),
            "total_cves_found": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "scan_epoch": scan_epoch, "warning": scan_run.warning,
        }

    scan_run.packages_scanned = packages_scanned
    scan_run.total_packages = total_packages
    scan_run.total_cves = total_cves
    scan_run.critical_count = critical
    scan_run.high_count = high
    scan_run.medium_count = medium
    scan_run.low_count = low
    scan_run.status = "complete"
    db.commit()

    try:
        crit = (db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.scan_run_id == scan_run_id,
                    VulnerabilityFinding.severity.in_(["CRITICAL","HIGH"]))
            .order_by(VulnerabilityFinding.cvss_score.desc().nullslast())
            .limit(50).all())
        for _f in crit:
            _asyncio.run(_dispatch_cve(db, tenant_id, {
                "event_type": "cve_found",
                "severity": 9 if _f.severity == "CRITICAL" else 7,
                "asset_name": _f.agent_id,
                "cve_id": _f.cve_id,
                "cvss_score": _f.cvss_score,
                "cvss_severity": _f.severity,
                "description": (_f.description or "") [:200],
                "remediation_class": "approval_required" if _f.severity == "CRITICAL" else "auto_safe",
                "ce_control": "A4",
                "ce_compliant": False,
                "tenant_id": tenant_id,
                "software_name": _f.software_name,
                "software_version": _f.software_version,
            }))
    except Exception as _exc:
        logger.warning("Integration dispatch failed: %s", _exc)

    return {
        "scan_run_id": scan_run_id, "tenant_id": tenant_id,
        "packages_scanned": packages_scanned,
        "total_packages_in_inventory": total_packages,
        "agent_packages_scanned": len(scanned_agent),
        "network_assets_scanned": len(scanned_network),
        "total_cves_found": total_cves,
        "critical": critical, "high": high, "medium": medium, "low": low,
        "scan_epoch": scan_epoch,
    }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_latest_scan_run(db: Session, tenant_id: str) -> VulnScanRun | None:
    return (
        db.query(VulnScanRun)
        .filter(VulnScanRun.tenant_id == tenant_id, VulnScanRun.status == "complete")
        .order_by(VulnScanRun.scan_epoch.desc())
        .first()
    )


def get_scan_runs(db: Session, tenant_id: str, limit: int = 20) -> list[VulnScanRun]:
    return (
        db.query(VulnScanRun)
        .filter(VulnScanRun.tenant_id == tenant_id)
        .order_by(VulnScanRun.scan_epoch.desc())
        .limit(limit)
        .all()
    )


def get_vuln_summary(db: Session, tenant_id: str) -> dict[str, Any]:
    latest = get_latest_scan_run(db, tenant_id)
    if not latest:
        return {
            "tenant_id": tenant_id, "total_open_cves": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "affected_assets": 0, "last_scan_epoch": None, "last_scan_run_id": None,
        }
    findings = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.scan_run_id == latest.id)
        .all()
    )
    annotations = {
        (a.cve_id, a.agent_id): a.status
        for a in db.query(VulnAnnotation).filter(VulnAnnotation.tenant_id == tenant_id).all()
    }
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assets: set[str] = set()
    open_total = 0
    for f in findings:
        if annotations.get((f.cve_id, f.agent_id)) in ("resolved", "accepted_risk", "false_positive"):
            continue
        open_total += 1
        counts[f.severity] = counts.get(f.severity, 0) + 1
        assets.add(f.agent_id)
    return {
        "tenant_id": tenant_id, "total_open_cves": open_total,
        "critical": counts["CRITICAL"], "high": counts["HIGH"],
        "medium": counts["MEDIUM"], "low": counts["LOW"],
        "affected_assets": len(assets),
        "last_scan_epoch": latest.scan_epoch, "last_scan_run_id": latest.id,
    }


def get_latest_findings_with_annotations(
    db: Session, tenant_id: str,
    severity: str | None = None, status_filter: str = "open",
    agent_id: str | None = None, source: str | None = None,
    limit: int = 200, offset: int = 0,
) -> list[dict[str, Any]]:
    latest = get_latest_scan_run(db, tenant_id)
    if not latest:
        return []
    annotations: dict[tuple[str, str], VulnAnnotation] = {
        (a.cve_id, a.agent_id): a
        for a in db.query(VulnAnnotation).filter(VulnAnnotation.tenant_id == tenant_id).all()
    }
    query = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.scan_run_id == latest.id)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity.upper())
    if agent_id:
        query = query.filter(VulnerabilityFinding.agent_id == agent_id)
    if source:
        query = query.filter(VulnerabilityFinding.source == source)
    findings = query.order_by(VulnerabilityFinding.cvss_score.desc().nullslast()).all()

    SUPPRESSED = {"resolved", "accepted_risk", "false_positive"}
    result = []
    for f in findings:
        ann = annotations.get((f.cve_id, f.agent_id))
        ann_status = ann.status if ann else "open"
        if status_filter == "open" and ann_status in SUPPRESSED:
            continue
        if status_filter != "open" and ann_status != status_filter:
            continue
        result.append({
            "id": f.id, "scan_run_id": f.scan_run_id,
            "tenant_id": f.tenant_id, "agent_id": f.agent_id,
            "source": getattr(f, "source", "agent"),
            "software_name": f.software_name, "software_version": f.software_version,
            "cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
            "description": f.description, "published": f.published,
            "status": ann_status,
            "annotation_id": ann.id if ann else None,
            "annotation_note": ann.note if ann else None,
            "annotated_by": ann.annotated_by if ann else None,
            "annotated_epoch": ann.annotated_epoch if ann else None,
        })
    return result[offset: offset + limit]


def get_scan_run_findings(db: Session, tenant_id: str, scan_run_id: int) -> list[VulnerabilityFinding]:
    return (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.tenant_id == tenant_id, VulnerabilityFinding.scan_run_id == scan_run_id)
        .order_by(VulnerabilityFinding.cvss_score.desc().nullslast())
        .all()
    )


def create_or_update_annotation(
    db: Session, tenant_id: str, cve_id: str,
    agent_id: str | None, software_name: str | None, status: str,
    annotated_by: str | None = None, note: str | None = None,
) -> VulnAnnotation:
    now = int(time.time())
    existing = (
        db.query(VulnAnnotation)
        .filter(VulnAnnotation.tenant_id == tenant_id, VulnAnnotation.cve_id == cve_id, VulnAnnotation.agent_id == agent_id)
        .first()
    )
    if existing:
        existing.status = status; existing.note = note
        existing.annotated_by = annotated_by; existing.annotated_epoch = now
        db.commit(); return existing
    ann = VulnAnnotation(
        tenant_id=tenant_id, cve_id=cve_id, agent_id=agent_id,
        software_name=software_name, status=status,
        annotated_by=annotated_by, annotated_epoch=now, note=note,
    )
    db.add(ann); db.commit(); return ann


def get_all_annotations(db: Session, tenant_id: str, limit: int = 500) -> list[VulnAnnotation]:
    return (
        db.query(VulnAnnotation)
        .filter(VulnAnnotation.tenant_id == tenant_id)
        .order_by(VulnAnnotation.annotated_epoch.desc())
        .limit(limit).all()
    )
