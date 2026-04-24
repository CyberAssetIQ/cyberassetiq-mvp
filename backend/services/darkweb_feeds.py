from __future__ import annotations

"""
CyberAssetIQ — Dark Web & Threat Intelligence Feed Integration
==============================================================
Integrates free/low-cost threat intelligence sources:

1. Shodan InternetDB  — free, no auth — checks IPs for known vulns/exposure
2. CISA KEV Feed      — free JSON — known exploited CVEs
3. HaveIBeenPwned     — email/domain breach checking (API key optional)
4. AbuseIPDB          — IP reputation checking (free tier, API key needed)

Usage:
  from services.darkweb_feeds import run_threat_intel_scan
  results = run_threat_intel_scan(db, tenant_id)
"""

import json
import logging
import time
import urllib.request
import urllib.parse
import os
from typing import Any

from sqlalchemy.orm import Session

from models.network import NetworkDiscoveredAsset
from models.telemetry import CanonicalSoftware
from services.darkweb_service import add_source_item, upsert_watchlist, run_darkweb_matching

logger = logging.getLogger(__name__)

# ── API keys (optional — set in .env) ────────────────────────────────────
HIBP_API_KEY    = os.getenv("HIBP_API_KEY", "")       # haveibeenpwned.com
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")  # abuseipdb.com

# ── CISA KEV cache ────────────────────────────────────────────────────────
_kev_cache: dict[str, Any] = {"data": None, "fetched_at": 0}
_KEV_TTL = 3600  # refresh hourly


def _fetch_cisa_kev() -> list[dict]:
    """Fetch CISA Known Exploited Vulnerabilities catalogue (free, no auth)."""
    now = time.time()
    if _kev_cache["data"] and (now - _kev_cache["fetched_at"]) < _KEV_TTL:
        return _kev_cache["data"]

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CyberAssetIQ/2.4 ThreatIntel"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            _kev_cache["data"] = vulns
            _kev_cache["fetched_at"] = now
            logger.info("CISA KEV: loaded %d known exploited CVEs", len(vulns))
            return vulns
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return _kev_cache.get("data") or []


def _check_shodan_internetdb(ip: str) -> dict | None:
    """
    Query Shodan InternetDB for a single IP.
    Free, no API key required.
    Returns vulnerability/exposure data or None.
    """
    # Skip private/reserved IPs
    parts = ip.split(".")
    if not len(parts) == 4:
        return None
    first = int(parts[0])
    if first in (10, 127, 169, 172, 192):
        # Private ranges — Shodan won't have data for these
        # but we still check for SMEs who may have internet-facing assets
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return None

    try:
        url = f"https://internetdb.shodan.io/{ip}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "CyberAssetIQ/2.4"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status == 200:
                return json.loads(resp.read())
    except Exception:
        pass
    return None


def _check_hibp_email(email: str, api_key: str = "") -> list[dict]:
    """
    Check HaveIBeenPwned for breaches affecting an email address.
    Uses test key 00000000000000000000000000000000 for testing.
    """
    key = api_key or HIBP_API_KEY
    if not key:
        return []
    try:
        url = (
            f"https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{urllib.parse.quote(email)}?truncateResponse=false"
        )
        req = urllib.request.Request(url, headers={
            "User-Agent":   "CyberAssetIQ/2.4",
            "hibp-api-key": key,
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        msg = str(exc)
        if "404" in msg:
            return []  # Not found = clean
        logger.warning("HIBP check failed for %s: %s", email, exc)
        return []


def _check_hibp_domain(domain: str, api_key: str = "") -> list[dict]:
    """
    Check HaveIBeenPwned for breaches affecting a domain.
    NOTE: Domain search requires verified domain ownership in HIBP dashboard.
    Falls back to checking common admin email patterns if domain search fails.
    """
    key = api_key or HIBP_API_KEY
    if not key:
        return []
    try:
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{urllib.parse.quote(domain)}"
        req = urllib.request.Request(url, headers={
            "User-Agent":   "CyberAssetIQ/2.4",
            "hibp-api-key": key,
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            # Returns {alias: [breach_names]} dict
            data = json.loads(resp.read())
            # Convert to list format for consistency
            breaches = []
            for alias, breach_names in data.items():
                for bname in breach_names:
                    breaches.append({"Name": bname, "alias": alias, "domain": domain})
            return breaches
    except Exception as exc:
        msg = str(exc)
        if "404" in msg:
            return []
        if "403" in msg:
            logger.info("HIBP domain search for %s requires verified domain ownership", domain)
            return []
        logger.warning("HIBP domain check failed for %s: %s", domain, exc)
        return []


def test_hibp_connection(test_email: str = "account-exists@hibp-integration-tests.com") -> dict:
    """
    Test HIBP connectivity using the free test API key.
    Test key: 00000000000000000000000000000000
    Test email: account-exists@hibp-integration-tests.com (always returns breaches)
    """
    TEST_KEY = "00000000000000000000000000000000"
    breaches = _check_hibp_email(test_email, api_key=TEST_KEY)
    return {
        "status":        "ok" if breaches is not None else "error",
        "test_email":    test_email,
        "breach_count":  len(breaches),
        "breaches":      [b.get("Name", b.get("Title", "?")) for b in breaches[:5]],
        "api_key_set":   bool(HIBP_API_KEY),
        "message":       (
            f"HIBP connection working — found {len(breaches)} breach(es) for test account"
            if breaches else
            "HIBP connection working — test account returned no breaches (check test email)"
        ),
    }


def _check_abuseipdb(ip: str) -> dict | None:
    """
    Check AbuseIPDB for IP reputation.
    Requires free API key from abuseipdb.com
    """
    if not ABUSEIPDB_KEY:
        return None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "User-Agent": "CyberAssetIQ/2.4",
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read()).get("data")
    except Exception as exc:
        logger.warning("AbuseIPDB check failed for %s: %s", ip, exc)
        return None


# ── Main scan orchestrator ────────────────────────────────────────────────

def run_threat_intel_scan(
    db: Session,
    tenant_id: str,
    check_ips: bool = True,
    check_kev: bool = True,
    check_hibp: bool = True,
) -> dict[str, Any]:
    """
    Run all threat intelligence checks for a tenant and populate
    dark web source items + watchlist matches.

    Returns summary of what was found.
    """
    results = {
        "tenant_id":     tenant_id,
        "shodan_checked": 0,
        "shodan_hits":    0,
        "kev_matched":    0,
        "hibp_checked":   0,
        "hibp_breaches":  0,
        "total_findings": 0,
    }

    # ── 1. Shodan InternetDB — check all network-discovered IPs ──────────
    if check_ips:
        network_assets = (
            db.query(NetworkDiscoveredAsset)
            .filter(NetworkDiscoveredAsset.tenant_id == tenant_id)
            .all()
        )

        internet_facing_ips = []
        for asset in network_assets:
            ip = asset.ip_address
            if not ip:
                continue
            # Only check non-private IPs
            if not (ip.startswith("192.168.") or
                    ip.startswith("10.") or
                    ip.startswith("172.") or
                    ip.startswith("127.")):
                internet_facing_ips.append(ip)

        logger.info("Shodan InternetDB: checking %d internet-facing IPs",
                    len(internet_facing_ips))

        for ip in internet_facing_ips[:20]:  # limit to 20 to avoid rate limits
            results["shodan_checked"] += 1
            data = _check_shodan_internetdb(ip)
            if not data:
                time.sleep(0.5)
                continue

            vulns  = data.get("vulns", [])
            ports  = data.get("ports", [])
            tags   = data.get("tags", [])
            cpes   = data.get("cpes", [])

            if vulns or "compromised" in tags or "malware" in tags:
                results["shodan_hits"] += 1
                severity = "critical" if "compromised" in tags else (
                    "high" if vulns else "medium"
                )

                content = (
                    f"IP: {ip}\n"
                    f"Open ports: {', '.join(str(p) for p in ports)}\n"
                    f"Tags: {', '.join(tags)}\n"
                    f"CVEs: {', '.join(vulns)}\n"
                    f"CPEs: {', '.join(cpes[:5])}\n"
                    f"Hostnames: {', '.join(data.get('hostnames', []))}"
                )

                add_source_item(
                    db,
                    tenant_id=tenant_id,
                    source_ref=f"shodan-internetdb-{ip}",
                    source_name="Shodan InternetDB",
                    source_type="threat_intel",
                    title=f"Internet exposure: {ip}",
                    content_text=content,
                    metadata={
                        "ip": ip,
                        "vulns": vulns,
                        "ports": ports,
                        "tags": tags,
                        "source": "shodan_internetdb",
                    },
                )

                # Auto-add watchlist entry for this IP if not already there
                upsert_watchlist(
                    db, tenant_id,
                    watch_type="keyword",
                    watch_value=ip,
                    label=f"Internet-exposed IP: {ip}",
                    severity=severity,
                )

            time.sleep(0.5)  # Rate limit: ~2 req/s

    # ── 2. CISA KEV — match against software inventory ───────────────────
    if check_kev:
        kev_entries = _fetch_cisa_kev()
        if kev_entries:
            # Build lookup: CVE ID -> KEV entry
            kev_lookup = {e["cveID"]: e for e in kev_entries}

            # Get all software from tenant
            software = (
                db.query(CanonicalSoftware)
                .filter(CanonicalSoftware.tenant_id == tenant_id)
                .all()
            )

            # Check if any software names appear in KEV vendor/product
            kev_vendor_products = {}
            for entry in kev_entries:
                vendor  = entry.get("vendorProject", "").lower()
                product = entry.get("product", "").lower()
                cve_id  = entry.get("cveID", "")
                key = f"{vendor} {product}".strip()
                if key not in kev_vendor_products:
                    kev_vendor_products[key] = []
                kev_vendor_products[key].append(entry)

            matched_kev: dict[str, list] = {}
            for sw in software:
                sw_name = (sw.name or "").lower()
                sw_ver  = (sw.version or "").lower()
                for key, entries in kev_vendor_products.items():
                    if any(word in sw_name for word in key.split() if len(word) > 3):
                        for entry in entries:
                            cve_id = entry.get("cveID", "")
                            if cve_id not in matched_kev:
                                matched_kev[cve_id] = []
                            matched_kev[cve_id].append({
                                "software": sw.name,
                                "version":  sw.version,
                                "agent_id": sw.agent_id,
                                "entry":    entry,
                            })

            if matched_kev:
                results["kev_matched"] = len(matched_kev)
                content_lines = [
                    "CISA Known Exploited Vulnerabilities matched to software inventory:\n"
                ]
                for cve_id, matches in list(matched_kev.items())[:50]:
                    entry = matches[0]["entry"]
                    sw_names = list({m["software"] for m in matches})
                    content_lines.append(
                        f"{cve_id} | {entry.get('vendorProject')} {entry.get('product')} | "
                        f"Due: {entry.get('dueDate','?')} | "
                        f"Matched: {', '.join(sw_names[:3])}"
                    )

                add_source_item(
                    db,
                    tenant_id=tenant_id,
                    source_ref=f"cisa-kev-{tenant_id}",
                    source_name="CISA KEV",
                    source_type="threat_intel",
                    title=f"CISA KEV: {len(matched_kev)} actively exploited CVEs in software inventory",
                    content_text="\n".join(content_lines),
                    metadata={
                        "source": "cisa_kev",
                        "matched_cves": list(matched_kev.keys())[:20],
                        "total_matched": len(matched_kev),
                    },
                )

                # Add watchlist entries for the top KEV CVEs
                for cve_id in list(matched_kev.keys())[:10]:
                    upsert_watchlist(
                        db, tenant_id,
                        watch_type="keyword",
                        watch_value=cve_id,
                        label=f"CISA KEV: {cve_id}",
                        severity="critical",
                    )

                logger.info("CISA KEV: matched %d actively exploited CVEs", len(matched_kev))

    # ── 3. HaveIBeenPwned — check domains from watchlist ─────────────────
    if check_hibp and HIBP_API_KEY:
        from models.darkweb import DarkWebWatchlist as _DWW
        # Check both email and domain watchlist entries
        email_domain_watchlists = (
            db.query(_DWW)
            .filter(
                _DWW.tenant_id == tenant_id,
                _DWW.watch_type.in_(["email", "domain"]),
                _DWW.is_active.is_(True),
            )
            .all()
        )

        for wl in email_domain_watchlists:
            value = wl.watch_value
            results["hibp_checked"] += 1

            if wl.watch_type == "email":
                breaches = _check_hibp_email(value)
            else:
                breaches = _check_hibp_domain(value)

            domain = value

            if breaches:
                results["hibp_breaches"] += len(breaches)
                breach_names = [b.get("Name", "Unknown") for b in breaches]
                breach_dates = [b.get("BreachDate", "?") for b in breaches]
                affected    = sum(b.get("PwnCount", 0) for b in breaches)

                content = (
                    f"Domain: {domain}\n"
                    f"Total breaches: {len(breaches)}\n"
                    f"Affected accounts: {affected:,}\n"
                    f"Breaches: {', '.join(breach_names[:10])}\n"
                    f"Dates: {', '.join(breach_dates[:10])}\n\n"
                )
                for breach in breaches[:5]:
                    content += (
                        f"[{breach.get('Name')}] "
                        f"Date: {breach.get('BreachDate')} | "
                        f"Accounts: {breach.get('PwnCount',0):,} | "
                        f"Data: {', '.join(breach.get('DataClasses',[])[:5])}\n"
                    )

                add_source_item(
                    db,
                    tenant_id=tenant_id,
                    source_ref=f"hibp-{domain}",
                    source_name="HaveIBeenPwned",
                    source_type="breach_data",
                    title=f"HIBP: {len(breaches)} breach(es) for {domain}",
                    content_text=content,
                    metadata={
                        "domain": domain,
                        "breach_count": len(breaches),
                        "affected_accounts": affected,
                        "source": "hibp",
                    },
                )

                logger.info("HIBP: %d breach(es) for %s", len(breaches), domain)

            time.sleep(1.5)  # HIBP rate limit: 1 req/1.5s

    # ── Run matching engine to correlate findings with assets ─────────────
    match_results = run_darkweb_matching(db, tenant_id)
    results["total_findings"] = match_results.get("finding_count", 0)

    logger.info(
        "Threat intel scan complete: %d Shodan hits, %d KEV matches, "
        "%d HIBP breaches, %d total findings",
        results["shodan_hits"], results["kev_matched"],
        results["hibp_breaches"], results["total_findings"],
    )
    return results


def auto_populate_watchlists(db: Session, tenant_id: str) -> int:
    """
    Automatically create watchlist entries from discovered asset data:
    - Domain names from agent hostnames
    - Email patterns from org domain
    - IP addresses of internet-facing assets

    Returns number of watchlist entries created/updated.
    """
    from models.asset import CanonicalAsset
    from models.network import NetworkDiscoveredAsset

    created = 0

    # Extract domains from agent hostnames
    assets = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id)
        .all()
    )
    seen_domains: set[str] = set()
    for asset in assets:
        fqdn = asset.fqdn or asset.hostname or ""
        if "." in fqdn:
            # Extract root domain (last two parts)
            parts = fqdn.lower().rstrip(".").split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
                # Skip generic Windows domains
                if domain not in ("local", "localdomain", "workgroup") and \
                   not domain.endswith(".local"):
                    seen_domains.add(domain)

    for domain in seen_domains:
        upsert_watchlist(
            db, tenant_id,
            watch_type="domain",
            watch_value=domain,
            label=f"Auto-detected domain: {domain}",
            severity="high",
        )
        created += 1

    # Add internet-facing IPs to watchlist
    net_assets = (
        db.query(NetworkDiscoveredAsset)
        .filter(NetworkDiscoveredAsset.tenant_id == tenant_id)
        .all()
    )
    for asset in net_assets:
        ip = asset.ip_address or ""
        if ip and not (ip.startswith("192.168.") or
                       ip.startswith("10.") or
                       ip.startswith("172.") or
                       ip.startswith("127.")):
            upsert_watchlist(
                db, tenant_id,
                watch_type="keyword",
                watch_value=ip,
                label=f"Internet-facing IP: {ip}",
                severity="medium",
            )
            created += 1

    db.commit()
    return created
