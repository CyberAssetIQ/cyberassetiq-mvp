from __future__ import annotations
# Device name discovery is imported lazily inside functions to avoid
# circular imports  -  see _enrich_device_names()

"""
CyberAssetIQ  -  Enterprise Network Scan Service v2
==================================================
Matches the agentless discovery data model of Qualys / Rapid7 / Tenable.

Scan pipeline per host:
  1. Nmap -Pn -sV -O --script (OS + services + banners + HTTP + SMB + SNMP + SSL)
  2. SNMP polling  (sysDescr, sysName, firmware, interfaces)
  3. HTTP/HTTPS header + title grabbing (admin panel detection)
  4. TLS certificate inspection (expiry, issuer, weak ciphers)
  5. NetBIOS/SMB enumeration (hostname, domain, shares)
  6. NVD CVE correlation (CPE → NVD API v2 → CVSS scores)
  7. Risk scoring engine (0.0–10.0)
  8. CE v3.2 compliance flagging
"""

import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import time
import traceback
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from models.network import NetworkDiscoveredAsset, NetworkScanJob

# --- Agentless software fingerprinting (SAFE ADD) ---
from services.agentless_fingerprint import fingerprint_asset
from models.telemetry import CanonicalSoftware

# ── Port list ────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 465, 514, 515, 548, 587, 631, 993, 995, 1080, 1433,
    1521, 1723, 3306, 3389, 3690, 4444, 5000, 5432, 5900, 5985,
    6379, 8080, 8443, 8888, 9100, 9200, 10000, 27017,
]

# ── Service knowledge base ───────────────────────────────────────────────
SERVICE_MAP = {
    21:    {"name": "FTP",            "risk": "medium",   "ce_issue": "ftp_enabled"},
    22:    {"name": "SSH",            "risk": "low",      "ce_issue": None},
    23:    {"name": "Telnet",         "risk": "critical", "ce_issue": "telnet_enabled"},
    25:    {"name": "SMTP",           "risk": "medium",   "ce_issue": None},
    53:    {"name": "DNS",            "risk": "low",      "ce_issue": None},
    80:    {"name": "HTTP",           "risk": "low",      "ce_issue": "unencrypted_admin"},
    110:   {"name": "POP3",           "risk": "medium",   "ce_issue": None},
    135:   {"name": "MSRPC",          "risk": "medium",   "ce_issue": "rpc_exposed"},
    139:   {"name": "NetBIOS",        "risk": "medium",   "ce_issue": "netbios_exposed"},
    143:   {"name": "IMAP",           "risk": "medium",   "ce_issue": None},
    161:   {"name": "SNMP",           "risk": "high",     "ce_issue": "snmp_exposed"},
    389:   {"name": "LDAP",           "risk": "medium",   "ce_issue": None},
    443:   {"name": "HTTPS",          "risk": "low",      "ce_issue": None},
    445:   {"name": "SMB",            "risk": "high",     "ce_issue": "smb_exposed"},
    515:   {"name": "LPD/Print",      "risk": "low",      "ce_issue": None},
    548:   {"name": "AFP",            "risk": "medium",   "ce_issue": None},
    631:   {"name": "IPP/Print",      "risk": "low",      "ce_issue": None},
    1433:  {"name": "MSSQL",          "risk": "high",     "ce_issue": "db_exposed"},
    1521:  {"name": "Oracle DB",      "risk": "high",     "ce_issue": "db_exposed"},
    3306:  {"name": "MySQL",          "risk": "high",     "ce_issue": "db_exposed"},
    3389:  {"name": "RDP",            "risk": "high",     "ce_issue": "rdp_exposed"},
    5432:  {"name": "PostgreSQL",     "risk": "high",     "ce_issue": "db_exposed"},
    5900:  {"name": "VNC",            "risk": "critical", "ce_issue": "vnc_exposed"},
    5985:  {"name": "WinRM",          "risk": "high",     "ce_issue": "winrm_exposed"},
    6379:  {"name": "Redis",          "risk": "critical", "ce_issue": "redis_exposed"},
    8080:  {"name": "HTTP-Alt",       "risk": "medium",   "ce_issue": None},
    8443:  {"name": "HTTPS-Alt",      "risk": "low",      "ce_issue": None},
    9100:  {"name": "JetDirect",      "risk": "medium",   "ce_issue": None},
    9200:  {"name": "Elasticsearch",  "risk": "critical", "ce_issue": "elasticsearch_exposed"},
    10000: {"name": "Webmin",         "risk": "high",     "ce_issue": "admin_panel_exposed"},
    27017: {"name": "MongoDB",        "risk": "critical", "ce_issue": "mongodb_exposed"},
}

OUI_TABLE = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",
    "00:1a:11": "Google",       "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:1b:21": "Intel",        "3c:97:0e": "HP",
    "b4:b5:2f": "Apple",        "f8:ff:c2": "Apple",
    "3c:22:fb": "Apple",        "00:50:ba": "D-Link",
    "00:26:b9": "Dell",         "f8:bc:12": "Dell",
    "00:21:70": "Cisco",        "00:0a:41": "Cisco",
    "a4:c3:f0": "Google",       "00:e0:4c": "Realtek",
    "fc:ec:da": "Ubiquiti",     "24:a4:3c": "Ubiquiti",
    "dc:9f:db": "TP-Link",      "50:c7:bf": "TP-Link",
    "00:1d:7e": "Cisco-Linksys","00:25:9c": "Cisco",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_path(name: str) -> str | None:
    return shutil.which(name)


def _build_scan_diagnostics(target: str) -> dict[str, Any]:
    return {
        'target': target,
        'nmap_path': _tool_path('nmap'),
        'masscan_path': _tool_path('masscan'),
        'ping_path': _tool_path('ping'),
        'snmpget_path': _tool_path('snmpget'),
        'started_at': _now_iso(),
    }


def _vendor_from_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = mac.lower()[:8]
    for oui, vendor in OUI_TABLE.items():
        if prefix.startswith(oui.lower()):
            return vendor
    return None


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _ping_host(ip: str) -> bool:
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


# ── HTTP enrichment ──────────────────────────────────────────────────────

def _grab_http_info(ip: str, port: int, use_ssl: bool = False) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberAssetIQ/2.4 Scanner"})
        opener_args = {"context": ctx} if use_ssl else {}
        with urllib.request.urlopen(req, timeout=5, **opener_args) as resp:
            hdrs = dict(resp.headers)
            body = resp.read(4096).decode("utf-8", errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = m.group(1).strip()[:128] if m else None
            admin_words = ["router","admin","login","management","configure","gateway",
                           "firewall","switch","printer","camera","nas","synology",
                           "qnap","hikvision","dahua","console"]
            is_admin = any(w in (title or "").lower() or w in body[:800].lower()
                           for w in admin_words)
            return {
                "server":         hdrs.get("Server") or hdrs.get("server"),
                "x_powered_by":   hdrs.get("X-Powered-By"),
                "title":          title,
                "is_admin_panel": is_admin,
                "status_code":    resp.status,
                "headers":        {k: v for k, v in list(hdrs.items())[:12]},
            }
    except Exception:
        return None


def _grab_tls_info(ip: str, port: int) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                not_after = cert.get("notAfter", "")
                days_remaining = None
                expired = False
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (exp - datetime.utcnow()).days
                    expired = days_remaining < 0
                except Exception:
                    pass
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                return {
                    "subject_cn":     subject.get("commonName"),
                    "issuer_org":     issuer.get("organizationName"),
                    "not_after":      not_after,
                    "days_remaining": days_remaining,
                    "expired":        expired,
                    "self_signed":    subject == issuer,
                    "cipher_suite":   cipher[0] if cipher else None,
                    "tls_version":    cipher[1] if cipher else None,
                    "weak_ciphers":   any(w in (cipher[0] or "")
                                         for w in ["RC4","DES","3DES","NULL","EXPORT","MD5"]),
                }
    except Exception:
        return None


def _poll_snmp(ip: str) -> dict | None:
    if not shutil.which("snmpget"):
        return None
    oids = {
        "sysDescr":    "1.3.6.1.2.1.1.1.0",
        "sysName":     "1.3.6.1.2.1.1.5.0",
        "sysUpTime":   "1.3.6.1.2.1.1.3.0",
        "sysContact":  "1.3.6.1.2.1.1.4.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
    }
    result = {}
    for key, oid in oids.items():
        try:
            p = subprocess.run(
                ["snmpget", "-v2c", "-c", "public", "-t", "2", "-r", "1", ip, oid],
                capture_output=True, text=True, timeout=5)
            if p.returncode == 0 and p.stdout:
                val = re.sub(r"^STRING:\s*", "", p.stdout.split("=",1)[-1].strip()).strip('"')
                result[key] = val
        except Exception:
            continue
    return result if result else None


# ── CVE correlation ──────────────────────────────────────────────────────

def _lookup_cves_for_cpe(cpe: str, max_results: int = 5) -> list[dict]:
    if not cpe:
        return []
    try:
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?cpeName={urllib.parse.quote(cpe)}&resultsPerPage={max_results}")
        req = urllib.request.Request(url, headers={"User-Agent": "CyberAssetIQ/2.4"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            cves = []
            for item in data.get("vulnerabilities", []):
                cve    = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc   = next((d["value"] for d in cve.get("descriptions", [])
                               if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                cvss_score = cvss_vector = None
                severity = "UNKNOWN"
                for mk in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    if mk in metrics and metrics[mk]:
                        m = metrics[mk][0].get("cvssData", {})
                        cvss_score  = m.get("baseScore")
                        cvss_vector = m.get("vectorString")
                        severity    = m.get("baseSeverity",
                                     metrics[mk][0].get("baseSeverity","UNKNOWN"))
                        break
                cves.append({
                    "cve_id":      cve_id,
                    "cvss_score":  cvss_score,
                    "cvss_vector": cvss_vector,
                    "severity":    severity.upper() if severity else "UNKNOWN",
                    "description": desc[:300],
                    "published":   cve.get("published","")[:10],
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
            return cves
    except Exception:
        return []


def _correlate_cves(services: list[dict]) -> list[dict]:
    all_cves: list[dict] = []
    checked: set[str] = set()
    priority = [s for s in services
                if s.get("port") in (21,22,23,80,443,445,3389,5900,6379,9200,27017,8080,10000)]
    for svc in priority[:8]:
        cpe = svc.get("cpe")
        if cpe and cpe not in checked:
            checked.add(cpe)
            cves = _lookup_cves_for_cpe(cpe)
            for c in cves:
                c["affected_service"] = f"{svc.get('service','?')}:{svc.get('port')}"
            all_cves.extend(cves)
            time.sleep(0.6)
    seen: dict[str, dict] = {}
    for c in all_cves:
        cid = c["cve_id"]
        if cid not in seen or (c.get("cvss_score") or 0) > (seen[cid].get("cvss_score") or 0):
            seen[cid] = c
    return sorted(seen.values(), key=lambda x: x.get("cvss_score") or 0, reverse=True)


# ── Risk scoring ─────────────────────────────────────────────────────────

def _calculate_risk(ports, vulns, device_type, snmp_data, tls_info, http_info):
    score = 0.0
    factors: list[str] = []
    pnums = {p.get("port") for p in ports}

    if vulns:
        score = max(score, max((v.get("cvss_score") or 0) for v in vulns))
        crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        hi   = sum(1 for v in vulns if v.get("severity") == "HIGH")
        if crit: factors.append(f"{crit}_critical_cves")
        if hi:   factors.append(f"{hi}_high_cves")

    checks = [
        (23,    9.0, "telnet_enabled"),
        (5900,  9.0, "vnc_exposed"),
        (6379,  9.8, "redis_exposed"),
        (9200,  9.8, "elasticsearch_exposed"),
        (27017, 9.8, "mongodb_exposed"),
        (3389,  7.5, "rdp_exposed"),
        (445,   7.0, "smb_exposed"),
        (161,   6.5, "snmp_public_community"),
        (21,    5.0, "ftp_enabled"),
        (5985,  7.0, "winrm_exposed"),
    ]
    for port, s, label in checks:
        if port in pnums:
            score = max(score, s); factors.append(label)

    if {1433,3306,5432} & pnums:
        score = max(score, 7.5); factors.append("database_port_exposed")
    if snmp_data:
        score = max(score, 6.5); factors.append("snmp_responding_public_community")
    if tls_info:
        if tls_info.get("expired"):     score = max(score,5.0); factors.append("tls_cert_expired")
        if tls_info.get("self_signed"): score = max(score,3.0); factors.append("tls_self_signed")
        if tls_info.get("weak_ciphers"):score = max(score,6.0); factors.append("weak_tls_ciphers")
    if http_info:
        if http_info.get("is_admin_panel") and 80 in pnums:
            score = max(score,6.0); factors.append("admin_panel_over_http")
        if http_info.get("default_creds_warning"):
            score = max(score,8.5); factors.append("default_credentials_suspected")

    score = min(round(score, 1), 10.0)
    if   score >= 9.0: level = "CRITICAL"
    elif score >= 7.0: level = "HIGH"
    elif score >= 4.0: level = "MEDIUM"
    elif score >  0.0: level = "LOW"
    else:              level = "INFO"
    return score, level, factors


# ── Device classification ─────────────────────────────────────────────────

def _classify_device(ports, os_guess, vendor, http_info, snmp_data, hostname):
    pnums  = {p.get("port") for p in ports}
    txt    = " ".join(filter(None, [
        (os_guess or "").lower(),
        (vendor   or "").lower(),
        (hostname or "").lower(),
        (snmp_data or {}).get("sysDescr","").lower() if snmp_data else "",
        ((http_info or {}).get("title") or "").lower()    if http_info else "",
    ]))
    if any(w in txt for w in ["fortigate","sonicwall","checkpoint","palo alto","asa"]):
        return "firewall", "Network Security"
    if any(w in txt for w in ["cisco","juniper","arista","ubiquiti"]) or (161 in pnums):
        return "network_device", "Network Infrastructure"
    if 9100 in pnums or 515 in pnums or 631 in pnums:
        for b in ["hp","canon","epson","brother","xerox","ricoh","kyocera","lexmark"]:
            if b in txt: return "printer", f"{b.upper()} Printer"
        return "printer", "Network Printer"
    if any(w in txt for w in ["hikvision","dahua","axis","camera","nvr"]):
        return "ip_camera", "Surveillance"
    if any(w in txt for w in ["synology","qnap","nas","diskstation"]):
        return "nas_device", "Storage"
    if any(w in txt for w in ["tizen","webos","smart tv","roku","firetv","bravia"]):
        return "smart_tv", "Media Device"
    if any(w in txt for w in ["voip","polycom","yealink","avaya"]):
        return "voip_device", "Communications"
    if "windows" in txt or (445 in pnums and 3389 in pnums) or (135 in pnums and 445 in pnums):
        if any(w in txt for w in ["server 2019","server 2022","server 2016","server 2012","server 2008"]):
            return "windows_server", "Windows Server"
        return ("windows_server","Windows Server") if "server" in txt else ("windows_host","Windows Workstation")
    if any(w in txt for w in ["linux","ubuntu","debian","centos","rhel","fedora","raspbian"]):
        return "linux_host", ("Linux Server" if (443 in pnums or 8443 in pnums or 3306 in pnums) else "Linux Workstation")
    if any(w in txt for w in ["mac os","macos","darwin","apple"]) or (22 in pnums and 548 in pnums):
        return "mac_host", "Apple Mac"
    if "android" in txt:
        return "mobile_device", "Android Device"
    if "ios" in txt or "iphone" in txt or "ipad" in txt:
        return "mobile_device", "Apple iOS Device"
    if any(w in txt for w in ["freebsd","openbsd","netbsd"]):
        return "linux_host", "BSD Server"
    if 554 in pnums:  # RTSP  -  likely IP camera
        return "ip_camera", "IP Camera"
    if 1883 in pnums:  # MQTT  -  IoT
        return "iot_device", "IoT/MQTT Device"
    if 5060 in pnums:  # SIP  -  VoIP
        return "voip_device", "VoIP Device"
    if 5900 in pnums:  # VNC
        return "linux_host", "VNC-enabled Host"
    if pnums and not {22,80,135,443,445,3389} & pnums:
        return "iot_device", "IoT Device"
    if 80 in pnums or 443 in pnums:
        return "server_or_web_device", "Web Server"
    return "unknown", None


# ── CE v3.2 checks ───────────────────────────────────────────────────────

def _check_ce_issues(ports, os_guess, risk_factors, managed):
    pnums  = {p.get("port") for p in ports}
    issues = []
    if not managed:                                issues.append("unregistered_asset_A1")
    if 23   in pnums:                              issues.append("telnet_enabled_A3")
    if 3389 in pnums:                              issues.append("rdp_exposed_A3")
    if 445  in pnums:                              issues.append("smb_exposed_A3")
    if 161  in pnums:                              issues.append("snmp_public_A3")
    if "admin_panel_over_http"       in risk_factors: issues.append("unencrypted_admin_A3")
    if "default_credentials_suspected" in risk_factors: issues.append("default_credentials_A2")
    if "tls_cert_expired"            in risk_factors: issues.append("expired_tls_cert_A3")
    if "weak_tls_ciphers"            in risk_factors: issues.append("weak_cipher_A3")
    if os_guess and any(old in os_guess for old in
                        ["Windows XP","Windows 7","Windows 8","2003","2008"]):
        issues.append("end_of_life_os_A5")
    return issues


# ── Nmap scan ────────────────────────────────────────────────────────────

def _parse_nmap_host(host, cmd) -> dict | None:
    status = host.find("status")
    if status is not None and status.attrib.get("state") != "up":
        return None

    address = mac = mac_vendor = None
    for addr in host.findall("address"):
        at = addr.attrib.get("addrtype")
        if at == "ipv4":   address    = addr.attrib.get("addr")
        elif at == "mac":  mac        = addr.attrib.get("addr"); mac_vendor = addr.attrib.get("vendor")
    if not address:
        return None

    hostname = None
    hn = host.find("hostnames/hostname")
    if hn is not None: hostname = hn.attrib.get("name")
    if not hostname:   hostname = _reverse_dns(address)

    os_guess = os_version = os_cpe = None; os_confidence = None
    om = host.find("os/osmatch")
    if om is not None:
        raw_os_guess = om.attrib.get("name")
        raw_os_conf  = int(om.attrib.get("accuracy", 0))
        oc = om.find("osclass")
        if oc is not None:
            os_version = oc.attrib.get("osgen")
            ce = oc.find("cpe")
            if ce is not None: os_cpe = ce.text

        # Filter implausible low-confidence OS guesses.
        # nmap often misidentifies phones/IoT/unknown devices as
        # projectors, printers or obscure embedded devices when
        # there are no open ports to fingerprint against.
        # Require 85%+ confidence OR must be a known common OS.
        TRUSTED_OS_KEYWORDS = [
            "windows", "linux", "ubuntu", "debian", "centos", "rhel",
            "android", "ios", "macos", "darwin", "freebsd", "openbsd",
            "cisco", "juniper", "fortios", "vmware", "esxi",
            "raspberry", "mikrotik", "synology", "qnap",
        ]
        os_lower = (raw_os_guess or "").lower()
        is_trusted = any(kw in os_lower for kw in TRUSTED_OS_KEYWORDS)

        if raw_os_conf >= 85 or is_trusted:
            os_guess      = raw_os_guess
            os_confidence = raw_os_conf
        else:
            # Low confidence + unrecognised OS  -  discard (likely false positive)
            os_guess      = None
            os_confidence = None
        # Further check: discard known-bad fingerprints regardless of confidence
        # These appear at 90-95% confidence but are impossible to fingerprint
        # without open ports (e.g. Sanyo projector, Cisco SF300)
        if os_guess and _is_bad_os_fingerprint(os_guess, 0):
            # Will be re-evaluated after port scan completes below
            _raw_os_guess_pending = os_guess
            os_guess = None
            os_confidence = None
        else:
            _raw_os_guess_pending = None

    open_ports: list[dict] = []
    services:   list[dict] = []
    for p in host.findall("ports/port"):
        st = p.find("state")
        if st is None or st.attrib.get("state") != "open": continue
        portid = int(p.attrib.get("portid", 0))
        proto  = p.attrib.get("protocol", "tcp")
        svc    = p.find("service")
        svc_name    = None if svc is None else svc.attrib.get("name")
        svc_product = None if svc is None else svc.attrib.get("product")
        svc_version = None if svc is None else svc.attrib.get("version")
        svc_extra   = None if svc is None else svc.attrib.get("extrainfo")
        svc_cpe     = None
        if svc is not None:
            ce = svc.find("cpe")
            if ce is not None: svc_cpe = ce.text
        banner = None
        for scr in p.findall("script"):
            if scr.attrib.get("id") == "banner":
                banner = scr.attrib.get("output","")[:200]
        known = SERVICE_MAP.get(portid, {})
        display = svc_name or known.get("name") or f"port-{portid}"
        open_ports.append({"port":portid,"protocol":proto,"service":display,"state":"open"})
        services.append({"port":portid,"protocol":proto,"service":display,
                         "product":svc_product,"version":svc_version,
                         "extra_info":svc_extra,"banner":banner,"cpe":svc_cpe,
                         "risk_rating":known.get("risk","info"),
                         "ce_issue":known.get("ce_issue")})

    # Re-evaluate pending OS guess now that we know port count
    if '_raw_os_guess_pending' in dir() and _raw_os_guess_pending:
        if not _is_bad_os_fingerprint(_raw_os_guess_pending, len(open_ports)):
            os_guess = _raw_os_guess_pending

    # If ALL scanned ports are filtered/closed, nmap OS detection is unreliable
    # The Sanyo/Xbox/printer false positives only happen in this scenario
    # Discard OS guess unless we have at least one open port to anchor it
    all_filtered = len(open_ports) == 0
    if all_filtered and os_guess:
        os_lower = (os_guess or "").lower()
        TRUSTED_OS_KEYWORDS = [
            "windows", "linux", "ubuntu", "debian", "centos", "rhel",
            "android", "ios", "macos", "darwin", "freebsd", "openbsd",
            "cisco", "juniper", "fortios", "vmware", "esxi",
            "raspberry", "mikrotik", "synology", "qnap",
        ]
        is_trusted = any(kw in os_lower for kw in TRUSTED_OS_KEYWORDS)
        if not is_trusted:
            # No open ports + unrecognised OS = unreliable fingerprint
            os_guess      = None
            os_confidence = None

    # Discard bad OS fingerprints if no open ports
    if os_guess and _is_bad_os_fingerprint(os_guess, len(open_ports)):
        os_guess = None
        os_confidence = None

    # TTL-based OS fingerprinting (fallback when nmap -O doesn't match)
    ttl_val = None
    for hop in host.findall(".//hop"):
        try:
            ttl_val = int(hop.attrib.get("ttl", 0))
        except ValueError:
            pass
    # Also check the host TTL directly
    if ttl_val is None:
        for dist in host.findall("distance"):
            pass  # distance is hops, not TTL
    # Infer OS from TTL if nmap OS detection failed
    if not os_guess and ttl_val:
        if ttl_val >= 120 and ttl_val <= 135:
            os_guess = "Windows (TTL-inferred)"
            os_confidence = 60
        elif ttl_val >= 60 and ttl_val <= 70:
            os_guess = "Linux (TTL-inferred)"
            os_confidence = 55
        elif ttl_val >= 250:
            os_guess = "Network Device (TTL-inferred)"
            os_confidence = 50

    # Script intel
    smb_info  = {}
    http_info = {}
    tls_info_raw = {}
    for script in host.findall(".//script"):
        sid = script.attrib.get("id",""); out = script.attrib.get("output","")
        if sid == "http-title":         http_info["title"]  = out.strip()[:128]
        if sid == "http-server-header": http_info["server"] = out.strip()[:128]
        if sid == "http-auth-finder":   http_info["auth_required"] = out.strip()[:200]
        if sid == "smb-os-discovery":
            for line in out.splitlines():
                if "OS:"           in line: smb_info["os"]            = line.split(":",1)[-1].strip()
                if "Computer name:"in line: smb_info["computer_name"] = line.split(":",1)[-1].strip()
                if "Workgroup:"    in line: smb_info["domain"]         = line.split(":",1)[-1].strip()
        if sid == "ssl-cert":
            tls_info_raw["cert_raw"] = out.strip()[:400]
            m = re.search(r"Not valid after:\s*(.+)", out)
            if m: tls_info_raw["not_after"] = m.group(1).strip()
        if sid == "ssl-enum-ciphers":
            tls_info_raw["weak_ciphers"] = any(w in out for w in ["RC4","DES","NULL","EXPORT"])
        if sid == "snmp-sysdescr":
            pass  # handled by _poll_snmp

    snmp_data = _poll_snmp(address) if any(p["port"]==161 for p in open_ports) else None
    if not http_info:
        for port, use_ssl in [(80,False),(443,True),(8080,False),(8443,True)]:
            if any(p["port"]==port for p in open_ports):
                http_info = _grab_http_info(address, port, use_ssl) or {}
                break
    tls = (tls_info_raw if tls_info_raw else None) or (
        _grab_tls_info(address, 443) if any(p["port"] in (443,8443) for p in open_ports) else None)

    # Use SMB OS discovery to fill in os_guess if nmap -O didn't get it
    if smb_info.get("os") and not os_guess:
        os_guess = smb_info["os"]
        os_confidence = 85  # SMB is very reliable for Windows

    # Enrich os_guess from service banners (SSH, FTP, HTTP server headers)
    if not os_guess:
        for svc in services:
            product = (svc.get("product") or "").lower()
            extra   = (svc.get("extra_info") or "").lower()
            banner  = (svc.get("banner") or "").lower()
            combined = f"{product} {extra} {banner}"
            if "windows" in combined:
                # Extract version if present
                import re as _re
                m = _re.search(r"windows[^0-9]*([0-9][0-9\.]+)", combined, _re.I)
                os_guess = f"Windows {m.group(1)}" if m else "Windows"
                os_confidence = 70
                break
            elif "ubuntu" in combined:
                os_guess = "Ubuntu Linux"; os_confidence = 70; break
            elif "debian" in combined:
                os_guess = "Debian Linux"; os_confidence = 70; break
            elif "centos" in combined or "rhel" in combined:
                os_guess = "RHEL/CentOS Linux"; os_confidence = 70; break
            elif "linux" in combined:
                os_guess = "Linux"; os_confidence = 65; break
            elif "openbsd" in combined:
                os_guess = "OpenBSD"; os_confidence = 70; break
            elif "freebsd" in combined or "darwin" in combined:
                os_guess = "macOS/FreeBSD"; os_confidence = 70; break

    if not mac_vendor and mac: mac_vendor = _vendor_from_mac(mac)

    device_type, device_family = _classify_device(
        open_ports, os_guess, mac_vendor, http_info or None, snmp_data, hostname)

    firmware_version = None
    if snmp_data:
        m = re.search(r"(?:Version|firmware|SW)[:\s]+([0-9][^\s,;]+)",
                      snmp_data.get("sysDescr",""), re.I)
        if m: firmware_version = m.group(1)

    vulns = _correlate_cves(services)
    risk_score, risk_level, risk_factors = _calculate_risk(
        open_ports, vulns, device_type, snmp_data, tls, http_info or None)
    ce_issues = _check_ce_issues(open_ports, os_guess, risk_factors, managed=False)

    return {
        "ip_address":       address,
        "hostname":         hostname,
        "netbios_name":     smb_info.get("computer_name"),
        "mdns_name":        None,
        "fqdn":             hostname,
        "mac_address":      mac,
        "vendor":           mac_vendor,
        "device_type":      device_type,
        "device_model":     None,
        "device_family":    device_family,
        "os_guess":         os_guess,
        "os_version":       os_version,
        "os_cpe":           os_cpe,
        "os_confidence":    os_confidence,
        "firmware_version": firmware_version,
        "ttl":              None,
        "network_segment":  address.rsplit(".",1)[0]+".0/24",
        "vlan":             None,
        "open_ports":       open_ports,
        "services":         services,
        "snmp_data":        snmp_data,
        "http_headers":     http_info or None,
        "tls_info":         tls,
        "banner_data":      {"smb": smb_info} if smb_info else None,
        "smb_info":         smb_info or None,
        "vulnerabilities":  vulns,
        "cve_count":        len(vulns),
        "critical_cve_count": sum(1 for v in vulns if v.get("severity")=="CRITICAL"),
        "high_cve_count":   sum(1 for v in vulns if v.get("severity")=="HIGH"),
        "medium_cve_count": sum(1 for v in vulns if v.get("severity")=="MEDIUM"),
        "risk_score":       risk_score,
        "risk_level":       risk_level,
        "risk_hint":        risk_level.lower(),
        "risk_factors":     risk_factors,
        "first_seen":       _now_iso(),
        "last_seen":        _now_iso(),
        "managed":          False,
        "agent_installed":  False,
        "is_rogue":         False,
        "ce_asset_registered": False,
        "ce_issues":        ce_issues,
        "raw_metadata_json": {"engine":"nmap","cmd":" ".join(cmd[1:]), "asset_confidence": "confirmed_asset" if (open_ports or hostname or mac) else "observed_host"},
        "asset_confidence": "confirmed_asset" if (open_ports or hostname or mac) else "observed_host",
    }


def _nmap_ping_sweep(target: str) -> list[str]:
    """
    Fallback host discovery when no agent ARP data is available.
    Uses TCP SYN ping  -  the only reliable method inside Docker.

    NOTE: This is the FALLBACK path. The primary path uses Windows Agent
    ARP data (real Layer 2 discovery). Only called when agent has no
    recent data.
    """
    cmd = [
        "nmap", "-sn",
        "-PS22,80,135,443,445,3389",  # TCP SYN  -  only method that works in Docker
        "-T4",
        "--max-retries", "1",
        "--host-timeout", "5s",
        "-oX", "-", target
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or "nmap ping sweep failed")

    root = ET.fromstring(proc.stdout)
    live_ips = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr")
                if not ip:
                    continue
                try:
                    last = int(ip.split(".")[-1])
                    if last in (0, 255):
                        continue
                except ValueError:
                    continue
                live_ips.append(ip)

    print(f"[nmap_ping_sweep] found {len(live_ips)} live hosts (fallback mode)")
    return live_ips



def _scan_single_host_deep(ip: str, pre_discovered_ports: list[str] | None = None) -> dict | None:
    """
    Deep scan a SINGLE host - matching Qualys/Rapid7/Nessus per-host approach.
    Each host gets its own isolated nmap session so one slow host
    cannot block or timeout the entire subnet scan.
    Returns parsed result dict or None if host unreachable.
    """
    if not shutil.which("nmap"):
        return None

    import os as _os
    is_root = (_os.getuid() == 0) if hasattr(_os, "getuid") else True

    # Enterprise port list  -  covers all device types
    ALL_PORTS = (
        "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,"
        "465,514,515,554,587,631,993,995,1080,1433,1883,3306,"
        "3389,5060,5432,5900,5985,6379,8080,8443,8888,9100,27017"
    )

    try:
        # ── Phase A: Port discovery ────────────────────────────────────
        if pre_discovered_ports is not None:
            open_port_nums = pre_discovered_ports
            host_a = None
        else:
            # Phase A: Fast nmap port scan on this single IP
            cmd_a = ["nmap", "-Pn", "-T4", f"-p{ALL_PORTS}",
                     "--host-timeout", "20s", "-oX", "-", ip]
            if is_root:
                cmd_a.insert(1, "-sS")

            p_a = subprocess.run(cmd_a, capture_output=True, text=True, timeout=30)
            if p_a.returncode not in (0, 1) or not p_a.stdout.strip():
                return None

            root_a = ET.fromstring(p_a.stdout)
            host_a = root_a.find("host")
            if host_a is None:
                return None

            open_port_nums = []
            for p in host_a.findall("ports/port"):
                st = p.find("state")
                if st is not None and st.attrib.get("state") == "open":
                    open_port_nums.append(p.attrib.get("portid", ""))

        # ── Phase B: Deep scan on open ports only ──────────────────────
        if not open_port_nums:
            if host_a is not None:
                result = _parse_nmap_host(host_a, "nmap_ping_only")
                if result:
                    result["os_guess"] = None
                    result["os_confidence"] = None
                return result
            # No open ports found — host responded but nothing open
            return None

        port_arg = ",".join(open_port_nums)

        scripts = ["smb-os-discovery", "http-title", "http-server-header"]
        if any(p in open_port_nums for p in ["443", "8443", "993", "995"]):
            scripts.append("ssl-cert")
        if "22" in open_port_nums:
            scripts.append("banner")

        cmd_b = [
            "nmap", "-Pn", "-T4",
            "-sV", "--version-intensity", "5",
            f"-p{port_arg}",
            "--script", ",".join(scripts),
            "--script-timeout", "10s",
            "--host-timeout", "25s",
            "-oX", "-", ip
        ]
        if is_root:
            cmd_b.insert(1, "-sS")
            cmd_b.insert(2, "-O")

        p_b = subprocess.run(cmd_b, capture_output=True, text=True, timeout=40)
        if p_b.returncode not in (0, 1) or not p_b.stdout.strip():
            # Fall back to phase A result if available, else None
            return _parse_nmap_host(host_a, "nmap_phase_a") if host_a is not None else None

        root_b = ET.fromstring(p_b.stdout)
        host_b = root_b.find("host")
        return _parse_nmap_host(host_b, "nmap_deep") if host_b is not None else _parse_nmap_host(host_a, "nmap_phase_a")

    except subprocess.TimeoutExpired:
        print(f"[nmap_deep] timeout for {ip}")
    except Exception as exc:
        print(f"[nmap_deep] error for {ip}: {exc}")
    return None


def _run_nmap(target: str, live_ips: list[str] | None = None) -> tuple[str, list[dict]]:
    """
    Enterprise-grade multi-phase network scan  -  Qualys/Rapid7/Nessus architecture:

    Phase 1: Host discovery
             - If live_ips provided (from Windows Agent ARP): use those directly
             - Otherwise: nmap TCP SYN ping sweep (fallback)
             Agent ARP is ALWAYS more accurate  -  it uses real Layer 2 discovery
             which Docker cannot do. This matches how Qualys/Rapid7 use their
             physical Scanner Appliance alongside cloud agents.

    Phase 2: Per-host deep scan in parallel batches of 16
             Each host gets its own nmap session  -  isolation prevents
             one slow host from blocking the entire scan
    """
    if not shutil.which("nmap"):
        raise FileNotFoundError("nmap not installed")

    # Phase 1: host discovery
    if live_ips:
        # Agent-provided IPs  -  authoritative Layer 2 ARP data (best)
        print(f"[nmap_deep] using {len(live_ips)} agent-confirmed hosts (ARP)")
    else:
        # Fallback: nmap ping sweep inside Docker (less reliable)
        live_ips = _nmap_ping_sweep(target)
        if not live_ips:
            return "nmap", []

    print(f"[nmap_deep] {len(live_ips)} live hosts  -  scanning in parallel batches of 16")

    # ── Masscan phase: rapid port discovery across ALL hosts ──────────
    # Phase 2: scan each host independently, 16 at a time
    BATCH_SIZE = 16
    all_results: list[dict] = []

    with ThreadPoolExecutor(max_workers=BATCH_SIZE) as ex:
        futures = {
            ex.submit(_scan_single_host_deep, ip, None): ip
            for ip in live_ips
        }
        for future in as_completed(futures, timeout=300):
            ip = futures[future]
            try:
                result = future.result(timeout=300)  # allow 2min per host
                if result:
                    all_results.append(result)
                else:
                    # Host responded to SYN ping but has no open ports.
                    # Only include if we already know it from agent ARP (has identity).
                    # Pure ping-only unknowns are NOT added  -  they are ghost entries.
                    # This is the Qualys/Rapid7 behaviour: unknown = not in inventory.
                    pass  # Skipped intentionally  -  no identity, no inventory entry
            except Exception as exc:
                print(f"[nmap_deep] scan failed for {ip}: {exc}")

    results = all_results
    nmap_returned_ips: set[str] = {r["ip_address"] for r in results if r.get("ip_address")}
    print(f"[nmap] total results: {len(results)} ({len(nmap_returned_ips)} with data)")
    return "nmap", results

def _scan_host_fallback(ip: str, timeout: float = 0.5) -> dict | None:
    open_ports: list[dict] = []
    services:   list[dict] = []
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    k = SERVICE_MAP.get(port, {})
                    open_ports.append({"port":port,"protocol":"tcp",
                                       "service":k.get("name",f"port-{port}"),"state":"open"})
                    services.append({"port":port,"protocol":"tcp",
                                     "service":k.get("name",f"port-{port}"),
                                     "product":None,"version":None,"banner":None,"cpe":None,
                                     "risk_rating":k.get("risk","info"),"ce_issue":k.get("ce_issue")})
        except Exception: continue

    if not open_ports and not _ping_host(ip):
        return None

    http_info = tls = None
    for port, use_ssl in [(80,False),(443,True),(8080,False),(8443,True)]:
        if any(p["port"]==port for p in open_ports):
            http_info = _grab_http_info(ip, port, use_ssl); break
    if any(p["port"] in (443,8443) for p in open_ports):
        tls = _grab_tls_info(ip, 443)

    device_type, device_family = _classify_device(open_ports,None,None,http_info,None,None)
    risk_score, risk_level, risk_factors = _calculate_risk(open_ports,[],device_type,None,tls,http_info)
    ce_issues = _check_ce_issues(open_ports, None, risk_factors, managed=False)
    via = "tcp_ports" if open_ports else "ping"

    return {
        "ip_address":       ip,
        "hostname":         _reverse_dns(ip),
        "netbios_name":     None, "mdns_name":None, "fqdn":None,
        "mac_address":      None, "vendor":None,
        "device_type":      device_type, "device_model":None, "device_family":device_family,
        "os_guess":         None, "os_version":None, "os_cpe":None,
        "os_confidence":    None, "firmware_version":None, "ttl":None,
        "network_segment":  ip.rsplit(".",1)[0]+".0/24", "vlan":None,
        "open_ports":       open_ports, "services":services,
        "snmp_data":        None, "http_headers":http_info, "tls_info":tls,
        "banner_data":      None, "smb_info":None,
        "vulnerabilities":  [], "cve_count":0,
        "critical_cve_count":0, "high_cve_count":0, "medium_cve_count":0,
        "risk_score":       risk_score, "risk_level":risk_level,
        "risk_hint":        risk_level.lower(), "risk_factors":risk_factors,
        "first_seen":       _now_iso(), "last_seen":_now_iso(),
        "managed":False, "agent_installed":False, "is_rogue":False,
        "ce_asset_registered":False, "ce_issues":ce_issues,
        "raw_metadata_json":{"engine":"fallback_socket_scan","detected_via":via},
    }



# ── mDNS Discovery ────────────────────────────────────────────────────────
# Discovers Apple devices, printers, smart TVs, Chromecast, Linux Avahi
# devices  -  anything that broadcasts via Multicast DNS (RFC 6762)

def _run_mdns_discovery(timeout: float = 3.0) -> list[dict]:
    """
    mDNS/Zeroconf discovery via multicast UDP to 224.0.0.251:5353.
    Sends PTR query for _services._dns-sd._udp.local to find all
    advertised service types, then resolves device names.

    Matches what Qualys and Rapid7 do for Apple/mDNS device discovery.
    Works inside Docker if the host network is accessible.
    """
    import struct

    results: dict[str, dict] = {}  # ip -> info dict

    # Known mDNS service types to query
    service_types = [
        "_http._tcp.local",
        "_https._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",       # AirPlay audio
        "_ipp._tcp.local",         # IPP printing
        "_pdl-datastream._tcp.local",  # HP JetDirect
        "_scanner._tcp.local",
        "_smb._tcp.local",
        "_afpovertcp._tcp.local",  # Apple AFP
        "_ssh._tcp.local",
        "_googlecast._tcp.local",  # Chromecast
        "_spotify-connect._tcp.local",
        "_daap._tcp.local",        # iTunes
        "_services._dns-sd._udp.local",
    ]

    def _build_mdns_query(name: str) -> bytes:
        """Build a minimal mDNS PTR query packet."""
        # Transaction ID = 0, Flags = standard query
        header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
        # Encode the name
        parts = name.encode().split(b".")
        qname = b""
        for part in parts:
            qname += bytes([len(part)]) + part
        qname += b"\x00"
        # QTYPE=PTR(12), QCLASS=IN(1) with unicast bit
        question = qname + struct.pack(">HH", 12, 0x8001)
        return header + question

    def _parse_mdns_response(data: bytes, src_ip: str) -> None:
        """Parse mDNS response and extract device info."""
        try:
            if len(data) < 12:
                return
            # Parse header
            flags = struct.unpack(">H", data[2:4])[0]
            is_response = (flags >> 15) & 1
            if not is_response:
                return

            # Extract readable strings from the packet
            # Look for .local names and IP hints
            raw = data.decode("latin-1", errors="replace")

            # Extract device name hints from packet text
            device_name = None
            device_type = "unknown"
            device_family = None

            # Detect device type from service/name strings in packet
            raw_lower = raw.lower()
            if any(x in raw_lower for x in ["airplay", "apple tv", "appletv"]):
                device_type, device_family = "smart_tv", "Apple TV"
            elif any(x in raw_lower for x in ["iphone", "ipad"]):
                device_type, device_family = "mobile_device", "Apple iOS Device"
            elif any(x in raw_lower for x in ["macbook", "imac", "mac mini", "mac pro"]):
                device_type, device_family = "mac_host", "Apple Mac"
            elif any(x in raw_lower for x in ["googlecast", "chromecast"]):
                device_type, device_family = "smart_device", "Google Chromecast"
            elif any(x in raw_lower for x in ["ipp", "pdl", "printer", "jetdirect", "laserjet"]):
                device_type, device_family = "printer", "Network Printer"
            elif any(x in raw_lower for x in ["spotify", "sonos", "speaker"]):
                device_type, device_family = "smart_device", "Smart Speaker"
            elif any(x in raw_lower for x in ["samsung", "bravia", "webos", "tizen"]):
                device_type, device_family = "smart_tv", "Smart TV"

            if src_ip not in results:
                results[src_ip] = {
                    "ip":          src_ip,
                    "device_type": device_type,
                    "device_family": device_family,
                    "mdns_name":   None,
                    "source":      "mdns",
                }
            elif device_type != "unknown":
                results[src_ip]["device_type"]   = device_type
                results[src_ip]["device_family"] = device_family

        except Exception:
            pass

    # Send multicast queries
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

        for svc_type in service_types[:6]:  # limit to 6 to avoid flooding
            try:
                pkt = _build_mdns_query(svc_type)
                sock.sendto(pkt, (MDNS_ADDR, MDNS_PORT))
            except Exception:
                pass

        # Collect responses
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                _parse_mdns_response(data, addr[0])
            except socket.timeout:
                break
            except Exception:
                break

        sock.close()
    except Exception as e:
        print(f"[mdns] discovery error (non-fatal): {e}")

    discovered = list(results.values())
    print(f"[mdns] discovered {len(discovered)} device(s)")
    return discovered


# ── SSDP Discovery ────────────────────────────────────────────────────────
# Discovers UPnP devices: smart TVs, routers, NAS, cameras, speakers,
# media players  -  anything that responds to SSDP M-SEARCH

def _run_ssdp_discovery(timeout: float = 3.0) -> list[dict]:
    """
    SSDP/UPnP discovery via multicast UDP to 239.255.255.250:1900.
    Sends M-SEARCH request and parses responses to identify device
    type, vendor, model, and services.

    Matches what Rapid7/Tenable do for IoT/consumer device discovery.
    """
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    results: dict[str, dict] = {}  # ip -> info

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(MSEARCH.encode(), (SSDP_ADDR, SSDP_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                response = data.decode("utf-8", errors="replace")
                response_lower = response.lower()

                # Parse key SSDP headers
                server_line = ""
                location = ""
                usn = ""
                for line in response.splitlines():
                    ll = line.lower()
                    if ll.startswith("server:"):
                        server_line = line.split(":", 1)[-1].strip()
                    elif ll.startswith("location:"):
                        location = line.split(":", 1)[-1].strip()
                    elif ll.startswith("usn:"):
                        usn = line.split(":", 1)[-1].strip()

                # Classify device from SERVER header and USN
                device_type = "unknown"
                device_family = None
                vendor = None

                combined = (server_line + " " + usn + " " + location).lower()

                if any(x in combined for x in ["samsung", "tizen"]):
                    device_type, device_family, vendor = "smart_tv", "Samsung Smart TV", "Samsung"
                elif any(x in combined for x in ["bravia", "sony"]):
                    device_type, device_family, vendor = "smart_tv", "Sony Bravia", "Sony"
                elif any(x in combined for x in ["webos", "lg"]):
                    device_type, device_family, vendor = "smart_tv", "LG Smart TV", "LG"
                elif any(x in combined for x in ["roku"]):
                    device_type, device_family, vendor = "smart_tv", "Roku", "Roku"
                elif any(x in combined for x in ["googlecast", "chromecast"]):
                    device_type, device_family, vendor = "smart_device", "Chromecast", "Google"
                elif any(x in combined for x in ["synology"]):
                    device_type, device_family, vendor = "nas_device", "Synology NAS", "Synology"
                elif any(x in combined for x in ["qnap"]):
                    device_type, device_family, vendor = "nas_device", "QNAP NAS", "QNAP"
                elif any(x in combined for x in ["hikvision", "dahua"]):
                    device_type, device_family, vendor = "ip_camera", "IP Camera", None
                elif any(x in combined for x in ["sonos"]):
                    device_type, device_family, vendor = "smart_device", "Sonos Speaker", "Sonos"
                elif any(x in combined for x in ["printer", "jetdirect", "ipp"]):
                    device_type, device_family = "printer", "Network Printer"
                elif any(x in combined for x in ["linux/2", "linux/3", "linux/4", "linux/5"]):
                    device_type, device_family = "linux_host", "Linux Device"
                elif any(x in combined for x in ["windows", "microsoft"]):
                    device_type, device_family = "windows_host", "Windows Device"
                elif any(x in combined for x in ["upnp", "dlna", "mediaserver"]):
                    device_type, device_family = "smart_device", "UPnP Media Device"

                if src_ip not in results:
                    results[src_ip] = {
                        "ip":           src_ip,
                        "device_type":  device_type,
                        "device_family": device_family,
                        "vendor":       vendor,
                        "ssdp_server":  server_line[:128] if server_line else None,
                        "ssdp_location": location[:256] if location else None,
                        "source":       "ssdp",
                    }
                elif device_type != "unknown":
                    # Update with better classification if we got one
                    results[src_ip]["device_type"]   = device_type
                    results[src_ip]["device_family"] = device_family
                    if vendor:
                        results[src_ip]["vendor"] = vendor
                    if server_line:
                        results[src_ip]["ssdp_server"] = server_line[:128]

            except socket.timeout:
                break
            except Exception:
                pass

        sock.close()

    except Exception as e:
        print(f"[ssdp] discovery error (non-fatal): {e}")

    discovered = list(results.values())
    print(f"[ssdp] discovered {len(discovered)} device(s)")
    return discovered


# ── Merge discovery results ───────────────────────────────────────────────



def _norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.strip().lower().replace("-", ":")
    parts = [part for part in mac.split(":") if part != ""]
    if len(parts) == 6:
        return ":".join(part.zfill(2) for part in parts)
    return mac


def _norm_name(name: str | None) -> str | None:
    if not name:
        return None
    name = name.strip().strip(".").lower()
    if name in {"unknown", "unknown device", "localhost", "ip", "n/a"}:
        return None
    return name


def _best_name(result: dict) -> str | None:
    return (
        result.get("hostname")
        or result.get("netbios_name")
        or result.get("mdns_name")
        or result.get("fqdn")
    )


def _is_ping_only_result(result: dict) -> bool:
    return not result.get("open_ports") and not result.get("services")


def _asset_confidence(result: dict) -> str:
    if result.get("mac_address"):
        return "confirmed_asset"
    if _best_name(result):
        return "confirmed_asset"
    if result.get("open_ports") or result.get("services"):
        return "confirmed_asset"
    return "observed_host"


def _identity_keys(result: dict) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []

    mac = _norm_mac(result.get("mac_address"))
    if mac:
        keys.append(("mac", mac))

    name = _norm_name(_best_name(result))
    if name:
        keys.append(("name", name))

    ip = result.get("ip_address")
    if ip:
        keys.append(("ip", ip))

    return keys


def _merge_values(existing: dict, new: dict) -> dict:
    merged = dict(existing)

    preserve_if_better = {
        "hostname", "netbios_name", "mdns_name", "fqdn",
        "mac_address", "vendor", "device_type", "device_family",
        "os_guess", "os_version", "os_cpe", "firmware_version",
        "device_model",
    }
    always_merge = {
        "open_ports", "services", "vulnerabilities",
        "risk_factors", "ce_issues", "raw_metadata_json",
        "http_headers", "snmp_data", "tls_info", "banner_data", "smb_info",
    }
    take_max = {
        "risk_score", "cve_count", "critical_cve_count",
        "high_cve_count", "medium_cve_count",
    }

    for k, v in new.items():
        if k == "asset_confidence":
            old = merged.get("asset_confidence", "observed_host")
            if old == "observed_host" and v == "confirmed_asset":
                merged[k] = v
            elif "asset_confidence" not in merged:
                merged[k] = v

        elif k in always_merge:
            if isinstance(v, list):
                old = merged.get(k) or []
                seen: set[str] = set()
                combined = []
                for item in old + v:
                    sig = json.dumps(item, sort_keys=True, default=str)
                    if sig not in seen:
                        seen.add(sig)
                        combined.append(item)
                merged[k] = combined
            elif isinstance(v, dict):
                old = dict(merged.get(k) or {})
                old.update(v)
                merged[k] = old
            elif v is not None:
                merged[k] = v

        elif k in take_max:
            old = merged.get(k) or 0
            merged[k] = max(old, v or 0)

        elif k in preserve_if_better:
            old = merged.get(k)
            old_blank = old in (None, "", "unknown", "Unknown Device")
            new_good = v not in (None, "", "unknown", "Unknown Device")
            if old_blank and new_good:
                merged[k] = v

        else:
            if merged.get(k) is None and v is not None:
                merged[k] = v

    # Preserve strongest risk level
    old_level = (merged.get("risk_level") or "INFO").upper()
    new_level = (new.get("risk_level") or old_level).upper()
    old_rank = _RISK_LEVEL_ORDER.get(old_level, 0)
    new_rank = _RISK_LEVEL_ORDER.get(new_level, 0)
    if new_rank >= old_rank:
        merged["risk_level"] = new.get("risk_level") or merged.get("risk_level")
        merged["risk_hint"] = (merged.get("risk_level") or "INFO").lower()

    return merged

def _merge_discovery_results(
    nmap_results: list[dict],
    mdns_results: list[dict],
    ssdp_results: list[dict],
) -> list[dict]:
    """
    Merge nmap + mDNS + SSDP results into a canonical asset list.

    Identity priority:
      1. MAC address
      2. Stable discovered name
      3. IP fallback

    This prevents the same device being inserted multiple times when
    multiple discovery engines report it differently.
    """
    merged_assets: list[dict] = []
    index: dict[tuple[str, str], int] = {}

    def _add_or_merge(candidate: dict):
        candidate = dict(candidate)
        candidate["mac_address"] = _norm_mac(candidate.get("mac_address"))
        candidate["asset_confidence"] = _asset_confidence(candidate)

        meta = dict(candidate.get("raw_metadata_json") or {})
        meta["asset_confidence"] = candidate["asset_confidence"]
        candidate["raw_metadata_json"] = meta

        matched_idx = None
        for key in _identity_keys(candidate):
            if key in index:
                matched_idx = index[key]
                break

        if matched_idx is None:
            merged_assets.append(candidate)
            idx = len(merged_assets) - 1
            for key in _identity_keys(candidate):
                index[key] = idx
        else:
            merged_assets[matched_idx] = _merge_values(merged_assets[matched_idx], candidate)
            for key in _identity_keys(merged_assets[matched_idx]):
                index[key] = matched_idx

    for r in nmap_results:
        _add_or_merge(r)

    for m in mdns_results:
        ip = m.get("ip")
        if not ip:
            continue
        candidate = {
            "ip_address": ip,
            "hostname": m.get("mdns_name"),
            "netbios_name": None,
            "mdns_name": m.get("mdns_name"),
            "fqdn": m.get("mdns_name"),
            "mac_address": m.get("mac_address"),
            "vendor": m.get("vendor"),
            "device_type": m.get("device_type", "unknown"),
            "device_model": None,
            "device_family": m.get("device_family"),
            "os_guess": None,
            "os_version": None,
            "os_cpe": None,
            "os_confidence": None,
            "firmware_version": None,
            "ttl": None,
            "network_segment": ip.rsplit(".", 1)[0] + ".0/24",
            "vlan": None,
            "open_ports": [],
            "services": [],
            "snmp_data": None,
            "http_headers": None,
            "tls_info": None,
            "banner_data": None,
            "smb_info": None,
            "vulnerabilities": [],
            "cve_count": 0,
            "critical_cve_count": 0,
            "high_cve_count": 0,
            "medium_cve_count": 0,
            "risk_score": 0.0,
            "risk_level": "INFO",
            "risk_hint": "info",
            "risk_factors": [],
            "first_seen": _now_iso(),
            "last_seen": _now_iso(),
            "managed": False,
            "agent_installed": False,
            "is_rogue": False,
            "ce_asset_registered": False,
            "ce_issues": [],
            "raw_metadata_json": {"engine": "mdns", "source": "mdns_discovery"},
        }
        _add_or_merge(candidate)

    for s in ssdp_results:
        ip = s.get("ip")
        if not ip:
            continue
        candidate = {
            "ip_address": ip,
            "hostname": None,
            "netbios_name": None,
            "mdns_name": None,
            "fqdn": None,
            "mac_address": s.get("mac_address"),
            "vendor": s.get("vendor"),
            "device_type": s.get("device_type", "unknown"),
            "device_model": None,
            "device_family": s.get("device_family"),
            "os_guess": None,
            "os_version": None,
            "os_cpe": None,
            "os_confidence": None,
            "firmware_version": None,
            "ttl": None,
            "network_segment": ip.rsplit(".", 1)[0] + ".0/24",
            "vlan": None,
            "open_ports": [],
            "services": [],
            "snmp_data": None,
            "http_headers": None,
            "tls_info": None,
            "banner_data": None,
            "smb_info": None,
            "vulnerabilities": [],
            "cve_count": 0,
            "critical_cve_count": 0,
            "high_cve_count": 0,
            "medium_cve_count": 0,
            "risk_score": 0.0,
            "risk_level": "INFO",
            "risk_hint": "info",
            "risk_factors": [],
            "first_seen": _now_iso(),
            "last_seen": _now_iso(),
            "managed": False,
            "agent_installed": False,
            "is_rogue": False,
            "ce_asset_registered": False,
            "ce_issues": [],
            "raw_metadata_json": {
                "engine": "ssdp",
                "ssdp_server": s.get("ssdp_server"),
                "ssdp_location": s.get("ssdp_location"),
            },
        }
        _add_or_merge(candidate)

    final = []
    for r in merged_assets:
        # Keep strong assets. Keep weak ping-only observations only once per IP.
        if r.get("asset_confidence") == "confirmed_asset":
            final.append(r)
            continue
        if r.get("ip_address"):
            final.append(r)

    print(f"[merge] nmap={len(nmap_results)} mdns={len(mdns_results)} ssdp={len(ssdp_results)} merged={len(final)}")
    return final


def _expand_target(target: str) -> list[str]:
    target = target.strip()
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        if len(hosts) > 512:
            raise ValueError("Target range too large. Use /23 or smaller.")
        return hosts
    if "," in target:
        return [t.strip() for t in target.split(",") if t.strip()]
    return [target]


def _run_fallback(target: str) -> tuple[str, list[dict]]:
    hosts = _expand_target(target)
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(64, max(4, len(hosts)))) as ex:
        futures = {ex.submit(_scan_host_fallback, ip): ip for ip in hosts}
        for f in as_completed(futures):
            item = f.result()
            if item: results.append(item)
    results.sort(key=lambda r: (
        tuple(int(x) for x in r["ip_address"].split("."))
        if r["ip_address"].count(".")==3 and all(p.isdigit() for p in r["ip_address"].split("."))
        else (999,999,999,999)
    ))
    return "fallback_socket_scan", results


# ── DB upsert ─────────────────────────────────────────────────────────────

UPSERT_FIELDS = [
    "scan_job_id","hostname","netbios_name","mdns_name","fqdn",
    "mac_address","vendor","device_type","device_model","device_family",
    "os_guess","os_version","os_cpe","os_confidence","firmware_version","ttl",
    "network_segment","vlan","open_ports","services",
    "snmp_data","http_headers","tls_info","banner_data","smb_info",
    "vulnerabilities","cve_count","critical_cve_count","high_cve_count","medium_cve_count",
    "risk_score","risk_level","risk_hint","risk_factors","last_seen",
    "managed","agent_installed","is_rogue","ce_asset_registered","ce_issues","raw_metadata_json",
]


# ── Agentless software inference storage ─────────────────────────────────
#
# FIX (v2.4.1): The original version used `except Exception: pass` which
# silently swallowed DB errors and left the SQLAlchemy session in a
# rolled-back / invalid state.  Every subsequent db.query() in the same
# loop then also failed, so only the first N assets (those processed before
# the first fingerprint failure) were ever saved  -  producing the "5 assets
# instead of 14" symptom.
#
# Fix: wrap in a savepoint so a failure here never poisons the outer session,
# and log every error so failures are visible in docker logs.
# ─────────────────────────────────────────────────────────────────────────

def _store_agentless_software(db: Session, tenant_id: str, result: dict) -> None:
    """
    Infer software from agentless scan and store in CanonicalSoftware
    so the existing CVE engine can process unmanaged devices.

    Uses a nested savepoint so any DB error here is isolated and does NOT
    corrupt the outer session (which is writing NetworkDiscoveredAsset rows).
    """
    ip = result.get("ip_address", "unknown")
    try:
        # ── Build the lightweight asset dict that fingerprint_asset expects ──
        # Normalise open_ports to a plain list of ints regardless of whether
        # the scan engine returned dicts {"port": N, ...} or raw integers.
        raw_ports = result.get("open_ports", [])
        port_ints = [
            p["port"] if isinstance(p, dict) else int(p)
            for p in raw_ports
            if p is not None
        ]

        asset = {
            "ip":         ip,
            "os":         result.get("os_guess"),
            "open_ports": port_ints,
            "banner":     json.dumps(result.get("services", []))[:500],
        }

        inferred = fingerprint_asset(asset)
        if not inferred:
            return  # nothing to store  -  exit cleanly, no DB touched

        # ── Use a savepoint so failures don't affect the outer transaction ──
        with db.begin_nested():
            for s in inferred:
                name = s.get("name")
                if not name:
                    continue
                exists = (
                    db.query(CanonicalSoftware)
                    .filter(
                        CanonicalSoftware.tenant_id == tenant_id,
                        CanonicalSoftware.agent_id  == ip,
                        CanonicalSoftware.name       == name,
                    )
                    .first()
                )
                if not exists:
                    sw = CanonicalSoftware(
                        tenant_id = tenant_id,
                        agent_id  = ip,
                        name      = name,
                        version   = s.get("version"),
                    )
                    # Only set source if the column exists on the model
                    if hasattr(CanonicalSoftware, "source"):
                        sw.source = "agentless"
                    db.add(sw)

    except Exception as exc:
        # Log clearly so we can see what failed without crashing the scan
        print(f"[agentless_sw] WARN: could not store software for {ip}: {exc}")
        traceback.print_exc()
        # The savepoint above already rolled back its own changes.
        # The outer session is completely unaffected  -  asset saving continues.


# Fields that should only be updated if the new value is better than existing
# (non-None, non-empty, non-"unknown")  -  prevents good data being overwritten
_PRESERVE_IF_BETTER = {
    "device_type", "device_family", "vendor", "hostname",
    "netbios_name", "mdns_name", "mac_address",
    # NOTE: os_guess is NOT here  -  we handle it separately below
    # to allow clearing known-bad values (e.g. Sanyo projector false positives)
}

# OS values known to be nmap false positives on devices with all-filtered ports
# These appear when nmap has no open ports to fingerprint against
# and relies on TCP/IP stack quirks  -  very unreliable in this scenario
_BAD_OS_FINGERPRINTS = {
    "sanyo plc-xu88", "sanyo",
    "cisco sf300", "cisco sg300",
    "intel express 510t", "intel express 520t", "intel express 550t",
    "fritz!box", "avm fritz", "asus wl-500",
    "axis 70u", "brother hl-", "brother mfc-", "ibm 6400",
    "xbox", "xbox game console",
}


def _is_bad_os_fingerprint(os_guess: str | None, open_port_count: int) -> bool:
    """Discard OS guesses that are known nmap false positives.
    When all ports are filtered nmap guesses from TTL only  -  not reliable."""
    if not os_guess:
        return False
    os_lower = os_guess.lower()
    if any(bad in os_lower for bad in _BAD_OS_FINGERPRINTS):
        return True
    if open_port_count == 0:
        return True
    return False

# Fields where higher value wins (risk data  -  take the max)
_TAKE_MAX = {"risk_score"}

# Risk level priority  -  never downgrade a known risk level to INFO
# unless the new scan has actual port/service evidence
_RISK_LEVEL_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Fields that should always be updated (timestamps, ports, services)
_ALWAYS_UPDATE = {
    "last_seen", "open_ports", "services", "scan_job_id",
    "risk_factors", "ce_issues",
    "vulnerabilities", "cve_count", "critical_cve_count",
    "high_cve_count", "medium_cve_count", "raw_metadata_json",
}


def _upsert_discovered_asset(db: Session, tenant_id: str, scan_job_id, result: dict) -> NetworkDiscoveredAsset:
    mac = _norm_mac(result.get("mac_address"))
    if mac:
        result["mac_address"] = mac

    best_name = _norm_name(
        result.get("hostname")
        or result.get("netbios_name")
        or result.get("mdns_name")
        or result.get("fqdn")
    )
    ip = result["ip_address"]

    existing = None

    # 1. Strongest identity: MAC address
    if mac:
        existing = (db.query(NetworkDiscoveredAsset)
                    .filter(NetworkDiscoveredAsset.tenant_id == tenant_id,
                            NetworkDiscoveredAsset.mac_address == mac)
                    .first())

    # 2. Stable discovered name
    if existing is None and best_name:
        existing = (db.query(NetworkDiscoveredAsset)
                    .filter(NetworkDiscoveredAsset.tenant_id == tenant_id)
                    .filter(
                        (NetworkDiscoveredAsset.hostname == best_name) |
                        (NetworkDiscoveredAsset.netbios_name == best_name) |
                        (NetworkDiscoveredAsset.mdns_name == best_name) |
                        (NetworkDiscoveredAsset.fqdn == best_name)
                    )
                    .first())

    # 3. IP fallback
    if existing is None:
        existing = (db.query(NetworkDiscoveredAsset)
                    .filter(NetworkDiscoveredAsset.tenant_id == tenant_id,
                            NetworkDiscoveredAsset.ip_address == ip)
                    .first())

    if existing:
        # Device may have moved IP; inventory identity should survive that
        existing.ip_address = ip

        for f in UPSERT_FIELDS:
            if f not in result:
                continue
            new_val = result[f]

            if f in _TAKE_MAX:
                old_val = getattr(existing, f, None) or 0
                if (new_val or 0) >= old_val:
                    setattr(existing, f, new_val)

            elif f == "os_guess":
                old_val = getattr(existing, f, None)
                old_lower = (old_val or "").lower()
                is_old_bad = any(bad in old_lower for bad in _BAD_OS_FINGERPRINTS)
                is_old_blank = old_val in (None, "", "unknown")
                is_new_good = new_val not in (None, "", "unknown")
                if is_old_bad or is_old_blank:
                    setattr(existing, f, new_val)
                elif is_new_good:
                    setattr(existing, f, new_val)

            elif f in _PRESERVE_IF_BETTER:
                old_val = getattr(existing, f, None)
                is_old_blank = old_val in (None, "", "unknown", "Unknown Device")
                is_new_good = new_val not in (None, "", "unknown", "Unknown Device")
                if is_old_blank and is_new_good:
                    setattr(existing, f, new_val)

            elif f in ("risk_level", "risk_hint"):
                old_level = getattr(existing, f, None) or "INFO"
                new_level = new_val or "INFO"
                old_rank = _RISK_LEVEL_ORDER.get(old_level.upper() if old_level else "INFO", 0)
                new_rank = _RISK_LEVEL_ORDER.get(new_level.upper() if new_level else "INFO", 0)
                if new_rank >= old_rank:
                    setattr(existing, f, new_val)

            elif f in _ALWAYS_UPDATE:
                setattr(existing, f, new_val)

            else:
                if new_val is not None:
                    setattr(existing, f, new_val)

        # Persist confidence metadata without requiring a schema migration
        meta = dict(existing.raw_metadata_json or {})
        new_meta = dict(result.get("raw_metadata_json") or {})
        meta.update(new_meta)
        old_conf = meta.get("asset_confidence", "observed_host")
        new_conf = result.get("asset_confidence") or new_meta.get("asset_confidence") or old_conf
        if old_conf == "observed_host" and new_conf == "confirmed_asset":
            meta["asset_confidence"] = "confirmed_asset"
        else:
            meta["asset_confidence"] = old_conf if old_conf else new_conf
        if mac:
            meta["canonical_key"] = f"mac:{mac}"
        elif best_name:
            meta["canonical_key"] = f"name:{best_name}"
        else:
            meta["canonical_key"] = f"ip:{ip}"
        existing.raw_metadata_json = meta

        existing.scan_job_id = scan_job_id
        return existing

    row = NetworkDiscoveredAsset(tenant_id=tenant_id, scan_job_id=scan_job_id, **{k: v for k, v in result.items() if k in UPSERT_FIELDS or k == "ip_address" or k == "first_seen"})
    meta = dict(row.raw_metadata_json or {})
    meta.update(result.get("raw_metadata_json") or {})
    conf = result.get("asset_confidence") or meta.get("asset_confidence") or "observed_host"
    meta["asset_confidence"] = conf
    if mac:
        meta["canonical_key"] = f"mac:{mac}"
    elif best_name:
        meta["canonical_key"] = f"name:{best_name}"
    else:
        meta["canonical_key"] = f"ip:{ip}"
    row.raw_metadata_json = meta
    db.add(row)
    return row



# ── Cancellation helpers ──────────────────────────────────────────────────

def _is_cancelled(db: Session, job_id: int) -> bool:
    """Check if a scan job has been cancelled by the user."""
    try:
        job = db.query(NetworkScanJob).filter(NetworkScanJob.id == job_id).first()
        return bool(job and job.status == "cancelled")
    except Exception:
        return False


def _abort_if_cancelled(db: Session, job_id: int) -> None:
    """Raise RuntimeError if job was cancelled  -  stops the worker cleanly."""
    if _is_cancelled(db, job_id):
        raise RuntimeError("Scan cancelled by user")


# ── Entry point ───────────────────────────────────────────────────────────

def run_network_scan_job(
    db: Session,
    tenant_id: str,
    target: str,
    requested_by: str | None = None,
    job_id: int | None = None,
):
    if job_id is not None:
        # Reuse existing job created by the async route
        job = (
            db.query(NetworkScanJob)
            .filter(NetworkScanJob.id == job_id,
                    NetworkScanJob.tenant_id == tenant_id)
            .first()
        )
        if not job:
            raise RuntimeError(f"Network scan job {job_id} not found")
        job.status = "running"
        db.commit()
        db.refresh(job)
    else:
        # Synchronous fallback  -  create job here
        job = NetworkScanJob(
            tenant_id    = tenant_id,
            target       = target,
            requested_by = requested_by,
            status       = "running",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

    # ── STEP 1: Mark all existing assets as inactive (stale) ────────────────
    # Qualys/Rapid7/Tenable approach:
    # Active inventory = only what the current scan finds.
    # Old records stay in DB marked inactive  -  full audit trail preserved.
    try:
        db.query(NetworkDiscoveredAsset).filter_by(tenant_id=tenant_id).update(
            {"is_active": False}, synchronize_session=False
        )
        db.commit()
        logger.info("[scan] marked all tenant assets inactive before scan")
    except Exception as _e:
        logger.warning("[scan] is_active mark failed (column may not exist yet): %s", _e)
        db.rollback()

    # ── Write initial progress to job ─────────────────────────────────────
    def _update_progress(phase: str, pct: int, msg: str = "", extra: dict | None = None) -> None:
        """Write scan progress to job.summary_json so UI can poll it."""
        try:
            current = dict(job.summary_json or {})
            current["progress"] = {"phase": phase, "pct": pct, "msg": msg}
            if extra:
                current.update(extra)
            job.summary_json = current
            db.commit()
        except Exception:
            pass

    scan_diag = _build_scan_diagnostics(target)
    _update_progress("Initialising", 5, "Starting multi-engine discovery", {"diagnostics": scan_diag})

    try:
        # ── Multi-engine discovery (Qualys/Rapid7/Tenable approach) ────
        # Run all discovery engines in parallel, then merge results.
        # Each engine finds different device types:
        #   nmap    → computers, servers, routers (port-based)
        #   mDNS    → Apple devices, printers, Chromecast (multicast)
        #   SSDP    → smart TVs, NAS, IoT, cameras (UPnP)
        #   ARP     → added by Windows agent every 5 min (layer 2)

        _update_progress("Host discovery", 10, "Running ping sweep + mDNS + SSDP")

        import concurrent.futures as _cf

        # Run nmap + mDNS + SSDP concurrently
        nmap_results  = []
        mdns_results  = []
        ssdp_results  = []
        engine        = "nmap"

        def _do_nmap():
            nonlocal engine
            try:
                scan_diag['discovery_source'] = 'fresh_nmap_sweep'
                scan_diag['host_hints_used'] = 0
                scan_diag['nmap_strategy'] = 'fresh_discovery_then_deep_scan'
                _update_progress('Host discovery', 18, 'Running fresh Nmap host discovery', {'diagnostics': scan_diag})
                e, r = _run_nmap(target, live_ips=None)
                engine = e
                scan_diag['selected_engine'] = e
                scan_diag['nmap_result_count'] = len(r or [])
                return r
            except Exception as ex:
                err = f'{type(ex).__name__}: {ex}'
                tb = traceback.format_exc(limit=12)
                logger.warning('[scan] nmap failed, using socket fallback: %s', err)
                scan_diag['selected_engine'] = 'fallback_socket_scan'
                scan_diag['nmap_error'] = err
                scan_diag['nmap_traceback'] = tb[-4000:]
                _update_progress('Fallback scanner', 24, f'Nmap failed, using socket fallback: {err[:180]}', {'diagnostics': scan_diag, 'nmap_error': err})
                try:
                    e, r = _run_fallback(target)
                    engine = e
                    scan_diag['fallback_result_count'] = len(r or [])
                    return r
                except Exception as fallback_ex:
                    ferr = f'{type(fallback_ex).__name__}: {fallback_ex}'
                    scan_diag['fallback_error'] = ferr
                    scan_diag['fallback_traceback'] = traceback.format_exc(limit=12)[-4000:]
                    _update_progress('Failed', 100, ferr[:180], {'diagnostics': scan_diag, 'error': ferr})
                    return []
        with _cf.ThreadPoolExecutor(max_workers=3) as ex:
            fut_nmap  = ex.submit(_do_nmap)
            fut_mdns  = ex.submit(_run_mdns_discovery, 3.0)
            fut_ssdp  = ex.submit(_run_ssdp_discovery, 3.0)
            nmap_results = fut_nmap.result()
            mdns_results = fut_mdns.result()
            ssdp_results = fut_ssdp.result()

        # Merge all engine results
        results = _merge_discovery_results(nmap_results, mdns_results, ssdp_results)
        print(f"[network_scan] discovered {len(results)} hosts via {engine}+mdns+ssdp")
        _abort_if_cancelled(db, job.id)
        _update_progress("Saving results", 75,
                         f"Found {len(results)} hosts  -  saving to inventory")
        _abort_if_cancelled(db, job.id)

        # ── PHASE 1: save all discovered assets (critical path) ──────────
        stored = []
        for i, result in enumerate(results, start=1):
            _abort_if_cancelled(db, job.id)
            try:
                row = _upsert_discovered_asset(db, tenant_id, job.id, result)
                try:
                    row.is_active = True
                except AttributeError:
                    pass  # Column not yet migrated
                if i == 1 or i % 5 == 0 or i == len(results):
                    _update_progress(
                        "Saving results",
                        min(90, 75 + int((i / max(len(results), 1)) * 15)),
                        f"Saved {i} of {len(results)} assets",
                    )
                stored.append(row)
                print(f"[network_scan] saved asset: {result.get('ip_address')}")
            except Exception as exc:
                print(f"[network_scan] ERROR saving asset {result.get('ip_address')}: {exc}")
                traceback.print_exc()
                db.rollback()   # restore session so next asset can still be saved
                # re-open the transaction
                db.begin()

        # Commit all asset rows before touching anything else
        db.commit()
        print(f"[network_scan] committed {len(stored)} assets to DB")

        # ── PHASE 2b: Device name enrichment ─────────────────────────────
        # For assets still missing a hostname, run multi-protocol name
        # discovery (NetBIOS, mDNS, LLMNR, UPnP, SNMP, SSH, HTTP).
        # This mirrors Qualys/Rapid7/Nessus post-scan enrichment.
        _abort_if_cancelled(db, job.id)
        _update_progress("Hostname enrichment", 92, "Resolving device names")

        blank_name_assets = [
            a for a in stored
            if not (a.hostname or a.netbios_name or a.mdns_name)
        ]
        if blank_name_assets:
            try:
                from services.device_name_discovery import batch_discover_device_names
                blank_ips = [a.ip_address for a in blank_name_assets if a.ip_address]
                print(f"[device_names] enriching {len(blank_ips)} assets with blank hostnames")
                name_results = batch_discover_device_names(blank_ips, max_workers=16)
                for asset in blank_name_assets:
                    result = name_results.get(asset.ip_address)
                    if not result or not result.get("name"):
                        continue
                    name   = result["name"]
                    source = result["source"]
                    extra  = result.get("extra", {})
                    if source == "NetBIOS/NBNS":
                        if not asset.netbios_name: asset.netbios_name = name
                        if not asset.hostname:     asset.hostname     = name
                        if extra.get("workgroup"): asset.domain       = extra["workgroup"]
                    elif source == "mDNS/Bonjour":
                        if not asset.mdns_name: asset.mdns_name = name
                        if not asset.hostname:  asset.hostname  = extra.get("fqdn") or name
                    elif source in ("LLMNR","SNMP sysName","SSH Banner",
                                    "HTTP Title","UPnP/SSDP","Reverse DNS"):
                        if not asset.hostname: asset.hostname = name
                    if source == "UPnP/SSDP":
                        if extra.get("model") and not asset.device_model:
                            asset.device_model = extra["model"]
                        if extra.get("manufacturer") and not asset.vendor:
                            asset.vendor = extra["manufacturer"]
                    print(f"[device_names] {asset.ip_address} -> '{name}' via {source}")
                db.commit()
            except Exception as exc:
                print(f"[device_names] enrichment error: {exc}")

        # ── PHASE 2: infer software (non-critical, isolated) ─────────────
        for result in results:
            _store_agentless_software(db, tenant_id, result)
        try:
            db.commit()
        except Exception as exc:
            print(f"[network_scan] WARN: software commit failed (non-fatal): {exc}")
            db.rollback()

        # ── Finalise job ─────────────────────────────────────────────────
        # Get total inventory count at this point in time
        # This is what the dashboard and archive should both display
        try:
            total_inventory = db.query(NetworkDiscoveredAsset).filter(
                NetworkDiscoveredAsset.tenant_id == tenant_id,
                NetworkDiscoveredAsset.is_active == True,
            ).count()
        except Exception:
            total_inventory = db.query(NetworkDiscoveredAsset).filter(
                NetworkDiscoveredAsset.tenant_id == tenant_id
            ).count()

        # Build frozen snapshot  -  each asset's state at scan time
        # This is what "View" on old scans will show  -  immutable archive
        snapshot_assets = []
        for r in results:
            snapshot_assets.append({
                "ip":          r.get("ip_address"),
                "hostname":    r.get("hostname") or r.get("netbios_name") or r.get("mdns_name"),
                "mac":         r.get("mac_address"),
                "vendor":      r.get("vendor"),
                "device_type": r.get("device_type"),
                "os_guess":    r.get("os_guess"),
                "risk_level":  r.get("risk_level"),
                "risk_score":  r.get("risk_score"),
                "open_ports":  [p.get("port") for p in (r.get("open_ports") or [])],
                "ce_issues":   r.get("ce_issues") or [],
                "confidence":  r.get("asset_confidence", "confirmed_asset"),
            })

        job.status = "completed"
        job.engine = engine
        job.summary_json = {
            "target":                target,
            "engine":                engine,
            "discovered_count":      len(results),
            "saved_count":           len(stored),
            "total_inventory_count": total_inventory,
            "active_count":          sum(1 for a in snapshot_assets
                                         if a.get("confidence") == "confirmed_asset"),
            "mdns_count":            len(mdns_results),
            "ssdp_count":            len(ssdp_results),
            "device_types":          sorted({r.get("device_type", "unknown") for r in results}),
            "risk_breakdown": {
                "CRITICAL": sum(1 for r in results if r.get("risk_level") == "CRITICAL"),
                "HIGH":     sum(1 for r in results if r.get("risk_level") == "HIGH"),
                "MEDIUM":   sum(1 for r in results if r.get("risk_level") == "MEDIUM"),
                "LOW":      sum(1 for r in results if r.get("risk_level") == "LOW"),
                "INFO":     sum(1 for r in results if r.get("risk_level") == "INFO"),
            },
            "total_cves":    sum(r.get("cve_count", 0) for r in results),
            "critical_cves": sum(r.get("critical_cve_count", 0) for r in results),
            # FROZEN SNAPSHOT  -  immutable archive of this scan's findings
            # Used by "View" on scan history  -  shows exact state at scan time
            "snapshot":      snapshot_assets,
            "diagnostics":   {**scan_diag, 'finished_at': _now_iso()},
            "progress":      {"phase": "Completed", "pct": 100, "msg": "Scan complete"},
        }
        db.commit()
        return job, stored

    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass

        current_job = (
            db.query(NetworkScanJob)
            .filter(NetworkScanJob.id == job.id)
            .first()
        )

        if current_job and current_job.status == "cancelled":
            current_job.summary_json = {
                **(current_job.summary_json or {}),
                "progress": {"phase": "Cancelled", "pct": 100,
                             "msg": "Scan cancelled by user"},
            }
            db.commit()
            logger.info("[scan] job %s cancelled cleanly", job.id)
            return current_job, []

        if current_job:
            current_job.status = "failed"
            current_job.summary_json = {
                **(current_job.summary_json or {}),
                "error": str(exc),
                "diagnostics": {**scan_diag, 'fatal_error': str(exc), 'failed_at': _now_iso()},
                "progress": {"phase": "Failed", "pct": 100, "msg": str(exc)},
            }
            db.commit()

        logger.exception("[scan] job %s failed: %s", job.id, exc)
        raise
