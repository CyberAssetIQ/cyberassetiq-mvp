from __future__ import annotations

import json
import logging
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger("cyberassetiq.external")

# ---------------------------------------------------------------------------
# Port risk database
# ---------------------------------------------------------------------------

EXTERNAL_RISKY_PORTS: dict[int, tuple[str, str, str, str]] = {
    # port: (title, severity, description, remediation)
    21:    ("FTP Exposed to Internet", "HIGH",
            "FTP transmits credentials in plaintext. Exposed to the public internet.",
            "Disable FTP. Use SFTP or FTPS. If required, restrict to specific IPs via firewall."),
    22:    ("SSH Exposed to Internet", "MEDIUM",
            "SSH is exposed. While encrypted, public exposure enables brute-force attacks.",
            "Restrict SSH to specific management IPs. Use key-based auth only. Disable password auth."),
    23:    ("Telnet Exposed to Internet", "CRITICAL",
            "Telnet transmits all data including credentials in plaintext.",
            "Disable Telnet immediately. Replace with SSH."),
    25:    ("SMTP Exposed to Internet", "MEDIUM",
            "SMTP port exposed — potential mail relay abuse or banner information disclosure.",
            "Restrict SMTP to authorised mail servers only."),
    53:    ("DNS Exposed to Internet", "MEDIUM",
            "DNS service publicly accessible — potential for DNS amplification DDoS.",
            "Restrict DNS to internal networks unless running a public resolver."),
    80:    ("HTTP Exposed to Internet", "LOW",
            "HTTP service accessible. Unencrypted traffic may expose sensitive data.",
            "Redirect HTTP to HTTPS. Ensure no sensitive data served over HTTP."),
    110:   ("POP3 Exposed to Internet", "MEDIUM",
            "POP3 mail service exposed. May transmit credentials in plaintext.",
            "Disable POP3 or enforce TLS. Use modern email clients."),
    135:   ("RPC Exposed to Internet", "CRITICAL",
            "Windows RPC exposed to internet — primary vector for remote exploitation.",
            "Block port 135 at perimeter firewall immediately."),
    139:   ("NetBIOS Exposed to Internet", "CRITICAL",
            "NetBIOS exposed — enables reconnaissance and lateral movement.",
            "Block ports 137-139 at perimeter firewall."),
    143:   ("IMAP Exposed to Internet", "MEDIUM",
            "IMAP mail service exposed. May allow credential harvesting.",
            "Disable IMAP or enforce TLS only."),
    443:   ("HTTPS Exposed to Internet", "INFO",
            "HTTPS service publicly accessible. Expected for web services.",
            "Ensure TLS configuration is current (TLS 1.2+). Run regular certificate checks."),
    445:   ("SMB Exposed to Internet", "CRITICAL",
            "SMB/Windows file sharing exposed to internet. Exploited by EternalBlue, WannaCry.",
            "Block port 445 at perimeter firewall immediately. This is a critical vulnerability."),
    1433:  ("MSSQL Exposed to Internet", "CRITICAL",
            "Microsoft SQL Server database port exposed to internet.",
            "Block port 1433 at perimeter firewall. Database should never be internet-facing."),
    1521:  ("Oracle DB Exposed to Internet", "CRITICAL",
            "Oracle database port exposed to internet.",
            "Block port 1521 at perimeter firewall."),
    2375:  ("Docker API Exposed (Unencrypted)", "CRITICAL",
            "Unencrypted Docker daemon API exposed — allows full container/host takeover.",
            "Disable Docker TCP socket or enforce TLS mutual auth immediately."),
    2376:  ("Docker API Exposed (TLS)", "HIGH",
            "Docker daemon API exposed with TLS — verify certificate configuration.",
            "Restrict Docker API access to management IPs only."),
    3306:  ("MySQL Exposed to Internet", "CRITICAL",
            "MySQL database port exposed to internet.",
            "Block port 3306 at perimeter firewall."),
    3389:  ("RDP Exposed to Internet", "CRITICAL",
            "Remote Desktop Protocol exposed to internet — top ransomware entry vector.",
            "Block RDP from internet immediately. Use VPN for remote access."),
    4444:  ("Common Backdoor Port Open", "CRITICAL",
            "Port 4444 is commonly associated with Metasploit and malware C2 channels.",
            "Investigate immediately — this may indicate active compromise."),
    5432:  ("PostgreSQL Exposed to Internet", "CRITICAL",
            "PostgreSQL database port exposed to internet.",
            "Block port 5432 at perimeter firewall."),
    5900:  ("VNC Exposed to Internet", "CRITICAL",
            "VNC remote desktop exposed to internet. Often uses weak authentication.",
            "Block VNC from internet. Use VPN for remote access."),
    5984:  ("CouchDB Exposed to Internet", "CRITICAL",
            "CouchDB admin interface exposed — default config allows unauthenticated access.",
            "Block port 5984 at perimeter firewall."),
    6379:  ("Redis Exposed to Internet", "CRITICAL",
            "Redis has no authentication by default. Public exposure = full data access.",
            "Block port 6379 at perimeter firewall. Enable Redis authentication."),
    8080:  ("HTTP Alt Port Exposed", "MEDIUM",
            "Alternate HTTP port exposed — may host admin panels or development services.",
            "Restrict to authorised IPs or move behind HTTPS with authentication."),
    8443:  ("HTTPS Alt Port Exposed", "LOW",
            "Alternate HTTPS port exposed.",
            "Verify this service is intentionally public."),
    9200:  ("Elasticsearch Exposed to Internet", "CRITICAL",
            "Elasticsearch has no authentication by default. Billions of records leaked this way.",
            "Block port 9200 at perimeter firewall immediately."),
    27017: ("MongoDB Exposed to Internet", "CRITICAL",
            "MongoDB has no authentication by default. Major source of data breaches.",
            "Block port 27017 at perimeter firewall immediately."),
}

# Ports that are expected/acceptable for web servers
EXPECTED_WEB_PORTS = {80, 443, 8080, 8443}


# ---------------------------------------------------------------------------
# Public IP detection
# ---------------------------------------------------------------------------

def get_public_ip() -> str | None:
    services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://api4.my-ip.io/ip",
    ]
    for url in services:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CyberAssetIQ/2.4"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                ip = resp.read().decode().strip()
                if ip and len(ip) < 16:
                    return ip
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Nmap external scan
# ---------------------------------------------------------------------------

def _run_nmap_external(public_ip: str) -> list[dict]:
    """Scan public IP for open ports. Returns list of {port, service, banner}."""
    # Common risky ports + web ports — targeted scan, not full port sweep
    target_ports = ",".join(str(p) for p in sorted(EXTERNAL_RISKY_PORTS.keys()))

    cmd = [
        "nmap",
        "-sV",          # service version detection
        "--open",       # only show open ports
        "-T4",          # aggressive timing
        "--host-timeout", "120s",
        "-p", target_ports,
        "--script", "banner",
        "-oX", "-",     # XML output to stdout
        public_ip,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return _parse_nmap_xml(result.stdout)
    except FileNotFoundError:
        logger.warning("nmap not found — falling back to socket probe")
        return _socket_probe(public_ip)
    except Exception as exc:
        logger.warning("nmap external scan failed: %s", exc)
        return _socket_probe(public_ip)


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    """Parse nmap XML output into list of open ports."""
    import xml.etree.ElementTree as ET
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port_el.get("portid", 0))
                service_el = port_el.find("service")
                service = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                banner = f"{product} {version}".strip()

                # Get banner script output
                for script in port_el.findall("script"):
                    if script.get("id") == "banner":
                        banner = script.get("output", banner)[:200]
                        break

                ports.append({
                    "port":    portid,
                    "service": service,
                    "banner":  banner,
                })
    except Exception as exc:
        logger.warning("nmap XML parse error: %s", exc)
    return ports


def _socket_probe(public_ip: str) -> list[dict]:
    """Fallback: TCP socket probe for common ports."""
    import socket
    open_ports = []
    probe_ports = list(EXTERNAL_RISKY_PORTS.keys())

    for port in probe_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((public_ip, port))
            sock.close()
            if result == 0:
                open_ports.append({"port": port, "service": "", "banner": ""})
        except Exception:
            pass

    return open_ports


# ---------------------------------------------------------------------------
# Build findings from open ports
# ---------------------------------------------------------------------------

def _build_findings(open_ports: list[dict]) -> list[dict]:
    findings = []
    for p in open_ports:
        port = p["port"]
        if port not in EXTERNAL_RISKY_PORTS:
            # Unknown open port
            findings.append({
                "port":        port,
                "service":     p.get("service", "unknown"),
                "severity":    "MEDIUM",
                "title":       f"Unknown Service on Port {port} Exposed",
                "description": f"Port {port} is open on your public IP. Service: {p.get('service', 'unknown')}.",
                "remediation": "Verify this port is intentionally exposed. If not required, close it at the firewall.",
            })
        else:
            title, severity, description, remediation = EXTERNAL_RISKY_PORTS[port]
            # Downgrade INFO to not count as findings
            findings.append({
                "port":        port,
                "service":     p.get("service", ""),
                "banner":      p.get("banner", ""),
                "severity":    severity,
                "title":       title,
                "description": description,
                "remediation": remediation,
            })
    return findings


# ---------------------------------------------------------------------------
# Run full external scan
# ---------------------------------------------------------------------------

def run_external_scan(db: Session, tenant_id: str) -> dict:
    from models.external_exposure import ExternalScan, ExternalFinding

    start = time.time()

    # Create scan record
    scan = ExternalScan(tenant_id=tenant_id, scan_status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Step 1: Get public IP
        public_ip = get_public_ip()
        if not public_ip:
            scan.scan_status = "failed"
            scan.error = "Could not determine public IP address"
            db.commit()
            return {"error": "Could not determine public IP"}

        scan.public_ip = public_ip
        db.commit()

        # Step 2: Nmap scan
        logger.info("Running external scan against public IP: %s", public_ip)
        open_ports = _run_nmap_external(public_ip)

        # Step 3: Build findings
        findings = _build_findings(open_ports)

        # Step 4: Save individual findings
        for f in findings:
            if f.get("severity") == "INFO":
                continue
            db.add(ExternalFinding(
                tenant_id   = tenant_id,
                scan_id     = scan.id,
                public_ip   = public_ip,
                port        = f.get("port"),
                service     = f.get("service", ""),
                banner      = f.get("banner", ""),
                severity    = f["severity"],
                title       = f["title"],
                description = f["description"],
                remediation = f["remediation"],
            ))

        # Step 5: Update scan record
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high     = sum(1 for f in findings if f.get("severity") == "HIGH")
        total    = sum(1 for f in findings if f.get("severity") != "INFO")

        scan.scan_status     = "completed"
        scan.open_ports_json = open_ports
        scan.findings_json   = [f for f in findings if f.get("severity") != "INFO"]
        scan.total_findings  = total
        scan.critical_count  = critical
        scan.high_count      = high
        scan.scan_duration_s = int(time.time() - start)
        db.commit()

        logger.info("External scan complete: IP=%s ports=%d findings=%d critical=%d",
                    public_ip, len(open_ports), total, critical)

        return {
            "scan_id":       scan.id,
            "public_ip":     public_ip,
            "open_ports":    len(open_ports),
            "total_findings": total,
            "critical":      critical,
            "high":          high,
            "duration_s":    scan.scan_duration_s,
        }

    except Exception as exc:
        scan.scan_status = "failed"
        scan.error = str(exc)
        db.commit()
        logger.exception("External scan failed: %s", exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_latest_scan(db: Session, tenant_id: str) -> dict | None:
    from models.external_exposure import ExternalScan

    scan = db.query(ExternalScan).filter(
        ExternalScan.tenant_id == tenant_id,
        ExternalScan.scan_status == "completed",
    ).order_by(desc(ExternalScan.id)).first()

    if not scan:
        return None

    return {
        "scan_id":        scan.id,
        "public_ip":      scan.public_ip,
        "scanned_at":     scan.scanned_at.isoformat() if scan.scanned_at else None,
        "total_findings": scan.total_findings,
        "critical_count": scan.critical_count,
        "high_count":     scan.high_count,
        "open_ports":     scan.open_ports_json or [],
        "findings":       scan.findings_json or [],
        "duration_s":     scan.scan_duration_s,
    }


def get_scan_history(db: Session, tenant_id: str) -> list[dict]:
    from models.external_exposure import ExternalScan

    rows = db.query(ExternalScan).filter(
        ExternalScan.tenant_id == tenant_id,
    ).order_by(desc(ExternalScan.id)).limit(20).all()

    return [
        {
            "scan_id":        r.id,
            "public_ip":      r.public_ip,
            "scanned_at":     r.scanned_at.isoformat() if r.scanned_at else None,
            "scan_status":    r.scan_status,
            "total_findings": r.total_findings,
            "critical_count": r.critical_count,
            "high_count":     r.high_count,
            "duration_s":     r.scan_duration_s,
        }
        for r in rows
    ]


def resolve_finding(db: Session, tenant_id: str, finding_id: int, status: str) -> dict:
    from models.external_exposure import ExternalFinding

    f = db.query(ExternalFinding).filter(
        ExternalFinding.id == finding_id,
        ExternalFinding.tenant_id == tenant_id,
    ).first()
    if not f:
        return {"error": "Finding not found"}
    f.status = status
    db.commit()
    return {"id": finding_id, "status": status}
