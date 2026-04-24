"""
services/integration_service.py
Handles connections to external security tools:
- Greenbone/OpenVAS (GMP API)
- Splunk (HEC)
- Wappalyzer (REST API)
- Metasploit (RPC API)
- Burp Suite (REST API)
- Bloodhound (Neo4j)
- Sigma (export)
- QRadar (CEF syslog)
"""
from __future__ import annotations
import json
import logging
import socket
import time
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)


# ── DB helpers ────────────────────────────────────────────────────────────────

def get_config(db: Session, tenant_id: str, key: str) -> dict | None:
    row = db.execute(
        text("SELECT * FROM integration_configs WHERE tenant_id=:t AND integration_key=:k"),
        {"t": tenant_id, "k": key}
    ).fetchone()
    return dict(row._mapping) if row else None


def upsert_config(db: Session, tenant_id: str, key: str, display_name: str,
                  host: str | None = None, port: int | None = None,
                  api_key: str | None = None, username: str | None = None,
                  password: str | None = None, extra: dict | None = None,
                  enabled: bool = False) -> dict:
    existing = get_config(db, tenant_id, key)
    if existing:
        db.execute(text("""
            UPDATE integration_configs SET
                host=:host, port=:port, api_key=:api_key,
                username=:username, password_enc=:password,
                extra_config=:extra, is_enabled=:enabled,
                updated_at=NOW()
            WHERE tenant_id=:t AND integration_key=:k
        """), {"t": tenant_id, "k": key, "host": host, "port": port,
               "api_key": api_key, "username": username, "password": password,
               "extra": json.dumps(extra or {}), "enabled": enabled})
    else:
        db.execute(text("""
            INSERT INTO integration_configs
              (tenant_id, integration_key, display_name, host, port, api_key,
               username, password_enc, extra_config, is_enabled)
            VALUES (:t,:k,:dn,:host,:port,:api_key,:username,:password,:extra,:enabled)
        """), {"t": tenant_id, "k": key, "dn": display_name, "host": host,
               "port": port, "api_key": api_key, "username": username,
               "password": password, "extra": json.dumps(extra or {}),
               "enabled": enabled})
    db.commit()
    return get_config(db, tenant_id, key)


def save_test_result(db: Session, tenant_id: str, key: str, ok: bool, msg: str):
    db.execute(text("""
        UPDATE integration_configs
        SET last_tested_at=NOW(), last_test_ok=:ok, last_test_msg=:msg
        WHERE tenant_id=:t AND integration_key=:k
    """), {"t": tenant_id, "k": key, "ok": ok, "msg": msg[:500]})
    db.commit()


def list_configs(db: Session, tenant_id: str) -> list[dict]:
    rows = db.execute(
        text("SELECT * FROM integration_configs WHERE tenant_id=:t ORDER BY integration_key"),
        {"t": tenant_id}
    ).fetchall()
    return [dict(r._mapping) for r in rows]


# ── Generic TCP reachability test ─────────────────────────────────────────────

def tcp_reachable(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, f"TCP {host}:{port} reachable"
    except Exception as e:
        return False, f"TCP {host}:{port} unreachable: {e}"


# ── Greenbone / OpenVAS ───────────────────────────────────────────────────────

def test_greenbone(host: str, port: int = 9390,
                   username: str = "admin", password: str = "") -> tuple[bool, str]:
    """Test GMP connection to Greenbone/OpenVAS."""
    ok, msg = tcp_reachable(host, port)
    if not ok:
        return False, msg
    try:
        import socket as _s
        s = _s.create_connection((host, port), timeout=5)
        # GMP sends a banner on connect
        banner = s.recv(256).decode("utf-8", errors="ignore")
        s.close()
        if "gvmd" in banner.lower() or "openvas" in banner.lower() or "<" in banner:
            return True, f"Greenbone/OpenVAS responding at {host}:{port}"
        return True, f"Connected to {host}:{port} (banner: {banner[:60]})"
    except Exception as e:
        return False, str(e)


def pull_greenbone_results(host: str, port: int, username: str, password: str,
                           db: Session, tenant_id: str) -> dict:
    """
    Pull completed scan results from Greenbone via GMP XML protocol.
    Imports findings into vulnerability_findings table.
    """
    try:
        import socket as _s
        # GMP XML protocol
        s = _s.create_connection((host, port), timeout=10)
        # Authenticate
        auth_xml = (
            f'<authenticate>'
            f'<credentials><username>{username}</username>'
            f'<password>{password}</password></credentials>'
            f'</authenticate>'
        )
        s.sendall(auth_xml.encode())
        time.sleep(0.5)
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        if "status=\"200\"" not in resp:
            s.close()
            return {"ok": False, "error": "Authentication failed", "imported": 0}

        # Get reports
        s.sendall(b'<get_reports filter="rows=50 sort-reverse=date"/>')
        time.sleep(1)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"</get_reports_response>" in data:
                break
        s.close()

        xml_str = data.decode("utf-8", errors="ignore")
        # Parse results (basic XML parsing without lxml dependency)
        import re as _re
        cves = _re.findall(r'<cve>([^<]+)</cve>', xml_str)
        hosts = _re.findall(r'<host>([^<]+)</host>', xml_str)
        severities = _re.findall(r'<severity>([^<]+)</severity>', xml_str)

        imported = 0
        for i, cve in enumerate(cves[:100]):
            cve = cve.strip()
            if not cve.startswith("CVE-"):
                continue
            host_val = hosts[i] if i < len(hosts) else "unknown"
            sev_val = float(severities[i]) if i < len(severities) else 0.0
            sev_label = "CRITICAL" if sev_val >= 9 else "HIGH" if sev_val >= 7 else "MEDIUM" if sev_val >= 4 else "LOW"
            try:
                db.execute(text("""
                    INSERT INTO vulnerability_findings
                      (tenant_id, cve_id, severity, cvss_score, software_name,
                       software_version, agent_id, source, status, scan_run_id)
                    VALUES (:t,:cve,:sev,:cvss,'Unknown (Greenbone)',
                            'unknown',:host,'greenbone','open',0)
                    ON CONFLICT (tenant_id, cve_id, agent_id, software_name) DO NOTHING
                """), {"t": tenant_id, "cve": cve, "sev": sev_label,
                       "cvss": sev_val, "host": host_val})
                imported += 1
            except Exception:
                pass
        db.commit()
        return {"ok": True, "imported": imported, "cves_found": len(cves)}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}


# ── Splunk HEC ────────────────────────────────────────────────────────────────

def test_splunk(host: str, port: int = 8088, hec_token: str = "") -> tuple[bool, str]:
    """Test Splunk HEC endpoint."""
    ok, msg = tcp_reachable(host, port)
    if not ok:
        return False, msg
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f"https://{host}:{port}/services/collector/health",
            headers={"Authorization": f"Splunk {hec_token}"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            body = r.read().decode()
            if r.status == 200:
                return True, "Splunk HEC healthy"
            return False, f"Splunk HEC status {r.status}: {body[:100]}"
    except Exception as e:
        return False, f"Splunk HEC error: {e}"


def push_to_splunk(host: str, port: int, hec_token: str,
                   events: list[dict]) -> dict:
    """Push events to Splunk via HEC."""
    try:
        import urllib.request, urllib.error, ssl, json as _json
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        payload = "\n".join(
            _json.dumps({"time": time.time(), "source": "cyberassetiq",
                         "sourcetype": "_json", "event": e})
            for e in events
        )
        req = urllib.request.Request(
            f"https://{host}:{port}/services/collector/event",
            data=payload.encode(),
            headers={"Authorization": f"Splunk {hec_token}",
                     "Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            body = r.read().decode()
            return {"ok": True, "sent": len(events), "response": body}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}


# ── Wappalyzer ────────────────────────────────────────────────────────────────

def test_wappalyzer(api_key: str) -> tuple[bool, str]:
    """Test Wappalyzer API key."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.wappalyzer.com/v2/lookup/?urls=https://example.com",
            headers={"x-api-key": api_key}
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            if r.status == 200:
                return True, "Wappalyzer API key valid"
            return False, f"Wappalyzer status {r.status}"
    except Exception as e:
        return False, f"Wappalyzer error: {e}"


def wappalyzer_lookup(api_key: str, url: str) -> dict:
    """Look up technologies for a URL."""
    try:
        import urllib.request, urllib.parse, json as _json
        encoded = urllib.parse.quote(url, safe='')
        req = urllib.request.Request(
            f"https://api.wappalyzer.com/v2/lookup/?urls={encoded}",
            headers={"x-api-key": api_key}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = _json.loads(r.read().decode())
            return {"ok": True, "url": url, "technologies": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Metasploit RPC ────────────────────────────────────────────────────────────

def test_metasploit(host: str, port: int = 55553,
                    username: str = "msf", password: str = "") -> tuple[bool, str]:
    """Test Metasploit RPC connection."""
    ok, msg = tcp_reachable(host, port)
    if not ok:
        return False, msg
    try:
        import urllib.request, json as _json
        payload = _json.dumps({
            "method": "auth.login",
            "params": [username, password]
        }).encode()
        req = urllib.request.Request(
            f"http://{host}:{port}/api/v1/auth/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = _json.loads(r.read().decode())
            if data.get("result") == "success" or "token" in data:
                return True, "Metasploit RPC authenticated"
            return False, f"Metasploit auth failed: {data}"
    except Exception as e:
        return False, f"Metasploit RPC error: {e}"


# ── Burp Suite REST ───────────────────────────────────────────────────────────

def test_burpsuite(host: str, port: int = 1337, api_key: str = "") -> tuple[bool, str]:
    """Test Burp Suite Enterprise REST API."""
    ok, msg = tcp_reachable(host, port)
    if not ok:
        return False, msg
    try:
        import urllib.request, json as _json
        req = urllib.request.Request(
            f"http://{host}:{port}/api/v1/",
            headers={"Authorization": f"token {api_key}"} if api_key else {}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            if r.status == 200:
                return True, "Burp Suite REST API reachable"
            return False, f"Burp Suite status {r.status}"
    except Exception as e:
        return False, f"Burp Suite error: {e}"


# ── Bloodhound Neo4j ──────────────────────────────────────────────────────────

def test_bloodhound(host: str, port: int = 7687,
                    username: str = "neo4j", password: str = "") -> tuple[bool, str]:
    """Test Bloodhound Neo4j bolt connection."""
    ok, msg = tcp_reachable(host, port)
    if not ok:
        return False, msg
    return True, f"Bloodhound Neo4j port {port} reachable at {host}"


# ── QRadar syslog ─────────────────────────────────────────────────────────────

def test_qradar(host: str, port: int = 514) -> tuple[bool, str]:
    """Test QRadar syslog reachability."""
    ok, msg = tcp_reachable(host, port)
    return ok, msg


def push_to_qradar(host: str, port: int, events: list[dict]) -> dict:
    """Forward events to QRadar via CEF syslog (UDP)."""
    try:
        import socket as _s, time as _t
        sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sent = 0
        for event in events:
            cef = (
                f"CEF:0|CyberAssetIQ|Platform|1.0|{event.get('type','alert')}|"
                f"{event.get('title','Security Event')}|{event.get('severity',5)}|"
                f"msg={event.get('summary','')}"
            )
            syslog_msg = f"<14>{cef}".encode("utf-8")
            sock.sendto(syslog_msg, (host, port))
            sent += 1
        sock.close()
        return {"ok": True, "sent": sent}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}


# ── Sigma export ──────────────────────────────────────────────────────────────

def export_sigma_rules(db: Session, tenant_id: str) -> list[dict]:
    """Export CyberAssetIQ detection patterns as Sigma rules."""
    try:
        rows = db.execute(text("""
            SELECT title, summary, severity, metadata_json
            FROM ai_alerts
            WHERE tenant_id=:t AND status='open'
            ORDER BY created_at DESC LIMIT 50
        """), {"t": tenant_id}).fetchall()
    except Exception:
        rows = []

    rules = []
    for r in rows:
        meta = r.metadata_json or {}
        rule = {
            "title": r.title,
            "status": "experimental",
            "description": r.summary or "",
            "level": (r.severity or "medium").lower(),
            "tags": [f"attack.{meta.get('mitre_tactic','unknown')}"] if meta.get("mitre_tactic") else [],
            "detection": {
                "keywords": [r.title],
                "condition": "keywords"
            },
            "logsource": {"product": "windows", "service": "security"},
            "falsepositives": ["Unknown"],
            "author": "CyberAssetIQ",
        }
        rules.append(rule)
    return rules


# ── Master test dispatcher ────────────────────────────────────────────────────

def test_integration(key: str, config: dict) -> tuple[bool, str]:
    host     = config.get("host", "")
    port     = config.get("port")
    api_key  = config.get("api_key", "")
    username = config.get("username", "")
    password = config.get("password_enc", "")

    if key == "greenbone":
        return test_greenbone(host, port or 9390, username, password)
    elif key == "splunk":
        return test_splunk(host, port or 8088, api_key)
    elif key == "wappalyzer":
        return test_wappalyzer(api_key)
    elif key == "metasploit":
        return test_metasploit(host, port or 55553, username, password)
    elif key == "burpsuite":
        return test_burpsuite(host, port or 1337, api_key)
    elif key == "bloodhound":
        return test_bloodhound(host, port or 7687, username, password)
    elif key == "qradar":
        return test_qradar(host, port or 514)
    elif key == "nmap":
        return True, "Nmap is built-in — always available"
    elif key == "sigma":
        return True, "Sigma export is built-in — no connection needed"
    else:
        return False, f"Unknown integration: {key}"
