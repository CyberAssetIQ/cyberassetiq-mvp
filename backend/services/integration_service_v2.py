"""
services/integration_service_v2.py
CyberAssetIQ — Full Integration Service
Connectors for all 20 integrated tools.
"""
from __future__ import annotations
import json, logging, socket, time, urllib.request, urllib.parse, ssl
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)

# ── SSL context (skip verify for internal tools) ─────────────────────────────
def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _http(url, method="GET", headers=None, data=None, timeout=10):
    req = urllib.request.Request(url, data=data,
          headers=headers or {}, method=method)
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", errors="ignore")

def _json_http(url, method="GET", headers=None, payload=None, timeout=10):
    data = json.dumps(payload).encode() if payload else None
    h = {"Content-Type": "application/json", **(headers or {})}
    status, body = _http(url, method, h, data, timeout)
    return status, json.loads(body) if body else {}

def tcp_ok(host, port, timeout=3):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close(); return True, f"TCP {host}:{port} reachable"
    except Exception as e:
        return False, f"TCP {host}:{port} unreachable: {e}"

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_cfg(db, tenant_id, key):
    r = db.execute(text(
        "SELECT * FROM integration_configs WHERE tenant_id=:t AND integration_key=:k"),
        {"t": tenant_id, "k": key}).fetchone()
    return dict(r._mapping) if r else None

def all_cfgs(db, tenant_id):
    rows = db.execute(text(
        "SELECT * FROM integration_configs WHERE tenant_id=:t ORDER BY integration_key"),
        {"t": tenant_id}).fetchall()
    return [dict(r._mapping) for r in rows]

def upsert_cfg(db, tenant_id, key, display_name, host=None, port=None,
               api_key=None, username=None, password=None,
               extra=None, enabled=False):
    ex = get_cfg(db, tenant_id, key)
    vals = dict(t=tenant_id, k=key, dn=display_name, host=host, port=port,
                api_key=api_key, username=username, password=password,
                extra=json.dumps(extra or {}), enabled=enabled)
    if ex:
        db.execute(text("""UPDATE integration_configs SET
            host=:host,port=:port,api_key=:api_key,username=:username,
            password_enc=:password,extra_config=:extra,is_enabled=:enabled,
            updated_at=NOW() WHERE tenant_id=:t AND integration_key=:k"""), vals)
    else:
        db.execute(text("""INSERT INTO integration_configs
          (tenant_id,integration_key,display_name,host,port,api_key,
           username,password_enc,extra_config,is_enabled)
          VALUES(:t,:k,:dn,:host,:port,:api_key,:username,:password,:extra,:enabled)"""), vals)
    db.commit()
    return get_cfg(db, tenant_id, key)

def save_test(db, tenant_id, key, ok, msg):
    db.execute(text("""UPDATE integration_configs SET
        last_tested_at=NOW(),last_test_ok=:ok,last_test_msg=:msg
        WHERE tenant_id=:t AND integration_key=:k"""),
        {"t": tenant_id, "k": key, "ok": ok, "msg": str(msg)[:500]})
    db.commit()

# ── Upsert unified finding ────────────────────────────────────────────────────
def _upsert_finding(db, tenant_id, cve_id, severity, cvss, software,
                    version, agent_id, source, description=""):
    sev_map = {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW"}
    sev = sev_map.get((severity or "").lower(), "MEDIUM")
    try:
        db.execute(text("""
            INSERT INTO vulnerability_findings
              (tenant_id,cve_id,severity,cvss_score,software_name,
               software_version,agent_id,source,status,scan_run_id,description)
            VALUES(:t,:cve,:sev,:cvss,:sw,:ver,:agent,:src,'open',0,:desc)
            ON CONFLICT (tenant_id,cve_id,agent_id,software_name) DO UPDATE SET
              severity=EXCLUDED.severity,cvss_score=EXCLUDED.cvss_score,
              source=EXCLUDED.source,description=EXCLUDED.description
        """), dict(t=tenant_id, cve=cve_id, sev=sev, cvss=float(cvss or 0),
                   sw=software or "Unknown", ver=version or "unknown",
                   agent=agent_id or "integration", src=source, desc=description[:500]))
    except Exception as e:
        logger.warning("upsert_finding %s: %s", cve_id, e)

# ══════════════════════════════════════════════════════════════════════════════
#  RAPID7 INSIGHTVM / NEXPOSE
# ══════════════════════════════════════════════════════════════════════════════
def test_rapid7(host, port=3780, username="", password=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        status, data = _json_http(
            f"https://{host}:{port}/api/3/administration/info",
            headers={"Authorization": f"Basic {creds}"})
        if status == 200:
            return True, f"Rapid7 InsightVM {data.get('version','?')} connected"
        return False, f"Rapid7 auth failed (HTTP {status})"
    except Exception as e:
        return False, f"Rapid7 error: {e}"

def pull_rapid7(db, tenant_id, host, port, username, password):
    try:
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}"}
        # Get vulnerabilities
        status, data = _json_http(
            f"https://{host}:{port}/api/3/vulnerabilities?size=500",
            headers=headers)
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}", "imported": 0}
        vulns = data.get("resources", [])
        imported = 0
        for v in vulns:
            cves = v.get("cves", [])
            for cve in cves:
                _upsert_finding(db, tenant_id, cve,
                    v.get("severity", {}).get("name", "medium"),
                    v.get("cvss", {}).get("v3", {}).get("score", 0),
                    v.get("title", "Unknown"), "unknown",
                    f"rapid7:{host}", "rapid7",
                    v.get("description", {}).get("text", "")[:500])
                imported += 1
        db.commit()
        return {"ok": True, "imported": imported, "total_vulns": len(vulns)}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  QUALYS VMDR
# ══════════════════════════════════════════════════════════════════════════════
def test_qualys(host="qualysapi.qualys.com", username="", password=""):
    try:
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        status, body = _http(
            f"https://{host}/api/2.0/fo/activity_log/?action=list&truncation_limit=1",
            headers={"Authorization": f"Basic {creds}",
                     "X-Requested-With": "CyberAssetIQ"})
        if status == 200:
            return True, "Qualys VMDR authenticated"
        return False, f"Qualys auth failed (HTTP {status})"
    except Exception as e:
        return False, f"Qualys error: {e}"

def pull_qualys(db, tenant_id, host, username, password):
    try:
        import base64, xml.etree.ElementTree as ET
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}",
                   "X-Requested-With": "CyberAssetIQ",
                   "Content-Type": "application/x-www-form-urlencoded"}
        data = b"action=list&truncation_limit=200&status=Active"
        status, body = _http(
            f"https://{host}/api/2.0/fo/knowledge_base/vuln/",
            method="POST", headers=headers, data=data)
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}", "imported": 0}
        root = ET.fromstring(body)
        imported = 0
        for vuln in root.iter("VULN"):
            cve_list = vuln.findtext("CVE_LIST/CVE/ID") or ""
            if not cve_list.startswith("CVE-"): continue
            sev = vuln.findtext("SEVERITY_LEVEL") or "3"
            sev_map = {"1":"LOW","2":"LOW","3":"MEDIUM","4":"HIGH","5":"CRITICAL"}
            _upsert_finding(db, tenant_id, cve_list,
                sev_map.get(sev, "MEDIUM"),
                float(vuln.findtext("CVSS/BASE") or 0),
                vuln.findtext("TITLE") or "Unknown", "unknown",
                f"qualys:{host}", "qualys",
                (vuln.findtext("DIAGNOSIS") or "")[:500])
            imported += 1
        db.commit()
        return {"ok": True, "imported": imported}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  TENABLE.IO / NESSUS
# ══════════════════════════════════════════════════════════════════════════════
def test_tenable(access_key="", secret_key="",
                 host="cloud.tenable.com", port=443):
    try:
        status, data = _json_http(
            f"https://{host}/session",
            headers={"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"})
        if status == 200:
            return True, "Tenable.io authenticated"
        return False, f"Tenable auth failed (HTTP {status})"
    except Exception as e:
        # Try Nessus local
        ok, msg = tcp_ok(host, port)
        if ok: return True, f"Nessus reachable at {host}:{port} (credentials not verified)"
        return False, f"Tenable error: {e}"

def pull_tenable(db, tenant_id, access_key, secret_key,
                 host="cloud.tenable.com"):
    try:
        headers = {"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"}
        # Get vulnerabilities
        status, data = _json_http(
            f"https://{host}/workbenches/vulnerabilities?date_range=90",
            headers=headers)
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}", "imported": 0}
        vulns = data.get("vulnerabilities", [])
        imported = 0
        for v in vulns:
            cve_list = v.get("cve", []) or []
            if isinstance(cve_list, str): cve_list = [cve_list]
            sev = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW"}.get(
                v.get("severity",2), "MEDIUM")
            for cve in cve_list:
                if not str(cve).startswith("CVE-"): continue
                _upsert_finding(db, tenant_id, cve, sev,
                    v.get("cvss3_base_score", 0) or v.get("cvss_base_score", 0),
                    v.get("plugin_name", "Unknown"), "unknown",
                    f"tenable:{host}", "tenable",
                    v.get("synopsis", "")[:500])
                imported += 1
        db.commit()
        return {"ok": True, "imported": imported, "total_vulns": len(vulns)}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  CROWDSTRIKE FALCON
# ══════════════════════════════════════════════════════════════════════════════
def test_crowdstrike(client_id="", client_secret="",
                     host="api.crowdstrike.com"):
    try:
        status, data = _json_http(
            f"https://{host}/oauth2/token", method="POST",
            payload={"client_id": client_id, "client_secret": client_secret})
        if status == 201 and data.get("access_token"):
            return True, "CrowdStrike Falcon authenticated"
        return False, f"CrowdStrike auth failed: {data.get('errors','')}"
    except Exception as e:
        return False, f"CrowdStrike error: {e}"

def _cs_token(client_id, client_secret, host):
    status, data = _json_http(
        f"https://{host}/oauth2/token", method="POST",
        payload={"client_id": client_id, "client_secret": client_secret})
    return data.get("access_token")

def pull_crowdstrike(db, tenant_id, client_id, client_secret,
                     host="api.crowdstrike.com"):
    try:
        token = _cs_token(client_id, client_secret, host)
        if not token:
            return {"ok": False, "error": "Auth failed", "imported": 0}
        headers = {"Authorization": f"Bearer {token}"}

        # Pull spotlight vulnerabilities
        status, data = _json_http(
            f"https://{host}/spotlight/queries/vulnerabilities/v1?limit=400&filter=status:'open'",
            headers=headers)
        vuln_ids = data.get("resources", [])

        imported = 0
        if vuln_ids:
            status, details = _json_http(
                f"https://{host}/spotlight/entities/vulnerabilities/v2?ids={'&ids='.join(vuln_ids[:100])}",
                headers=headers)
            for v in details.get("resources", []):
                cve = v.get("cve", {}).get("id", "")
                if not cve.startswith("CVE-"): continue
                sev = v.get("cve", {}).get("severity", "MEDIUM")
                cvss = v.get("cve", {}).get("base_score", 0)
                aid = v.get("aid", "crowdstrike")
                _upsert_finding(db, tenant_id, cve, sev, cvss,
                    v.get("cve", {}).get("description", "Unknown")[:80],
                    "unknown", f"cs:{aid}", "crowdstrike",
                    v.get("cve", {}).get("description", "")[:500])
                imported += 1

        # Pull device inventory into network assets
        status, devices = _json_http(
            f"https://{host}/devices/queries/devices/v1?limit=200",
            headers=headers)
        device_ids = devices.get("resources", [])
        assets_imported = 0
        if device_ids:
            status, ddata = _json_http(
                f"https://{host}/devices/entities/devices/v2?ids={'&ids='.join(device_ids[:100])}",
                headers=headers)
            for d in ddata.get("resources", []):
                try:
                    db.execute(text("""
                        INSERT INTO network_discovered_assets
                          (tenant_id,ip_address,hostname,os_guess,device_type,
                           managed,is_active,first_seen,last_seen,
                           risk_level,risk_score,open_ports,services,ce_issues,
                           raw_metadata_json)
                        VALUES(:t,:ip,:hn,:os,'endpoint',true,true,:fs,:ls,
                               'LOW',2.0,'[]','[]','[]',:meta)
                        ON CONFLICT (tenant_id,ip_address) DO UPDATE SET
                          hostname=EXCLUDED.hostname,os_guess=EXCLUDED.os_guess,
                          managed=true,last_seen=EXCLUDED.last_seen
                    """), dict(
                        t=tenant_id,
                        ip=d.get("local_ip","0.0.0.0"),
                        hn=d.get("hostname",""),
                        os=d.get("os_version",""),
                        fs=d.get("first_seen",""),
                        ls=d.get("last_seen",""),
                        meta=json.dumps({"source":"crowdstrike","aid":d.get("device_id","")})))
                    assets_imported += 1
                except Exception: pass
        db.commit()
        return {"ok": True, "vulns_imported": imported,
                "assets_imported": assets_imported}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  CYBERARK PAM
# ══════════════════════════════════════════════════════════════════════════════
def test_cyberark(host, port=443, username="", password=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        status, data = _json_http(
            f"https://{host}/PasswordVault/API/auth/CyberArk/Logon",
            method="POST",
            payload={"username": username, "password": password})
        if status == 200 and isinstance(data, str) and len(data) > 10:
            return True, "CyberArk PAM authenticated"
        return False, f"CyberArk auth failed (HTTP {status})"
    except Exception as e:
        return False, f"CyberArk error: {e}"

def pull_cyberark(db, tenant_id, host, port, username, password):
    try:
        # Authenticate
        status, token_raw = _json_http(
            f"https://{host}/PasswordVault/API/auth/CyberArk/Logon",
            method="POST",
            payload={"username": username, "password": password})
        if status != 200:
            return {"ok": False, "error": "Auth failed", "imported": 0}
        token = token_raw if isinstance(token_raw, str) else token_raw.get("token","")
        token = token.strip('"')
        headers = {"Authorization": token}

        # Get accounts
        status, data = _json_http(
            f"https://{host}/PasswordVault/API/Accounts?limit=500",
            headers=headers)
        accounts = data.get("value", [])

        imported = 0
        for acc in accounts:
            try:
                db.execute(text("""
                    INSERT INTO security_posture_events
                      (tenant_id,event_type,severity,title,description,
                       asset_identifier,source,metadata_json,created_at)
                    VALUES(:t,'privileged_account','MEDIUM',:title,:desc,:asset,
                           'cyberark',:meta,NOW())
                    ON CONFLICT DO NOTHING
                """), dict(
                    t=tenant_id,
                    title=f"Privileged account: {acc.get('userName','')}",
                    desc=f"Safe: {acc.get('safeName','')} | Platform: {acc.get('platformId','')}",
                    asset=acc.get("address",""),
                    meta=json.dumps({"source":"cyberark",
                                     "safe":acc.get("safeName",""),
                                     "platform":acc.get("platformId","")})))
                imported += 1
            except Exception: pass
        db.commit()
        return {"ok": True, "accounts_imported": imported}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  BEYONDTRUST
# ══════════════════════════════════════════════════════════════════════════════
def test_beyondtrust(host, port=443, api_key=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        status, data = _json_http(
            f"https://{host}/BeyondTrust/api/public/v3/CurrentUser",
            headers={"Authorization": f"PS-Auth key={api_key};runas=admin;"})
        if status == 200:
            return True, f"BeyondTrust connected: {data.get('UserName','')}"
        return False, f"BeyondTrust auth failed (HTTP {status})"
    except Exception as e:
        return False, f"BeyondTrust error: {e}"

def pull_beyondtrust(db, tenant_id, host, port, api_key):
    try:
        headers = {"Authorization": f"PS-Auth key={api_key};runas=admin;"}
        status, data = _json_http(
            f"https://{host}/BeyondTrust/api/public/v3/Accounts",
            headers=headers)
        if status != 200:
            return {"ok": False, "error": f"HTTP {status}", "imported": 0}
        accounts = data if isinstance(data, list) else data.get("value", [])
        imported = 0
        for acc in accounts:
            try:
                db.execute(text("""
                    INSERT INTO security_posture_events
                      (tenant_id,event_type,severity,title,description,
                       asset_identifier,source,metadata_json,created_at)
                    VALUES(:t,'privileged_account','MEDIUM',:title,:desc,:asset,
                           'beyondtrust',:meta,NOW())
                    ON CONFLICT DO NOTHING
                """), dict(
                    t=tenant_id,
                    title=f"BeyondTrust account: {acc.get('AccountName','')}",
                    desc=f"System: {acc.get('SystemName','')}",
                    asset=acc.get("SystemName",""),
                    meta=json.dumps({"source":"beyondtrust","id":acc.get("AccountID","")})))
                imported += 1
            except Exception: pass
        db.commit()
        return {"ok": True, "accounts_imported": imported}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  DELINEA (formerly Thycotic Secret Server)
# ══════════════════════════════════════════════════════════════════════════════
def test_delinea(host, port=443, username="", password=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        data = urllib.parse.urlencode({
            "grant_type":"password","username":username,"password":password
        }).encode()
        status, body = _http(
            f"https://{host}/SecretServer/oauth2/token",
            method="POST",
            headers={"Content-Type":"application/x-www-form-urlencoded"},
            data=data)
        resp = json.loads(body)
        if status == 200 and resp.get("access_token"):
            return True, "Delinea Secret Server authenticated"
        return False, f"Delinea auth failed (HTTP {status})"
    except Exception as e:
        return False, f"Delinea error: {e}"

def pull_delinea(db, tenant_id, host, port, username, password):
    try:
        data = urllib.parse.urlencode({
            "grant_type":"password","username":username,"password":password
        }).encode()
        status, body = _http(
            f"https://{host}/SecretServer/oauth2/token",
            method="POST",
            headers={"Content-Type":"application/x-www-form-urlencoded"},
            data=data)
        token = json.loads(body).get("access_token","")
        if not token:
            return {"ok": False, "error": "Auth failed", "imported": 0}
        headers = {"Authorization": f"Bearer {token}"}
        status, data = _json_http(
            f"https://{host}/SecretServer/api/v1/secrets?take=500",
            headers=headers)
        secrets = data.get("records", [])
        imported = 0
        for s in secrets:
            try:
                db.execute(text("""
                    INSERT INTO security_posture_events
                      (tenant_id,event_type,severity,title,description,
                       asset_identifier,source,metadata_json,created_at)
                    VALUES(:t,'privileged_account','MEDIUM',:title,:desc,:asset,
                           'delinea',:meta,NOW())
                    ON CONFLICT DO NOTHING
                """), dict(
                    t=tenant_id,
                    title=f"Delinea secret: {s.get('name','')}",
                    desc=f"Folder: {s.get('folderPath','')}",
                    asset=s.get("name",""),
                    meta=json.dumps({"source":"delinea","id":s.get("id","")})))
                imported += 1
            except Exception: pass
        db.commit()
        return {"ok": True, "secrets_imported": imported}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  GREENBONE / OPENVAS
# ══════════════════════════════════════════════════════════════════════════════
def test_greenbone(host, port=9390, username="admin", password=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        s = socket.create_connection((host, int(port)), timeout=5)
        banner = s.recv(256).decode("utf-8", errors="ignore")
        s.close()
        return True, f"Greenbone/OpenVAS responding at {host}:{port}"
    except Exception as e:
        return False, str(e)

def pull_greenbone(db, tenant_id, host, port, username, password):
    try:
        s = socket.create_connection((host, int(port)), timeout=10)
        auth = (f'<authenticate><credentials>'
                f'<username>{username}</username>'
                f'<password>{password}</password>'
                f'</credentials></authenticate>')
        s.sendall(auth.encode())
        time.sleep(0.5)
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        if 'status="200"' not in resp:
            s.close()
            return {"ok": False, "error": "Authentication failed", "imported": 0}
        s.sendall(b'<get_reports filter="rows=100 sort-reverse=date"/>')
        time.sleep(1)
        data = b""
        for _ in range(20):
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
            if b"</get_reports_response>" in data: break
        s.close()
        import re
        xml = data.decode("utf-8", errors="ignore")
        cves = re.findall(r'<cve>(CVE-[^<]+)</cve>', xml)
        severities = re.findall(r'<severity>([^<]+)</severity>', xml)
        imported = 0
        for i, cve in enumerate(cves[:200]):
            sev_val = float(severities[i]) if i < len(severities) else 0.0
            sev = ("CRITICAL" if sev_val>=9 else "HIGH" if sev_val>=7
                   else "MEDIUM" if sev_val>=4 else "LOW")
            _upsert_finding(db, tenant_id, cve.strip(), sev, sev_val,
                "Unknown (Greenbone)", "unknown",
                f"greenbone:{host}", "greenbone")
            imported += 1
        db.commit()
        return {"ok": True, "imported": imported}
    except Exception as e:
        return {"ok": False, "error": str(e), "imported": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  SPLUNK HEC
# ══════════════════════════════════════════════════════════════════════════════
def test_splunk(host, port=8088, hec_token=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        status, body = _http(
            f"https://{host}:{port}/services/collector/health",
            headers={"Authorization": f"Splunk {hec_token}"})
        return (status == 200), f"Splunk HEC {'healthy' if status==200 else 'error '+str(status)}"
    except Exception as e:
        return False, f"Splunk HEC error: {e}"

def push_splunk(host, port, hec_token, events):
    try:
        payload = "\n".join(json.dumps({
            "time": time.time(), "source": "cyberassetiq",
            "sourcetype": "_json", "event": e}) for e in events).encode()
        status, body = _http(
            f"https://{host}:{port}/services/collector/event",
            method="POST", data=payload,
            headers={"Authorization": f"Splunk {hec_token}",
                     "Content-Type": "application/json"})
        return {"ok": status in (200,204), "sent": len(events), "status": status}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  WAPPALYZER
# ══════════════════════════════════════════════════════════════════════════════
def test_wappalyzer(api_key):
    try:
        status, body = _http(
            "https://api.wappalyzer.com/v2/lookup/?urls=https://example.com",
            headers={"x-api-key": api_key})
        return (status == 200), f"Wappalyzer {'valid' if status==200 else 'invalid key'}"
    except Exception as e:
        return False, f"Wappalyzer error: {e}"

def pull_wappalyzer(db, tenant_id, api_key):
    try:
        rows = db.execute(text("""
            SELECT DISTINCT ip_address FROM network_discovered_assets
            WHERE tenant_id=:t AND is_active=true LIMIT 20
        """), {"t": tenant_id}).fetchall()
        results = []
        for r in rows:
            try:
                ip = r.ip_address
                enc = urllib.parse.quote(f"http://{ip}", safe="")
                status, body = _http(
                    f"https://api.wappalyzer.com/v2/lookup/?urls={enc}",
                    headers={"x-api-key": api_key})
                data = json.loads(body) if body else []
                if data:
                    techs = []
                    for item in data:
                        techs.extend(item.get("technologies",[]))
                    tech_names = [t.get("name","") for t in techs]
                    if tech_names:
                        db.execute(text("""
                            UPDATE network_discovered_assets
                            SET raw_metadata_json = raw_metadata_json ||
                                :wapp::jsonb
                            WHERE tenant_id=:t AND ip_address=:ip
                        """), {"t": tenant_id, "ip": ip,
                               "wapp": json.dumps({"wappalyzer_techs": tech_names})})
                results.append({"ip": ip, "techs": tech_names})
            except Exception: pass
        db.commit()
        return {"ok": True, "assets_enriched": len(results)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════
#  METASPLOIT RPC
# ══════════════════════════════════════════════════════════════════════════════
def test_metasploit(host, port=55553, username="msf", password=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    return True, f"Metasploit RPC port reachable at {host}:{port}"

# ══════════════════════════════════════════════════════════════════════════════
#  BURP SUITE
# ══════════════════════════════════════════════════════════════════════════════
def test_burpsuite(host, port=1337, api_key=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    try:
        status, _ = _http(f"http://{host}:{port}/api/v1/",
            headers={"Authorization": f"token {api_key}"} if api_key else {})
        return True, f"Burp Suite API reachable (HTTP {status})"
    except Exception as e:
        return False, f"Burp Suite error: {e}"

# ══════════════════════════════════════════════════════════════════════════════
#  BLOODHOUND (Neo4j)
# ══════════════════════════════════════════════════════════════════════════════
def test_bloodhound(host, port=7687, username="neo4j", password=""):
    ok, msg = tcp_ok(host, port)
    if not ok: return False, msg
    return True, f"BloodHound Neo4j port {port} reachable at {host}"

# ══════════════════════════════════════════════════════════════════════════════
#  QRADAR (CEF syslog)
# ══════════════════════════════════════════════════════════════════════════════
def test_qradar(host, port=514):
    ok, msg = tcp_ok(host, port)
    return ok, msg

def push_qradar(host, port, events):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent = 0
        for e in events:
            cef = (f"CEF:0|CyberAssetIQ|Platform|1.0|"
                   f"{e.get('type','alert')}|{e.get('title','Event')}|"
                   f"{e.get('severity',5)}|msg={e.get('summary','')}")
            sock.sendto(f"<14>{cef}".encode(), (host, int(port)))
            sent += 1
        sock.close()
        return {"ok": True, "sent": sent}
    except Exception as e:
        return {"ok": False, "error": str(e), "sent": 0}

# ══════════════════════════════════════════════════════════════════════════════
#  SIGMA EXPORT
# ══════════════════════════════════════════════════════════════════════════════
def export_sigma(db, tenant_id):
    try:
        rows = db.execute(text("""
            SELECT title,summary,severity,metadata_json FROM ai_alerts
            WHERE tenant_id=:t AND status='open'
            ORDER BY created_at DESC LIMIT 50
        """), {"t": tenant_id}).fetchall()
    except Exception:
        rows = []
    rules = []
    for r in rows:
        meta = r.metadata_json or {}
        rules.append({
            "title": r.title, "status": "experimental",
            "description": r.summary or "",
            "level": (r.severity or "medium").lower(),
            "tags": [f"attack.{meta.get('mitre_tactic','unknown')}"]
                    if meta.get("mitre_tactic") else [],
            "detection": {"keywords": [r.title], "condition": "keywords"},
            "logsource": {"product": "windows", "service": "security"},
            "falsepositives": ["Unknown"], "author": "CyberAssetIQ",
        })
    return rules

# ══════════════════════════════════════════════════════════════════════════════
#  MASTER TEST DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════
def test_integration(key, cfg):
    h  = cfg.get("host","") if cfg else ""
    p  = cfg.get("port") if cfg else None
    ak = cfg.get("api_key","") if cfg else ""
    un = cfg.get("username","") if cfg else ""
    pw = cfg.get("password_enc","") if cfg else ""
    ex = cfg.get("extra_config") if cfg else {}
    if isinstance(ex, str):
        try: ex = json.loads(ex)
        except: ex = {}

    dispatch = {
        "nmap":        lambda: (True,  "Nmap is built-in — always available"),
        "nvd":         lambda: (True,  "NVD API is built-in — always available"),
        "winget":      lambda: (True,  "winget is built-in — always available"),
        "ipify":       lambda: (True,  "ipify is built-in — always available"),
        "sigma":       lambda: (True,  "Sigma export is built-in — no connection needed"),
        "groq":        lambda: (bool(ak), "Groq API key configured" if ak else "No API key"),
        "gemini":      lambda: (bool(ak), "Gemini API key configured" if ak else "No API key"),
        "anthropic":   lambda: (bool(ak), "Anthropic API key configured" if ak else "No API key"),
        "openai":      lambda: (bool(ak), "OpenAI API key configured" if ak else "No API key"),
        "gmail":       lambda: (bool(h), f"Gmail SMTP: {h}" if h else "Not configured"),
        "slack":       lambda: (bool(ak), "Slack webhook configured" if ak else "Not configured"),
        "rapid7":      lambda: test_rapid7(h, p or 3780, un, pw),
        "qualys":      lambda: test_qualys(h or "qualysapi.qualys.com", un, pw),
        "tenable":     lambda: test_tenable(un, pw, h or "cloud.tenable.com", p or 443),
        "crowdstrike": lambda: test_crowdstrike(un, pw, h or "api.crowdstrike.com"),
        "cyberark":    lambda: test_cyberark(h, p or 443, un, pw),
        "beyondtrust": lambda: test_beyondtrust(h, p or 443, ak),
        "delinea":     lambda: test_delinea(h, p or 443, un, pw),
        "greenbone":   lambda: test_greenbone(h, p or 9390, un, pw),
        "splunk":      lambda: test_splunk(h, p or 8088, ak),
        "wappalyzer":  lambda: test_wappalyzer(ak),
        "metasploit":  lambda: test_metasploit(h, p or 55553, un, pw),
        "burpsuite":   lambda: test_burpsuite(h, p or 1337, ak),
        "bloodhound":  lambda: test_bloodhound(h, p or 7687, un, pw),
        "qradar":      lambda: test_qradar(h, p or 514),
    }
    fn = dispatch.get(key)
    if fn:
        try: return fn()
        except Exception as e: return False, str(e)
    return False, f"Unknown integration: {key}"
