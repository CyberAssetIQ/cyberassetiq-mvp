"""
api/routes/integrations.py  (v2 — replaces v1)
Full REST API for the Integrations tab.
"""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from services.integration_service_v2 import (
    get_cfg, upsert_cfg, all_cfgs, save_test, test_integration,
    pull_rapid7, pull_qualys, pull_tenable, pull_crowdstrike,
    pull_cyberark, pull_beyondtrust, pull_delinea,
    pull_greenbone, pull_wappalyzer,
    push_splunk, push_qradar, export_sigma,
)
from services.unified_findings_service import (
    get_unified_findings, get_source_coverage,
    get_competitive_gap_report,
)

router = APIRouter()

# ── Full integration catalogue ────────────────────────────────────────────────
CATALOGUE = [
    # Built-in
    {"key":"nmap",        "name":"Nmap",               "category":"network",
     "desc":"Network scanner — built-in. Discovers hosts, ports and services.",
     "logo":"🗺️",  "color":"#4fd1ff", "fields":[], "builtin":True,
     "data_flow":"Nmap → CyberAssetIQ (network assets)",
     "docs":"https://nmap.org"},
    {"key":"nvd",         "name":"NVD / NIST",          "category":"vuln_scanner",
     "desc":"NIST National Vulnerability Database — built-in CVE correlation engine.",
     "logo":"🛡️",  "color":"#4fd1ff", "fields":[], "builtin":True,
     "data_flow":"NVD API → CyberAssetIQ (CVE data)",
     "docs":"https://nvd.nist.gov"},
    {"key":"winget",      "name":"Windows Package Manager","category":"patching",
     "desc":"winget — built-in automated patch management for Windows endpoints.",
     "logo":"🔧",  "color":"#4fd1ff", "fields":[], "builtin":True,
     "data_flow":"winget → CyberAssetIQ (patch status)",
     "docs":"https://learn.microsoft.com/en-us/windows/package-manager/winget"},
    {"key":"ipify",       "name":"ipify",               "category":"network",
     "desc":"Public IP detection — built-in for external exposure scanning.",
     "logo":"🌐",  "color":"#4fd1ff", "fields":[], "builtin":True,
     "data_flow":"ipify → CyberAssetIQ (external IP)",
     "docs":"https://www.ipify.org"},
    {"key":"sigma",       "name":"Sigma Rules",          "category":"export",
     "desc":"Export CyberAssetIQ detections as Sigma YAML rules for any SIEM.",
     "logo":"Σ",   "color":"#3b82f6", "fields":[], "builtin":True,
     "data_flow":"CyberAssetIQ → Sigma YAML",
     "docs":"https://sigmahq.io"},
    # AI Providers
    {"key":"groq",        "name":"Groq",                 "category":"ai",
     "desc":"Primary AI provider (llama-3.3-70b). Powers AI Security Intelligence.",
     "logo":"⚡",  "color":"#a855f7", "fields":["api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ ↔ Groq LLM",
     "docs":"https://console.groq.com", "api_key_label":"Groq API Key"},
    {"key":"gemini",      "name":"Google Gemini",        "category":"ai",
     "desc":"AI fallback provider (gemini-2.0-flash).",
     "logo":"✨",  "color":"#4285f4", "fields":["api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ ↔ Gemini",
     "docs":"https://ai.google.dev", "api_key_label":"Gemini API Key"},
    {"key":"anthropic",   "name":"Anthropic Claude",     "category":"ai",
     "desc":"AI fallback provider (Claude Sonnet).",
     "logo":"🧠",  "color":"#d97706", "fields":["api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ ↔ Claude",
     "docs":"https://console.anthropic.com", "api_key_label":"Anthropic API Key"},
    {"key":"openai",      "name":"OpenAI",               "category":"ai",
     "desc":"AI fallback provider (GPT-4).",
     "logo":"🤖",  "color":"#10b981", "fields":["api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ ↔ OpenAI",
     "docs":"https://platform.openai.com", "api_key_label":"OpenAI API Key"},
    # Alerting
    {"key":"gmail",       "name":"Gmail SMTP",           "category":"alerting",
     "desc":"Email alerting via Gmail SMTP. Sends CE compliance and risk alerts.",
     "logo":"📧",  "color":"#ef4444", "fields":["host","username","api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ → Gmail (alerts)",
     "docs":"https://support.google.com/mail/?hl=en",
     "api_key_label":"App Password"},
    {"key":"slack",       "name":"Slack",                "category":"alerting",
     "desc":"Slack webhook notifications for critical security events.",
     "logo":"💬",  "color":"#4a154b", "fields":["api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ → Slack (alerts)",
     "docs":"https://api.slack.com/messaging/webhooks",
     "api_key_label":"Webhook URL"},
    # Vuln Scanners
    {"key":"rapid7",      "name":"Rapid7 InsightVM",     "category":"vuln_scanner",
     "desc":"Pull vulnerability scan results from Rapid7 InsightVM/Nexpose into unified findings.",
     "logo":"🔴",  "color":"#ef4444", "fields":["host","port","username","password"],
     "builtin":False, "data_flow":"Rapid7 → CyberAssetIQ (CVEs + assets)",
     "docs":"https://docs.rapid7.com/insightvm/api-v3",
     "default_port":3780},
    {"key":"qualys",      "name":"Qualys VMDR",          "category":"vuln_scanner",
     "desc":"Pull Qualys VMDR vulnerability detections and compliance data.",
     "logo":"🟦",  "color":"#dc2626", "fields":["host","username","password"],
     "builtin":False, "data_flow":"Qualys → CyberAssetIQ (CVEs + compliance)",
     "docs":"https://www.qualys.com/docs/qualys-api-quick-reference.pdf"},
    {"key":"tenable",     "name":"Tenable.io / Nessus",  "category":"vuln_scanner",
     "desc":"Pull Tenable.io or Nessus vulnerability scan data into unified findings.",
     "logo":"🟩",  "color":"#16a34a", "fields":["host","username","password"],
     "builtin":False, "data_flow":"Tenable → CyberAssetIQ (CVEs + assets)",
     "docs":"https://developer.tenable.com",
     "username_label":"Access Key", "password_label":"Secret Key"},
    {"key":"greenbone",   "name":"Greenbone / OpenVAS",  "category":"vuln_scanner",
     "desc":"Open-source vulnerability scanner. Pull scan results into CVE findings.",
     "logo":"🟢",  "color":"#10b981", "fields":["host","port","username","password"],
     "builtin":False, "data_flow":"Greenbone → CyberAssetIQ (CVE findings)",
     "docs":"https://www.greenbone.net", "default_port":9390},
    # Endpoint / Detection
    {"key":"crowdstrike", "name":"CrowdStrike Falcon",   "category":"endpoint",
     "desc":"Pull CrowdStrike Spotlight vulnerabilities and endpoint inventory.",
     "logo":"🦅",  "color":"#ef4444", "fields":["host","username","password"],
     "builtin":False, "data_flow":"CrowdStrike → CyberAssetIQ (endpoints + CVEs)",
     "docs":"https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis",
     "username_label":"Client ID", "password_label":"Client Secret",
     "host_placeholder":"api.crowdstrike.com"},
    # Identity / PAM
    {"key":"cyberark",    "name":"CyberArk PAM",         "category":"identity",
     "desc":"Pull privileged accounts from CyberArk and correlate with asset risk.",
     "logo":"🏛️",  "color":"#1d4ed8", "fields":["host","port","username","password"],
     "builtin":False, "data_flow":"CyberArk → CyberAssetIQ (privileged accounts)",
     "docs":"https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/cyberark-rest-api-overview.htm",
     "default_port":443},
    {"key":"beyondtrust", "name":"BeyondTrust",          "category":"identity",
     "desc":"Pull BeyondTrust privileged session data and account risks.",
     "logo":"🔐",  "color":"#7c3aed", "fields":["host","port","api_key"],
     "builtin":False, "data_flow":"BeyondTrust → CyberAssetIQ (privileged sessions)",
     "docs":"https://www.beyondtrust.com/docs/privileged-remote-access/how-to/integrations/api",
     "default_port":443, "api_key_label":"API Key"},
    {"key":"delinea",     "name":"Delinea / Thycotic",   "category":"identity",
     "desc":"Pull Delinea Secret Server privileged account inventory.",
     "logo":"🔑",  "color":"#0284c7", "fields":["host","port","username","password"],
     "builtin":False, "data_flow":"Delinea → CyberAssetIQ (secrets + accounts)",
     "docs":"https://docs.delinea.com/online-help/secret-server/restapi",
     "default_port":443},
    # Pen Test
    {"key":"metasploit",  "name":"Metasploit",           "category":"pentest",
     "desc":"Pull exploit findings from Metasploit RPC into asset risk scoring.",
     "logo":"💀",  "color":"#ef4444", "fields":["host","port","username","password"],
     "builtin":False, "data_flow":"Metasploit → CyberAssetIQ (exploit findings)",
     "docs":"https://docs.metasploit.com", "default_port":55553},
    {"key":"burpsuite",   "name":"Burp Suite",           "category":"pentest",
     "desc":"Pull web application scan results from Burp Suite Enterprise.",
     "logo":"🕷️",  "color":"#f97316", "fields":["host","port","api_key"],
     "builtin":False, "data_flow":"Burp Suite → CyberAssetIQ (web vulns)",
     "docs":"https://portswigger.net/burp/documentation/enterprise/api-documentation",
     "default_port":1337, "api_key_label":"API Key"},
    {"key":"bloodhound",  "name":"BloodHound",           "category":"pentest",
     "desc":"Query BloodHound Neo4j for AD attack paths and enrich the attack graph.",
     "logo":"🐕",  "color":"#ef4444", "fields":["host","port","username","password"],
     "builtin":False, "data_flow":"BloodHound → CyberAssetIQ (AD attack paths)",
     "docs":"https://bloodhound.readthedocs.io", "default_port":7687},
    # SIEM
    {"key":"splunk",      "name":"Splunk",               "category":"siem",
     "desc":"Forward CyberAssetIQ alerts and events to Splunk via HTTP Event Collector.",
     "logo":"📊",  "color":"#22c55e", "fields":["host","port","api_key"],
     "builtin":False, "data_flow":"CyberAssetIQ → Splunk (alerts + events)",
     "docs":"https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
     "default_port":8088, "api_key_label":"HEC Token"},
    {"key":"qradar",      "name":"IBM QRadar",           "category":"siem",
     "desc":"Forward CyberAssetIQ events to QRadar via CEF syslog.",
     "logo":"🦅",  "color":"#6366f1", "fields":["host","port"],
     "builtin":False, "data_flow":"CyberAssetIQ → QRadar (CEF events)",
     "docs":"https://www.ibm.com/docs/en/qsip", "default_port":514},
    # Recon
    {"key":"wappalyzer",  "name":"Wappalyzer",           "category":"recon",
     "desc":"Enrich web assets with technology stack fingerprinting.",
     "logo":"🔍",  "color":"#3b82f6", "fields":["api_key"],
     "builtin":False, "data_flow":"Wappalyzer → CyberAssetIQ (tech stacks)",
     "docs":"https://www.wappalyzer.com/api", "api_key_label":"API Key"},
]

CATALOGUE_MAP = {c["key"]: c for c in CATALOGUE}


@router.get("/catalogue")
def get_catalogue():
    return CATALOGUE


@router.get("/configs")
def get_all_configs(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    configs = {c["integration_key"]: c for c in all_cfgs(db, auth.tenant_id)}
    # Also read env vars for built-in tools
    import os
    env_status = {
        "groq":      bool(os.environ.get("GROQ_API_KEY")),
        "gemini":    bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")),
        "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai":    bool(os.environ.get("OPENAI_API_KEY")),
        "gmail":     bool(os.environ.get("CYBERASSETIQ_SMTP_HOST")),
        "slack":     bool(os.environ.get("CYBERASSETIQ_WEBHOOK_URL")),
    }
    result = []
    for item in CATALOGUE:
        key = item["key"]
        cfg = configs.get(key, {})
        is_enabled = cfg.get("is_enabled", False) or item.get("builtin", False)
        # Override with env var status for AI/alerting tools
        if key in env_status:
            is_enabled = env_status[key] or is_enabled
        result.append({
            **item,
            "is_enabled":     is_enabled,
            "host":           cfg.get("host"),
            "port":           cfg.get("port"),
            "username":       cfg.get("username"),
            "has_password":   bool(cfg.get("password_enc")),
            "has_api_key":    bool(cfg.get("api_key")) or env_status.get(key, False),
            "last_tested_at": str(cfg["last_tested_at"]) if cfg.get("last_tested_at") else None,
            "last_test_ok":   cfg.get("last_test_ok"),
            "last_test_msg":  cfg.get("last_test_msg"),
        })
    return result


class SaveConfigPayload(BaseModel):
    integration_key: str
    host:     str | None = None
    port:     int | None = None
    api_key:  str | None = None
    username: str | None = None
    password: str | None = None
    enabled:  bool = False


@router.post("/configs")
def save_config(
    payload: SaveConfigPayload,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    item = CATALOGUE_MAP.get(payload.integration_key)
    if not item:
        raise HTTPException(400, "Unknown integration key")
    upsert_cfg(db, auth.tenant_id, payload.integration_key, item["name"],
               host=payload.host, port=payload.port, api_key=payload.api_key,
               username=payload.username, password=payload.password,
               enabled=payload.enabled)
    return {"status": "saved", "key": payload.integration_key}


@router.post("/test/{key}")
def test_conn(
    key: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = get_cfg(db, auth.tenant_id, key)
    ok, msg = test_integration(key, cfg or {})
    if cfg:
        save_test(db, auth.tenant_id, key, ok, msg)
    return {"ok": ok, "message": msg, "key": key}


@router.post("/pull/{key}")
def pull_data(
    key: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = get_cfg(db, auth.tenant_id, key)
    if not cfg or not cfg.get("is_enabled"):
        raise HTTPException(400, f"{key} not enabled — configure and enable first")

    h  = cfg.get("host","")
    p  = cfg.get("port") or 0
    un = cfg.get("username","")
    pw = cfg.get("password_enc","")
    ak = cfg.get("api_key","")

    if key == "rapid7":
        return pull_rapid7(db, auth.tenant_id, h, p or 3780, un, pw)
    elif key == "qualys":
        return pull_qualys(db, auth.tenant_id, h or "qualysapi.qualys.com", un, pw)
    elif key == "tenable":
        return pull_tenable(db, auth.tenant_id, un, pw, h or "cloud.tenable.com")
    elif key == "crowdstrike":
        return pull_crowdstrike(db, auth.tenant_id, un, pw, h or "api.crowdstrike.com")
    elif key == "cyberark":
        return pull_cyberark(db, auth.tenant_id, h, p or 443, un, pw)
    elif key == "beyondtrust":
        return pull_beyondtrust(db, auth.tenant_id, h, p or 443, ak)
    elif key == "delinea":
        return pull_delinea(db, auth.tenant_id, h, p or 443, un, pw)
    elif key == "greenbone":
        return pull_greenbone(db, auth.tenant_id, h, p or 9390, un, pw)
    elif key == "wappalyzer":
        return pull_wappalyzer(db, auth.tenant_id, ak)
    raise HTTPException(400, f"Pull not supported for {key}")


@router.post("/push/{key}")
def push_data(
    key: str,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cfg = get_cfg(db, auth.tenant_id, key)
    if not cfg or not cfg.get("is_enabled"):
        raise HTTPException(400, f"{key} not enabled")

    h  = cfg.get("host","")
    p  = cfg.get("port") or 0
    ak = cfg.get("api_key","")

    try:
        alerts = db.execute(text("""
            SELECT title,summary,severity FROM ai_alerts
            WHERE tenant_id=:t ORDER BY created_at DESC LIMIT 100
        """), {"t": auth.tenant_id}).fetchall()
        events = [{"title":a.title,"summary":a.summary,
                   "severity":a.severity,"type":"alert"} for a in alerts]
    except Exception:
        events = []

    if key == "splunk":
        return push_splunk(h, p or 8088, ak, events)
    elif key == "qradar":
        return push_qradar(h, p or 514, events)
    raise HTTPException(400, f"Push not supported for {key}")


# ── Unified findings ──────────────────────────────────────────────────────────

@router.get("/unified-findings")
def unified_findings(
    limit: int = 200,
    severity: str | None = None,
    status: str = "open",
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """Deduplicated, ML-re-ranked findings across ALL integrated sources."""
    return get_unified_findings(db, auth.tenant_id, limit, severity, status)


@router.get("/source-coverage")
def source_coverage(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    return get_source_coverage(db, auth.tenant_id)


@router.get("/competitive-gap")
def competitive_gap(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    """AI-generated report of what CyberAssetIQ found that competitors missed."""
    return get_competitive_gap_report(db, auth.tenant_id)


# ── Sigma export ──────────────────────────────────────────────────────────────

@router.get("/sigma/export")
def sigma_export(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    rules = export_sigma(db, auth.tenant_id)
    try:
        import yaml
        yaml_str = yaml.dump_all(rules, default_flow_style=False, allow_unicode=True)
    except Exception:
        yaml_str = "\n---\n".join(str(r) for r in rules)
    return {"rules": rules, "yaml": yaml_str, "count": len(rules)}
