from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import desc

logger = logging.getLogger("cyberassetiq.identity")

# ---------------------------------------------------------------------------
# Risk finding definitions
# ---------------------------------------------------------------------------

def _parse_password_policy(raw: str) -> dict:
    """Parse net accounts output into structured dict."""
    result = {}
    patterns = {
        "min_length":      r"Minimum password length:\s+(\d+)",
        "max_age_days":    r"Maximum password age \(days\):\s+(\d+)",
        "min_age_days":    r"Minimum password age \(days\):\s+(\d+)",
        "history_length":  r"Length of password history maintained:\s+(\d+|None)",
        "lockout_threshold": r"Lockout threshold:\s+(\d+|Never)",
        "lockout_duration": r"Lockout duration \(minutes\):\s+(\d+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, raw, re.IGNORECASE)
        if m:
            val = m.group(1)
            result[key] = int(val) if val.isdigit() else val
    return result


def analyse_identity_risk(db: Session, tenant_id: str) -> dict:
    """
    Analyse identity and security posture risks from existing agent telemetry.
    Returns structured risk report with findings per agent.
    """
    from models.telemetry import SecurityPostureEvent
    from models.agent import Agent

    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
    agent_map = {a.agent_id: a for a in agents}

    # Get latest posture event per agent
    all_agent_ids = (
        db.query(SecurityPostureEvent.agent_id)
        .filter(SecurityPostureEvent.tenant_id == tenant_id)
        .distinct()
        .all()
    )

    agent_reports = []
    total_findings = 0
    critical_count = 0

    for (agent_id,) in all_agent_ids:
        evt = (
            db.query(SecurityPostureEvent)
            .filter(
                SecurityPostureEvent.tenant_id == tenant_id,
                SecurityPostureEvent.agent_id == agent_id,
            )
            .order_by(desc(SecurityPostureEvent.id))
            .first()
        )
        if not evt:
            continue

        payload = evt.payload_json or {}
        posture = payload.get("security_posture", {})
        hostname = payload.get("asset", {}).get("hostname") or agent_id

        # Try to get hostname from agent record
        agent_rec = agent_map.get(agent_id)
        if agent_rec and getattr(agent_rec, "hostname", None):
            hostname = agent_rec.hostname

        findings = []

        # ── 1. Local admin accounts ──────────────────────────────────────
        identity = posture.get("identity", {})
        local_admins = identity.get("local_admins", [])

        if len(local_admins) == 0:
            pass  # Can't assess
        elif len(local_admins) > 3:
            findings.append({
                "category": "Access Control",
                "severity": "HIGH",
                "title": f"Excessive Local Admin Accounts ({len(local_admins)})",
                "detail": f"Found {len(local_admins)} local admin accounts: {', '.join(local_admins[:5])}",
                "remediation": "Remove unnecessary local admin accounts. Standard users should not have admin rights. Follow least privilege principle.",
                "evidence": {"admin_accounts": local_admins},
            })
        elif len(local_admins) > 1:
            # Check for suspicious names
            suspicious = [a for a in local_admins if any(
                kw in a.lower() for kw in ["test", "temp", "old", "backup", "admin2", "user"]
            )]
            if suspicious:
                findings.append({
                    "category": "Access Control",
                    "severity": "MEDIUM",
                    "title": f"Suspicious Admin Account Names Detected",
                    "detail": f"Potentially unnecessary admin accounts: {', '.join(suspicious)}",
                    "remediation": "Review and remove admin accounts with generic or test names.",
                    "evidence": {"suspicious_accounts": suspicious},
                })

        # Check if default Administrator account is enabled
        admin_accounts = [a for a in local_admins if a.lower().endswith("\\administrator")]
        if admin_accounts:
            findings.append({
                "category": "Access Control",
                "severity": "MEDIUM",
                "title": "Built-in Administrator Account Active",
                "detail": f"The built-in Administrator account ({admin_accounts[0]}) is active and in use.",
                "remediation": "Disable the built-in Administrator account. Use named accounts with admin rights for auditability.",
                "evidence": {"account": admin_accounts[0]},
            })

        # ── 2. Password policy ────────────────────────────────────────────
        pw_raw = posture.get("password_policy_raw", "")
        if pw_raw:
            pw = _parse_password_policy(pw_raw)

            min_len = pw.get("min_length", 0)
            if isinstance(min_len, int) and min_len < 8:
                findings.append({
                    "category": "Password Policy",
                    "severity": "CRITICAL" if min_len == 0 else "HIGH",
                    "title": f"Weak Minimum Password Length ({min_len} characters)",
                    "detail": f"Minimum password length is {min_len}. NCSC recommends minimum 10 characters; CE v3.2 requires minimum 8.",
                    "remediation": "Set minimum password length to at least 10 characters via Group Policy or Local Security Policy.",
                    "evidence": {"min_length": min_len},
                })

            max_age = pw.get("max_age_days", 42)
            if isinstance(max_age, int) and max_age > 365:
                findings.append({
                    "category": "Password Policy",
                    "severity": "MEDIUM",
                    "title": f"Password Never Expires ({max_age} days max age)",
                    "detail": f"Passwords are set to expire after {max_age} days or never. NCSC recommends not forcing expiry but enabling MFA instead.",
                    "remediation": "If MFA is not enforced, set password expiry to 365 days maximum. If MFA is enforced, no expiry is acceptable.",
                    "evidence": {"max_age_days": max_age},
                })

            lockout = pw.get("lockout_threshold", "Never")
            if lockout == "Never" or lockout == 0:
                findings.append({
                    "category": "Password Policy",
                    "severity": "HIGH",
                    "title": "No Account Lockout Policy",
                    "detail": "Account lockout is disabled. Accounts can be brute-forced without any lockout.",
                    "remediation": "Enable account lockout after 5-10 failed attempts via Local Security Policy.",
                    "evidence": {"lockout_threshold": lockout},
                })

            history = pw.get("history_length", "None")
            if history == "None" or history == 0:
                findings.append({
                    "category": "Password Policy",
                    "severity": "MEDIUM",
                    "title": "No Password History Enforced",
                    "detail": "Users can reuse previous passwords immediately.",
                    "remediation": "Set password history to remember at least 5 previous passwords.",
                    "evidence": {"history_length": history},
                })

        # ── 3. Firewall ───────────────────────────────────────────────────
        fw_profiles = posture.get("firewall_profiles", [])
        disabled_fw = [p["Name"] for p in fw_profiles if p.get("Enabled") == 0]
        if disabled_fw:
            findings.append({
                "category": "Firewall",
                "severity": "CRITICAL",
                "title": f"Windows Firewall Disabled ({', '.join(disabled_fw)} profile(s))",
                "detail": f"Firewall is disabled for: {', '.join(disabled_fw)}. CE v3.2 requires firewall enabled on all profiles.",
                "remediation": "Enable Windows Firewall for all profiles (Domain, Private, Public) immediately.",
                "evidence": {"disabled_profiles": disabled_fw},
            })

        # ── 4. BitLocker ──────────────────────────────────────────────────
        bitlocker = posture.get("bitlocker", [])
        if bitlocker:
            unencrypted = [b["MountPoint"] for b in bitlocker if b.get("ProtectionStatus") != 1]
            if unencrypted:
                findings.append({
                    "category": "Encryption",
                    "severity": "HIGH",
                    "title": f"Drives Not Encrypted ({', '.join(unencrypted)})",
                    "detail": f"Drive(s) {', '.join(unencrypted)} do not have BitLocker encryption active.",
                    "remediation": "Enable BitLocker encryption on all drives. CE v3.2 requires encryption on devices that may leave the office.",
                    "evidence": {"unencrypted_drives": unencrypted},
                })
        else:
            findings.append({
                "category": "Encryption",
                "severity": "MEDIUM",
                "title": "BitLocker Status Unknown",
                "detail": "Could not determine BitLocker encryption status for this device.",
                "remediation": "Verify BitLocker is enabled via Settings → Privacy & Security → Device Encryption.",
                "evidence": {},
            })

        # ── 5. Defender / AV ─────────────────────────────────────────────
        defender = posture.get("defender", {})
        if defender:
            if not defender.get("AntivirusEnabled"):
                findings.append({
                    "category": "Malware Protection",
                    "severity": "CRITICAL",
                    "title": "Antivirus Disabled",
                    "detail": "Windows Defender antivirus is disabled on this device.",
                    "remediation": "Enable Windows Defender or install a supported third-party AV product immediately.",
                    "evidence": defender,
                })
            elif not defender.get("RealTimeProtectionEnabled"):
                findings.append({
                    "category": "Malware Protection",
                    "severity": "HIGH",
                    "title": "Real-Time Protection Disabled",
                    "detail": "Windows Defender real-time protection is disabled.",
                    "remediation": "Enable real-time protection in Windows Security settings.",
                    "evidence": defender,
                })

            sig_age = defender.get("AntivirusSignatureAge", 0)
            if isinstance(sig_age, (int, float)) and sig_age > 7:
                findings.append({
                    "category": "Malware Protection",
                    "severity": "HIGH",
                    "title": f"Antivirus Signatures Outdated ({sig_age} days old)",
                    "detail": f"Defender signature database is {sig_age} days old. Outdated signatures miss recent malware.",
                    "remediation": "Update Defender signatures immediately. Check Windows Update and internet connectivity.",
                    "evidence": {"signature_age_days": sig_age},
                })

        # ── 6. Screen lock ────────────────────────────────────────────────
        screensaver = posture.get("screensaver_timeout")
        if screensaver is not None:
            try:
                timeout = int(screensaver)
                if timeout == 0:
                    findings.append({
                        "category": "Physical Security",
                        "severity": "MEDIUM",
                        "title": "Screen Lock Disabled",
                        "detail": "No screensaver or screen lock timeout configured.",
                        "remediation": "Enable screen lock with timeout of 5-15 minutes via Group Policy or Display settings.",
                        "evidence": {"screensaver_timeout_seconds": timeout},
                    })
                elif timeout > 900:  # > 15 minutes
                    findings.append({
                        "category": "Physical Security",
                        "severity": "LOW",
                        "title": f"Screen Lock Timeout Too Long ({timeout//60} minutes)",
                        "detail": f"Screen locks after {timeout//60} minutes of inactivity. Recommended: 5-15 minutes.",
                        "remediation": "Reduce screen lock timeout to 15 minutes or less.",
                        "evidence": {"screensaver_timeout_seconds": timeout},
                    })
            except (ValueError, TypeError):
                pass

        # ── Summarise ─────────────────────────────────────────────────────
        agent_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        agent_high     = sum(1 for f in findings if f["severity"] == "HIGH")
        agent_medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")

        risk_score = 100
        risk_score -= min(agent_critical * 20, 40)
        risk_score -= min(agent_high * 10, 30)
        risk_score -= min(agent_medium * 5, 20)
        risk_score = max(0, risk_score)

        total_findings += len(findings)
        critical_count += agent_critical

        collected_at = evt.created_at.isoformat() if evt.created_at else None

        agent_reports.append({
            "agent_id":     agent_id,
            "hostname":     hostname,
            "risk_score":   risk_score,
            "local_admins": local_admins,
            "findings":     findings,
            "critical":     agent_critical,
            "high":         agent_high,
            "medium":       agent_medium,
            "collected_at": collected_at,
            "summary": {
                "firewall_ok":   all(p.get("Enabled") == 1 for p in fw_profiles) if fw_profiles else None,
                "av_ok":         bool(defender.get("AntivirusEnabled") and defender.get("RealTimeProtectionEnabled")) if defender else None,
                "bitlocker_ok":  all(b.get("ProtectionStatus") == 1 for b in bitlocker) if bitlocker else None,
                "admin_count":   len(local_admins),
            }
        })

    # Overall summary
    avg_score = round(sum(r["risk_score"] for r in agent_reports) / len(agent_reports)) if agent_reports else None

    return {
        "agents_assessed": len(agent_reports),
        "total_findings":  total_findings,
        "critical_count":  critical_count,
        "avg_risk_score":  avg_score,
        "agents":          sorted(agent_reports, key=lambda x: x["risk_score"]),
    }
