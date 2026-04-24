from __future__ import annotations

import time
from typing import Any


SEVERITY_WEIGHTS = {
    "CRITICAL": 18,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "critical": 18,
    "high": 10,
    "medium": 5,
    "low": 2,
}

PORT_RISKS = {
    21: (12, "FTP exposed"),
    22: (6, "SSH exposed"),
    23: (22, "Telnet exposed"),
    80: (4, "HTTP service exposed"),
    135: (8, "RPC exposed"),
    139: (10, "SMB/NetBIOS exposed"),
    443: (3, "HTTPS service exposed"),
    445: (14, "SMB exposed"),
    3389: (18, "RDP exposed"),
    5432: (10, "PostgreSQL exposed"),
    3306: (10, "MySQL exposed"),
    5900: (12, "VNC exposed"),
    6379: (14, "Redis exposed"),
    9200: (14, "Elasticsearch exposed"),
}


def _boolish_enabled(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"on", "enabled", "true", "1", "yes", "active", "running", "allow"}:
            return True
        if low in {"off", "disabled", "false", "0", "no", "inactive", "stopped", "deny"}:
            return False
    return None


def _append_issue(target: list[dict[str, Any]], title: str, points: int, severity: str, remediation: str) -> None:
    target.append(
        {
            "title": title,
            "points": points,
            "severity": severity,
            "remediation": remediation,
        }
    )


def compute_asset_risk(
    *,
    managed: bool,
    agent_id: str | None,
    hostname: str | None,
    fqdn: str | None,
    domain: str | None,
    os_family: str | None,
    os_version: str | None,
    ip_addresses: list[str],
    open_ports: list[dict[str, Any]],
    security_posture: dict[str, Any],
    network_risk_hints: list[str],
    vulnerabilities: list[Any],
    linked_darkweb_findings: list[dict[str, Any]],
    last_seen_epoch: int | None,
    software_count: int,
    compliance_score: float | None,
    local_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    darkweb_points = 0

    if not managed:
        _append_issue(
            issues,
            "Unmanaged / shadow IT asset",
            26,
            "high",
            "Install the agent or onboard the device into MDM so posture and ownership are known.",
        )

    if compliance_score is not None and compliance_score < 70:
        penalty = 18 if compliance_score < 50 else 10
        _append_issue(
            issues,
            f"Low compliance score ({round(compliance_score)}%)",
            penalty,
            "high" if penalty >= 15 else "medium",
            "Address the failing CE controls shown in the compliance view.",
        )

    posture = security_posture or {}
    defender = posture.get("defender", {}) if isinstance(posture, dict) else {}
    firewall_profiles = posture.get("firewall_profiles", []) if isinstance(posture, dict) else []
    bitlocker = posture.get("bitlocker", []) if isinstance(posture, dict) else []
    linux_firewall = posture.get("firewall", {}) if isinstance(posture, dict) else {}
    disk_encryption = posture.get("disk_encryption", {}) if isinstance(posture, dict) else {}

    if defender:
        av_enabled = _boolish_enabled(defender.get("AntivirusEnabled") or defender.get("AMServiceEnabled"))
        rt_enabled = _boolish_enabled(defender.get("RealTimeProtectionEnabled"))
        if av_enabled is False or rt_enabled is False:
            _append_issue(
                issues,
                "Endpoint protection is disabled",
                16,
                "high",
                "Re-enable Defender or your primary AV and confirm real-time protection is on.",
            )

    if firewall_profiles:
        disabled_profiles = [row for row in firewall_profiles if _boolish_enabled(row.get("Enabled")) is False]
        if disabled_profiles:
            _append_issue(
                issues,
                "Firewall disabled on one or more profiles",
                18,
                "high",
                "Enable the firewall on all active network profiles and review inbound allow rules.",
            )
    elif linux_firewall:
        states = " ".join(str(v).lower() for v in linux_firewall.values())
        if states and not any(token in states for token in ["active", "running", "enabled"]):
            _append_issue(
                issues,
                "Linux firewall state is not clearly active",
                12,
                "medium",
                "Enable UFW or firewalld and confirm default deny inbound policy.",
            )

    if bitlocker:
        unprotected = [row for row in bitlocker if _boolish_enabled(row.get("ProtectionStatus")) is False or str(row.get("ProtectionStatus")).lower() in {"off", "0"}]
        if unprotected:
            _append_issue(
                issues,
                "Disk encryption missing",
                10,
                "medium",
                "Enable BitLocker or full disk encryption on all portable devices.",
            )
    elif os_family and "linux" in (os_family or "").lower() and not disk_encryption:
        _append_issue(
            issues,
            "Disk encryption status unknown",
            8,
            "medium",
            "Confirm dm-crypt/LUKS or other full disk encryption is enabled.",
        )

    vuln_total = len(vulnerabilities or [])
    if vuln_total:
        critical = sum(1 for row in vulnerabilities if (getattr(row, "severity", None) or "").upper() == "CRITICAL")
        high = sum(1 for row in vulnerabilities if (getattr(row, "severity", None) or "").upper() == "HIGH")
        points = min(34, critical * 14 + high * 7 + max(0, vuln_total - critical - high) * 2)
        title = f"{vuln_total} open CVE finding(s)"
        if critical:
            title = f"{critical} critical and {vuln_total} total open CVEs"
        _append_issue(
            issues,
            title,
            points,
            "critical" if critical else "high",
            "Prioritise internet-facing and critical CVEs first, then patch or mitigate affected software.",
        )

    seen_ports: set[int] = set()
    for port_row in open_ports or []:
        port = port_row.get("port") or port_row.get("local_port")
        if not isinstance(port, int) or port in seen_ports:
            continue
        seen_ports.add(port)
        if port in PORT_RISKS:
            points, label = PORT_RISKS[port]
            severity = "critical" if points >= 18 else "high" if points >= 12 else "medium"
            remediation = f"Review service on port {port}; restrict exposure to trusted networks or disable it if unnecessary."
            _append_issue(issues, label, points, severity, remediation)

    for hint in network_risk_hints or []:
        if not hint:
            continue
        low = str(hint).lower()
        if low == "high":
            _append_issue(issues, "Network scan marked host as high risk", 12, "high", "Investigate exposed services and verify host ownership.")
        elif low == "medium":
            _append_issue(issues, "Network scan marked host as medium risk", 6, "medium", "Review the exposed services and onboard the device if legitimate.")

    if last_seen_epoch:
        age_days = (int(time.time()) - int(last_seen_epoch)) / 86400
        if age_days > 7:
            _append_issue(
                issues,
                f"Telemetry is stale ({int(age_days)} days old)",
                8,
                "medium",
                "Trigger a new scan or confirm the agent is still checking in.",
            )
    elif managed:
        _append_issue(
            issues,
            "No recent telemetry timestamp",
            6,
            "medium",
            "Run a fresh scan to confirm the asset posture is current.",
        )

    if managed and software_count == 0:
        _append_issue(
            issues,
            "Software inventory missing",
            8,
            "medium",
            "Run software inventory collection so the asset can be assessed for vulnerable apps.",
        )

    if local_findings:
        secret_hits = [row for row in local_findings if row.get("secret_type")]
        if secret_hits:
            _append_issue(
                issues,
                f"{len(secret_hits)} local secret finding(s)",
                min(18, 6 + len(secret_hits) * 3),
                "high",
                "Rotate exposed secrets and remove plaintext credentials from the endpoint.",
            )

    for finding in linked_darkweb_findings or []:
        points = SEVERITY_WEIGHTS.get(finding.get("severity"), 5)
        darkweb_points += points
    if linked_darkweb_findings:
        top = linked_darkweb_findings[0]
        _append_issue(
            issues,
            f"Dark web exposure linked ({top.get('matched_value')})",
            min(28, darkweb_points),
            "critical" if darkweb_points >= 18 else "high",
            "Reset exposed credentials, review MFA coverage, and inspect the linked assets for suspicious access.",
        )

    total_score = min(100, sum(item["points"] for item in issues))
    if total_score >= 75:
        level = "critical"
    elif total_score >= 55:
        level = "high"
    elif total_score >= 30:
        level = "medium"
    else:
        level = "low"

    issues.sort(key=lambda item: item["points"], reverse=True)
    recommended_actions: list[str] = []
    for item in issues:
        if item["remediation"] not in recommended_actions:
            recommended_actions.append(item["remediation"])
        if len(recommended_actions) >= 4:
            break

    return {
        "risk_score": total_score,
        "risk_level": level,
        "risk_breakdown": issues,
        "risk_increase_from_darkweb": min(28, darkweb_points),
        "top_risks": [item["title"] for item in issues[:3]],
        "recommended_actions": recommended_actions,
    }
