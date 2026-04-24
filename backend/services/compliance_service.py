from __future__ import annotations

"""
Cyber Essentials v3.2 Compliance Mapping Engine.

Maps collected asset data to the eight CE controls, computes a compliance
score per asset and per tenant, flags gaps with remediation guidance, and
generates structured evidence packages ready for submission.

CE v3.2 control reference (NCSC, April 2025):
  A1  Asset management / inventory
  A2  User access control
  A3  Secure configuration
  A4  Vulnerability management
  A5  Patch management
  A6  Malware protection
  A7  Network perimeter security (firewall)
  A8  Removable media controls

Each control is evaluated as: PASS | PARTIAL | FAIL | NOT_ASSESSED

Asset sources:
  - CanonicalAsset is used for primary CE only when classified as managed and in scope
  - NetworkDiscoveredAsset is used as visibility context, not primary CE pass/fail scope
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset
from models.telemetry import CanonicalSoftware, VulnerabilityFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ControlResult:
    control_id: str
    control_name: str
    status: str          # PASS | PARTIAL | FAIL | NOT_ASSESSED
    score: float         # 0.0 – 1.0
    findings: list[str]  # human-readable gap descriptions
    evidence: dict[str, Any]  # structured evidence data
    remediation: list[str] = field(default_factory=list)


@dataclass
class AssetComplianceReport:
    tenant_id: str
    agent_id: str
    hostname: str | None
    assessed_at_epoch: int
    overall_score: float     # 0.0 – 1.0
    overall_status: str      # PASS | PARTIAL | FAIL
    controls: list[ControlResult]
    summary: dict[str, Any]
    asset_source: str = "agent"   # "agent" | "network"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_to_status(score: float) -> str:
    if score >= 0.85:
        return "PASS"
    if score >= 0.5:
        return "PARTIAL"
    return "FAIL"


def _overall_status(controls: list[ControlResult]) -> tuple[float, str]:
    """
    Compute automated CE readiness from controls that can be technically assessed.

    A8 is excluded from automated pass/fail until manual evidence upload or
    MDM/GPO evidence collection is implemented. A8 still appears in evidence
    as NOT_ASSESSED / manual evidence required.
    """
    scored_controls = [c for c in controls if c.control_id != "A8"]

    if not scored_controls:
        return 0.0, "FAIL"

    avg = sum(c.score for c in scored_controls) / len(scored_controls)

    if any(c.status == "FAIL" for c in scored_controls):
        return avg, "FAIL"
    if any(c.status == "PARTIAL" for c in scored_controls):
        return avg, "PARTIAL"

    return avg, "PASS"


# ---------------------------------------------------------------------------
# Control evaluators — CanonicalAsset (agent-managed)
# ---------------------------------------------------------------------------

def _eval_a1_asset_register(asset: CanonicalAsset, software_rows: list) -> ControlResult:
    """A1: Asset register — is the asset fully inventoried?"""
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    evidence["hostname"] = asset.hostname
    evidence["fqdn"] = asset.fqdn
    evidence["os_family"] = asset.os_family
    evidence["os_version"] = asset.os_version
    evidence["ip_addresses"] = asset.ips or []
    evidence["mac_addresses"] = asset.macs or []
    evidence["serial_number"] = asset.serial_number
    evidence["device_id"] = asset.device_id
    evidence["software_package_count"] = len(software_rows)
    evidence["last_seen_epoch"] = asset.last_snapshot_epoch

    if not asset.hostname:
        findings.append("Hostname not recorded.")
        score -= 0.15
    if not asset.os_version:
        findings.append("OS version not recorded.")
        score -= 0.15
    if not asset.ips:
        findings.append("No IP addresses recorded.")
        score -= 0.1
    if not asset.serial_number and not asset.device_id:
        findings.append("No hardware identifier (serial or device ID) recorded.")
        score -= 0.1
    if len(software_rows) == 0:
        findings.append("No software inventory collected — run agent software collection.")
        score -= 0.2

    # Staleness check: last seen > 7 days ago
    if asset.last_snapshot_epoch:
        age_days = (int(time.time()) - asset.last_snapshot_epoch) / 86400
        evidence["data_age_days"] = round(age_days, 1)
        if age_days > 7:
            findings.append(f"Asset data is {age_days:.0f} days old — CE requires continuous inventory.")
            score -= 0.2
    else:
        findings.append("No snapshot timestamp — data recency cannot be confirmed.")
        score -= 0.1

    score = max(0.0, min(1.0, score))
    status = _score_to_status(score)
    remediation = [
        "Deploy agent on all endpoints and schedule collection every 24h.",
        "Record serial numbers via BIOS/WMI for all physical devices.",
    ] if findings else []

    return ControlResult("A1", "Asset management and inventory", status, score, findings, evidence, remediation)


def _eval_a2_user_access(asset: CanonicalAsset) -> ControlResult:
    """A2: User access control — local admins, least privilege."""
    posture = asset.security_posture_json or {}
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    if asset.os_family == "Windows":
        evidence["os_family"] = "Windows"
        identity_data = posture.get("identity", {})
        local_admins = identity_data.get("local_admins", [])
        evidence["local_admin_accounts"] = local_admins

        if not local_admins:
            findings.append("Local administrator group membership not collected — deploy identity collector.")
            score -= 0.3
        elif len(local_admins) > 2:
            findings.append(
                f"{len(local_admins)} local admin accounts detected. "
                "CE requires minimising privileged accounts."
            )
            score -= 0.2
    elif asset.os_family == "Linux":
        evidence["os_family"] = "Linux"
        findings.append("Linux user access assessment requires SSH access or identity plugin data.")
        score = 0.5
    else:
        evidence["os_family"] = asset.os_family or "Unknown"
        score = 0.5
        findings.append("User access control assessment not fully automated for this OS family.")

    score = max(0.0, min(1.0, score))
    remediation = [
        "Ensure each user operates under a standard (non-admin) account for daily tasks.",
        "Remove stale admin accounts and review admin group membership quarterly.",
        "Enable Windows Hello or MFA for all privileged accounts.",
    ] if findings else []

    return ControlResult("A2", "User access control", _score_to_status(score), score, findings, evidence, remediation)


def _eval_a3_secure_config(asset: CanonicalAsset) -> ControlResult:
    """A3: Secure configuration — hardening baseline."""
    posture = asset.security_posture_json or {}
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    if asset.os_family == "Windows":
        defender = posture.get("defender", {})
        bitlocker_list = posture.get("bitlocker", [])
        firewall_list = posture.get("firewall_profiles", [])

        evidence["defender_status"] = defender
        evidence["bitlocker_volumes"] = bitlocker_list
        evidence["firewall_profiles"] = firewall_list

        unprotected = [
            v for v in bitlocker_list
            if isinstance(v, dict) and v.get("ProtectionStatus") not in ("On", 1, "1", True)
        ]
        if unprotected:
            findings.append(
                f"{len(unprotected)} disk volume(s) not BitLocker-protected. "
                "CE v3.2 requires full-disk encryption on laptops and portable devices."
            )
            score -= 0.25

        findings.append(
            "Manual check required: verify UAC is enabled, Guest account is disabled, "
            "and auto-run is turned off for removable media."
        )
        score -= 0.05

    elif asset.os_family == "Linux":
        disk = posture.get("disk_encryption", {})
        evidence["disk_info"] = disk
        if not disk:
            findings.append("Disk encryption status not collected for Linux asset.")
            score -= 0.2
        findings.append(
            "Manual check required: verify SSH root login is disabled, "
            "password authentication is disabled (key-only), and unnecessary services are stopped."
        )
        score -= 0.05
    else:
        score = 0.5
        findings.append("Secure configuration assessment requires OS-specific data.")

    score = max(0.0, min(1.0, score))
    remediation = [
        "Enable BitLocker on all portable Windows devices with TPM or PIN.",
        "Disable the Guest account and rename the default Administrator account.",
        "Review and remove unnecessary software and services.",
    ] if len(findings) > 1 else []

    return ControlResult("A3", "Secure configuration", _score_to_status(score), score, findings, evidence, remediation)


def _eval_a4_vulnerability_management(
    vuln_rows: list[VulnerabilityFinding],
) -> ControlResult:
    """A4: Vulnerability management — open CVEs by severity."""
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    critical = [v for v in vuln_rows if v.severity == "CRITICAL"]
    high = [v for v in vuln_rows if v.severity == "HIGH"]
    medium = [v for v in vuln_rows if v.severity == "MEDIUM"]

    evidence["total_open_cves"] = len(vuln_rows)
    evidence["critical_cves"] = [
        {"cve_id": v.cve_id, "software": v.software_name, "version": v.software_version}
        for v in critical[:10]
    ]
    evidence["high_cves"] = [
        {"cve_id": v.cve_id, "software": v.software_name}
        for v in high[:10]
    ]
    evidence["medium_count"] = len(medium)

    if critical:
        findings.append(
            f"{len(critical)} CRITICAL CVE(s) found. "
            "CE v3.2 requires critical vulnerabilities to be remediated within 14 days."
        )
        score -= min(0.5, len(critical) * 0.1)

    if high:
        findings.append(
            f"{len(high)} HIGH severity CVE(s) found. "
            "CE v3.2 requires high vulnerabilities to be remediated within 30 days."
        )
        score -= min(0.3, len(high) * 0.05)

    if not vuln_rows:
        findings.append(
            "No vulnerability scan results found. "
            "Run a vulnerability scan before generating CE evidence."
        )
        score = 0.5

    score = max(0.0, min(1.0, score))
    remediation = [
        "Remediate CRITICAL CVEs within 14 days and HIGH CVEs within 30 days.",
        "Schedule automated NVD scans weekly.",
        "Use patch management to prioritise CVE remediation by asset exposure.",
    ] if findings else []

    return ControlResult(
        "A4", "Vulnerability management",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_a5_patch_management(asset: CanonicalAsset, software_rows: list) -> ControlResult:
    """A5: Patch management — OS hotfixes, recency check."""
    posture = asset.security_posture_json or {}
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    if asset.os_family == "Windows":
        hotfixes = posture.get("hotfixes", [])
        evidence["hotfix_count"] = len(hotfixes) if isinstance(hotfixes, list) else 0
        evidence["recent_hotfixes"] = hotfixes[:5] if isinstance(hotfixes, list) else []

        if not hotfixes:
            findings.append(
                "No Windows hotfix data collected. "
                "CE v3.2 requires patches to be applied within 14 days of release."
            )
            score -= 0.4
        else:
            evidence["hotfix_count"] = len(hotfixes)

        os_ver = asset.os_version or ""
        if "Windows 7" in os_ver or "Windows 8" in os_ver or "2008" in os_ver or "2012" in os_ver:
            findings.append(
                f"End-of-life OS detected: {os_ver}. "
                "CE v3.2 requires all software to be within vendor support."
            )
            score -= 0.5

    elif asset.os_family == "Linux":
        evidence["package_count"] = len(software_rows)
        findings.append(
            "Linux patch verification requires running 'apt list --upgradable' or 'yum check-update'. "
            "Automated assessment not yet available — manual review required."
        )
        score = 0.6

    evidence["os_version"] = asset.os_version

    score = max(0.0, min(1.0, score))
    remediation = [
        "Enable Windows Update and set to automatic for security updates.",
        "Apply all critical and security patches within 14 days of release.",
        "Decommission or isolate end-of-life operating systems immediately.",
    ] if findings else []

    return ControlResult(
        "A5", "Patch management",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_a6_malware_protection(asset: CanonicalAsset) -> ControlResult:
    """A6: Malware protection — AV/EDR status."""
    posture = asset.security_posture_json or {}
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    if asset.os_family == "Windows":
        defender = posture.get("defender", {})
        evidence["defender"] = defender

        av_enabled = defender.get("AntivirusEnabled") or defender.get("AMServiceEnabled")
        rt_enabled = defender.get("RealTimeProtectionEnabled")

        if not av_enabled:
            findings.append(
                "Windows Defender antivirus is disabled. "
                "CE v3.2 requires active malware protection on all devices."
            )
            score -= 0.5

        if not rt_enabled:
            findings.append(
                "Windows Defender real-time protection is disabled. "
                "Real-time scanning is required under CE v3.2."
            )
            score -= 0.3

        if av_enabled and rt_enabled and not findings:
            evidence["status_summary"] = "Windows Defender active with real-time protection enabled."

    elif asset.os_family in ("Linux", "Darwin"):
        evidence["os_family"] = asset.os_family
        findings.append(
            "Malware protection verification on Linux/macOS requires additional agent data. "
            "Confirm ClamAV, Malwarebytes, or equivalent is installed and active."
        )
        score = 0.6

    score = max(0.0, min(1.0, score))
    remediation = [
        "Enable Windows Defender or install an approved third-party AV product.",
        "Ensure real-time scanning and automatic definition updates are active.",
        "Verify AV signatures are updated within the last 24 hours.",
    ] if findings else []

    return ControlResult(
        "A6", "Malware protection",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_a7_network_security(asset: CanonicalAsset, open_ports: list[dict]) -> ControlResult:
    """A7: Network perimeter security — firewall rules, open ports."""
    posture = asset.security_posture_json or {}
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    risky_ports = {21, 23, 135, 137, 138, 139, 445, 3389, 5900}
    exposed = [
        p for p in open_ports
        if (p.get("local_port") or p.get("port")) in risky_ports
    ]
    evidence["listening_ports"] = open_ports[:50]
    evidence["risky_ports_exposed"] = exposed

    if exposed:
        port_list = ", ".join(str(p["local_port"]) for p in exposed)
        findings.append(
            f"Risky ports listening: {port_list}. "
            "CE v3.2 requires firewall rules to block unnecessary inbound connections."
        )
        score -= min(0.4, len(exposed) * 0.1)

    if asset.os_family == "Windows":
        fw_profiles = posture.get("firewall_profiles", [])
        evidence["firewall_profiles"] = fw_profiles

        disabled_profiles = [
            p for p in fw_profiles
            if isinstance(p, dict) and not p.get("Enabled")
        ]
        if disabled_profiles:
            names = [p.get("Name", "Unknown") for p in disabled_profiles]
            findings.append(
                f"Windows Firewall disabled for profile(s): {', '.join(names)}. "
                "CE v3.2 requires host firewall active on all profiles."
            )
            score -= 0.4

    elif asset.os_family == "Linux":
        fw_data = posture.get("firewall", {})
        evidence["firewall"] = fw_data
        ufw_status = fw_data.get("ufw", "")
        firewalld_status = fw_data.get("firewalld", "")
        if "inactive" in ufw_status.lower() and "not running" in firewalld_status.lower():
            findings.append("No active host firewall detected (ufw/firewalld both inactive).")
            score -= 0.4

    score = max(0.0, min(1.0, score))
    remediation = [
        "Ensure Windows Firewall is enabled for Domain, Private, and Public profiles.",
        "Block inbound RDP (3389), SMB (445), and Telnet (23) from untrusted networks.",
        "Review all listening services and disable those not required for business.",
    ] if findings else []

    return ControlResult(
        "A7", "Network perimeter security",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_a8_removable_media(_asset) -> ControlResult:
    """A8: Removable media — flagged as requiring manual policy evidence."""
    return ControlResult(
        control_id="A8",
        control_name="Removable media controls",
        status="NOT_ASSESSED",
        score=0.5,
        findings=[
            "Removable media policy requires manual evidence submission. "
            "Provide a written policy document or Group Policy configuration evidence."
        ],
        evidence={
            "note": (
                "CE v3.2 A8 requires either a written policy prohibiting removable media, "
                "or technical controls (GPO, MDM) to enforce encryption or block use. "
                "Automated verification is not available without MDM integration."
            )
        },
        remediation=[
            "Define and communicate a removable media policy.",
            "Use Group Policy to restrict or encrypt USB storage devices.",
            "Enable BitLocker To Go for any permitted removable storage.",
        ],
    )


# ---------------------------------------------------------------------------
# Control evaluators — NetworkDiscoveredAsset (agentless)
# ---------------------------------------------------------------------------

def _eval_net_a1_asset_register(asset: NetworkDiscoveredAsset) -> ControlResult:
    """A1 for network-discovered asset: uses ip, hostname, mac, os_guess, last_seen."""
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    # Best available name
    display_name = asset.hostname or asset.netbios_name or asset.mdns_name
    evidence["ip_address"] = asset.ip_address
    evidence["hostname"] = display_name
    evidence["mac_address"] = asset.mac_address
    evidence["vendor"] = asset.vendor
    evidence["os_guess"] = asset.os_guess
    evidence["os_version"] = asset.os_version
    evidence["os_confidence"] = asset.os_confidence
    evidence["device_type"] = asset.device_type
    evidence["first_seen"] = asset.first_seen
    evidence["last_seen"] = asset.last_seen
    evidence["asset_source"] = "network_scan"
    evidence["agent_installed"] = asset.agent_installed

    # Scored gaps
    if not display_name:
        findings.append("Hostname not resolved — device name unknown. "
                        "CE requires assets to be named and owned.")
        score -= 0.15

    if not asset.mac_address:
        findings.append("MAC address not captured — hardware identity unconfirmed.")
        score -= 0.1

    if not asset.os_guess:
        findings.append("Operating system not identified — deploy agent for OS inventory.")
        score -= 0.2

    if not asset.agent_installed:
        findings.append(
            "No CyberAssetIQ agent installed. This device is network-visible but unmanaged. "
            "CE v3.2 requires full inventory of all in-scope devices."
        )
        score -= 0.2

    # Staleness: last_seen is an ISO string — parse cautiously
    if asset.last_seen:
        try:
            import datetime
            last_seen_dt = datetime.datetime.fromisoformat(asset.last_seen.replace("Z", "+00:00"))
            age_days = (datetime.datetime.now(datetime.timezone.utc) - last_seen_dt).days
            evidence["data_age_days"] = age_days
            if age_days > 7:
                findings.append(
                    f"Asset last seen {age_days} days ago — "
                    "CE requires continuous inventory visibility."
                )
                score -= 0.15
        except Exception:
            pass
    else:
        findings.append("No last-seen timestamp recorded.")
        score -= 0.1

    score = max(0.0, min(1.0, score))
    remediation = [
        "Install the CyberAssetIQ Windows agent to collect full hardware and software inventory.",
        "Assign an owner to each network-discovered device.",
        "Ensure all in-scope devices appear in the CE asset register.",
    ] if findings else []

    return ControlResult(
        "A1", "Asset management and inventory",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_net_a2_user_access(_asset: NetworkDiscoveredAsset) -> ControlResult:
    """A2 for network asset: NOT_ASSESSED — no user data available without agent."""
    return ControlResult(
        control_id="A2",
        control_name="User access control",
        status="NOT_ASSESSED",
        score=0.5,
        findings=[
            "User access control assessment requires agent installation. "
            "This device was discovered via network scan — local account data is unavailable."
        ],
        evidence={
            "note": "Install the CyberAssetIQ agent to assess local admin accounts, "
                    "password policies, and MFA enforcement."
        },
        remediation=[
            "Install the CyberAssetIQ agent on this device to enable automated A2 assessment.",
            "Manually verify: least privilege, no shared accounts, MFA on admin accounts.",
        ],
    )


def _eval_net_a3_secure_config(asset: NetworkDiscoveredAsset) -> ControlResult:
    """A3 for network asset: partial — uses open ports and risk factors as proxy."""
    findings = []
    evidence: dict[str, Any] = {}
    score = 0.75  # Start at PARTIAL — no agent = limited config visibility

    open_ports = asset.open_ports or []
    risk_factors = asset.risk_factors or []
    smb_info = asset.smb_info or {}

    evidence["open_ports_count"] = len(open_ports)
    evidence["risk_factors"] = risk_factors
    evidence["smb_signing"] = smb_info.get("smb_signing", "unknown")
    evidence["assessment_note"] = "Partial assessment — network scan only, no agent data."

    # Check for configuration red flags in risk factors
    config_risks = [
        f for f in risk_factors
        if f in ("default_creds_suspected", "anonymous_ftp", "snmp_public_community",
                 "telnet_enabled", "http_no_https_redirect")
    ]
    if config_risks:
        findings.append(
            f"Configuration risk indicators detected: {', '.join(config_risks)}. "
            "These suggest insecure default settings in violation of CE A3."
        )
        score -= min(0.3, len(config_risks) * 0.1)

    # SMB signing
    if smb_info and smb_info.get("smb_signing") is False:
        findings.append(
            "SMB signing not required — susceptible to relay attacks. "
            "CE A3 requires secure protocol configuration."
        )
        score -= 0.15

    findings.append(
        "Full secure configuration assessment requires agent installation. "
        "Manual verification of UAC, BitLocker, and auto-run settings is required."
    )

    score = max(0.0, min(1.0, score))
    remediation = [
        "Install the CyberAssetIQ agent for automated configuration baseline assessment.",
        "Review and disable any default credentials identified during network scan.",
        "Enable SMB signing to prevent relay attacks on Windows devices.",
    ] if findings else []

    return ControlResult(
        "A3", "Secure configuration",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_net_a4_vulnerability_management(asset: NetworkDiscoveredAsset) -> ControlResult:
    """A4 for network asset: uses pre-computed CVE counts and vulnerability JSON."""
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    vulns = asset.vulnerabilities or []
    critical_count = asset.critical_cve_count or 0
    high_count = asset.high_cve_count or 0
    medium_count = asset.medium_cve_count or 0
    total = asset.cve_count or len(vulns)

    evidence["total_cves"] = total
    evidence["critical_count"] = critical_count
    evidence["high_count"] = high_count
    evidence["medium_count"] = medium_count
    evidence["sample_cves"] = [
        {"cve_id": v.get("cve_id"), "severity": v.get("severity"), "title": v.get("title")}
        for v in vulns[:10]
    ]
    evidence["data_source"] = "network_scan_cve_correlation"

    if total == 0:
        findings.append(
            "No CVE data available for this network-discovered asset. "
            "Run a vulnerability scan or install the agent for NVD correlation."
        )
        score = 0.5
    else:
        if critical_count > 0:
            findings.append(
                f"{critical_count} CRITICAL CVE(s) detected via network scan. "
                "CE v3.2 requires critical vulnerabilities remediated within 14 days."
            )
            score -= min(0.5, critical_count * 0.1)

        if high_count > 0:
            findings.append(
                f"{high_count} HIGH severity CVE(s) detected. "
                "CE v3.2 requires high vulnerabilities remediated within 30 days."
            )
            score -= min(0.3, high_count * 0.05)

    score = max(0.0, min(1.0, score))
    remediation = [
        "Remediate CRITICAL CVEs within 14 days and HIGH CVEs within 30 days.",
        "Install the CyberAssetIQ agent for continuous software-level CVE correlation.",
        "Schedule network-based vulnerability scans weekly.",
    ] if findings else []

    return ControlResult(
        "A4", "Vulnerability management",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_net_a5_patch_management(asset: NetworkDiscoveredAsset) -> ControlResult:
    """A5 for network asset: checks os_guess for EOL signals; otherwise PARTIAL."""
    findings = []
    evidence: dict[str, Any] = {}
    score = 0.65  # Start PARTIAL — can't verify patches without agent

    os_text = f"{asset.os_guess or ''} {asset.os_version or ''}".lower()
    evidence["os_guess"] = asset.os_guess
    evidence["os_version"] = asset.os_version
    evidence["assessment_note"] = "Patch status assessed from OS fingerprint only — agent required for full verification."

    # EOL OS detection from nmap fingerprint
    eol_signals = [
        ("windows xp", "Windows XP"),
        ("windows vista", "Windows Vista"),
        ("windows 7", "Windows 7"),
        ("windows 8 ", "Windows 8"),
        ("server 2003", "Windows Server 2003"),
        ("server 2008", "Windows Server 2008"),
        ("server 2012", "Windows Server 2012"),
        ("ubuntu 14", "Ubuntu 14.04"),
        ("ubuntu 16", "Ubuntu 16.04"),
        ("ubuntu 18", "Ubuntu 18.04"),
        ("centos 6", "CentOS 6"),
        ("centos 7", "CentOS 7"),
        ("debian 8", "Debian 8"),
        ("debian 9", "Debian 9"),
    ]
    for signal, label in eol_signals:
        if signal in os_text:
            findings.append(
                f"End-of-life OS detected: {label}. "
                "CE v3.2 requires all software to be within vendor support. "
                "This device must be upgraded or isolated immediately."
            )
            score -= 0.5
            break

    if not findings:
        findings.append(
            "Patch status cannot be fully verified from network scan alone. "
            "Install the CyberAssetIQ agent to assess Windows Update compliance and hotfix history."
        )
        score = 0.65

    score = max(0.0, min(1.0, score))
    remediation = [
        "Install the CyberAssetIQ agent to collect hotfix and patch data.",
        "If end-of-life OS confirmed, upgrade immediately or isolate from network.",
        "Apply all available OS patches within 14 days of release.",
    ] if findings else []

    return ControlResult(
        "A5", "Patch management",
        _score_to_status(score), score, findings, evidence, remediation,
    )


def _eval_net_a6_malware_protection(_asset: NetworkDiscoveredAsset) -> ControlResult:
    """A6 for network asset: NOT_ASSESSED — AV status requires agent."""
    return ControlResult(
        control_id="A6",
        control_name="Malware protection",
        status="NOT_ASSESSED",
        score=0.5,
        findings=[
            "Malware protection status cannot be verified via network scan. "
            "Agent installation required to confirm AV/EDR product status."
        ],
        evidence={
            "note": "Install the CyberAssetIQ agent to verify Windows Defender status, "
                    "real-time protection, and definition update recency."
        },
        remediation=[
            "Install the CyberAssetIQ agent on this device to enable A6 assessment.",
            "Manually confirm an approved AV product is installed and active.",
        ],
    )


def _eval_net_a7_network_security(asset: NetworkDiscoveredAsset) -> ControlResult:
    """A7 for network asset: full assessment — open_ports data is rich."""
    findings = []
    evidence: dict[str, Any] = {}
    score = 1.0

    open_ports = asset.open_ports or []
    risk_factors = asset.risk_factors or []
    services = asset.services or []

    risky_ports = {21, 23, 135, 137, 138, 139, 445, 3389, 5900, 1433, 3306, 5432}
    risky_port_names = {
        21: "FTP", 23: "Telnet", 135: "RPC", 137: "NetBIOS-NS",
        138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 445: "SMB",
        3389: "RDP", 5900: "VNC", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL"
    }

    exposed = []
    for p in open_ports:
        port_num = p.get("port") or p.get("portid")
        try:
            port_num = int(port_num)
        except (TypeError, ValueError):
            continue
        if port_num in risky_ports:
            exposed.append({"port": port_num, "name": risky_port_names.get(port_num, str(port_num))})

    evidence["open_ports"] = open_ports[:50]
    evidence["open_port_count"] = len(open_ports)
    evidence["risky_ports_exposed"] = exposed
    evidence["risk_factors"] = risk_factors
    evidence["internet_facing"] = asset.is_internet_facing

    if exposed:
        names = ", ".join(f"{e['name']} ({e['port']})" for e in exposed)
        findings.append(
            f"Risky services exposed on network: {names}. "
            "CE v3.2 requires firewall rules to block unnecessary inbound connections."
        )
        score -= min(0.5, len(exposed) * 0.1)

    if asset.is_internet_facing:
        findings.append(
            "Device is internet-facing. CE v3.2 requires a boundary firewall "
            "blocking all inbound connections except those explicitly required."
        )
        score -= 0.2

    if "telnet_enabled" in risk_factors:
        findings.append("Telnet service active — unencrypted remote access violates CE A7.")
        score -= 0.2

    if "rdp_exposed" in risk_factors:
        findings.append(
            "RDP exposed — CE v3.2 requires RDP restricted to authorised users "
            "and not accessible from untrusted networks."
        )
        score -= 0.15

    if not open_ports:
        evidence["note"] = "No open ports detected — firewall posture appears good."

    score = max(0.0, min(1.0, score))
    remediation = [
        "Restrict RDP (3389) and SMB (445) to management VLANs only.",
        "Disable Telnet (23) and FTP (21) — use SSH and SFTP instead.",
        "Review all exposed services and close any not required for business operations.",
        "Ensure a host firewall is enabled (Windows Firewall / ufw / firewalld).",
    ] if findings else []

    return ControlResult(
        "A7", "Network perimeter security",
        _score_to_status(score), score, findings, evidence, remediation,
    )


# ---------------------------------------------------------------------------
# Orchestration — CanonicalAsset (agent)
# ---------------------------------------------------------------------------

def assess_asset(
    db: Session,
    tenant_id: str,
    agent_id: str,
) -> AssetComplianceReport | None:
    """
    Run all CE v3.2 controls for a single agent-managed asset.
    """
    asset = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id, CanonicalAsset.agent_id == agent_id)
        .first()
    )
    if not asset:
        return None

    if (
        asset.asset_state != "managed"
        or asset.management_state != "managed"
        or asset.compliance_scope != "in_scope"
        or not asset.agent_installed
    ):
        return None

    software_rows = (
        db.query(CanonicalSoftware)
        .filter(CanonicalSoftware.tenant_id == tenant_id, CanonicalSoftware.agent_id == agent_id)
        .all()
    )

    vuln_rows = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.tenant_id == tenant_id,
            VulnerabilityFinding.agent_id == agent_id,
            VulnerabilityFinding.status == "open",
        )
        .all()
    )

    posture = asset.security_posture_json or {}
    open_ports = posture.get("open_ports", [])

    controls = [
        _eval_a1_asset_register(asset, software_rows),
        _eval_a2_user_access(asset),
        _eval_a3_secure_config(asset),
        _eval_a4_vulnerability_management(vuln_rows),
        _eval_a5_patch_management(asset, software_rows),
        _eval_a6_malware_protection(asset),
        _eval_a7_network_security(asset, open_ports),
        _eval_a8_removable_media(asset),
    ]

    overall_score, overall_status = _overall_status(controls)

    return AssetComplianceReport(
        tenant_id=tenant_id,
        agent_id=agent_id,
        hostname=asset.hostname,
        assessed_at_epoch=int(time.time()),
        overall_score=round(overall_score, 3),
        overall_status=overall_status,
        asset_source="agent",
        controls=controls,
        summary={
            "controls_pass": sum(1 for c in controls if c.status == "PASS"),
            "controls_partial": sum(1 for c in controls if c.status == "PARTIAL"),
            "controls_fail": sum(1 for c in controls if c.status == "FAIL"),
            "controls_not_assessed": sum(1 for c in controls if c.status == "NOT_ASSESSED"),
            "total_controls": len(controls),
            "ce_ready": overall_status == "PASS",
        },
    )


# ---------------------------------------------------------------------------
# Orchestration — NetworkDiscoveredAsset (agentless)
# ---------------------------------------------------------------------------

def assess_network_asset(
    db: Session,
    tenant_id: str,
    asset_db_id: int,
) -> AssetComplianceReport | None:
    """
    Run CE v3.2 controls for a single network-discovered (agentless) asset.
    Uses a synthetic agent_id of the form 'net-{id}'.
    """
    asset = (
        db.query(NetworkDiscoveredAsset)
        .filter(
            NetworkDiscoveredAsset.tenant_id == tenant_id,
            NetworkDiscoveredAsset.id == asset_db_id,
            NetworkDiscoveredAsset.is_active.is_(True),
        )
        .first()
    )
    if not asset:
        return None

    synthetic_id = f"net-{asset.id}"
    display_name = asset.hostname or asset.netbios_name or asset.mdns_name or asset.ip_address

    controls = [
        _eval_net_a1_asset_register(asset),
        _eval_net_a2_user_access(asset),
        _eval_net_a3_secure_config(asset),
        _eval_net_a4_vulnerability_management(asset),
        _eval_net_a5_patch_management(asset),
        _eval_net_a6_malware_protection(asset),
        _eval_net_a7_network_security(asset),
        _eval_a8_removable_media(asset),
    ]

    overall_score, overall_status = _overall_status(controls)

    return AssetComplianceReport(
        tenant_id=tenant_id,
        agent_id=synthetic_id,
        hostname=display_name,
        assessed_at_epoch=int(time.time()),
        overall_score=round(overall_score, 3),
        overall_status=overall_status,
        asset_source="network",
        controls=controls,
        summary={
            "controls_pass": sum(1 for c in controls if c.status == "PASS"),
            "controls_partial": sum(1 for c in controls if c.status == "PARTIAL"),
            "controls_fail": sum(1 for c in controls if c.status == "FAIL"),
            "controls_not_assessed": sum(1 for c in controls if c.status == "NOT_ASSESSED"),
            "total_controls": len(controls),
            "ce_ready": overall_status == "PASS",
        },
    )


# ---------------------------------------------------------------------------
# Tenant-level assessment — combines agent + network assets
# ---------------------------------------------------------------------------

def assess_tenant(db: Session, tenant_id: str) -> dict[str, Any]:
    """
    Run CE v3.2 assessment for a tenant using strict asset-governance rules.

    Primary CE compliance:
    - managed, in-scope, agent-backed assets only

    Separate visibility context:
    - observed/unmanaged/guest assets are reported as visibility gaps
    - they do not directly determine CE readiness
    """
    reports: list[AssetComplianceReport] = []

    managed_assets = (
        db.query(CanonicalAsset)
        .filter(
            CanonicalAsset.tenant_id == tenant_id,
            CanonicalAsset.asset_state == "managed",
            CanonicalAsset.management_state == "managed",
            CanonicalAsset.compliance_scope == "in_scope",
            CanonicalAsset.agent_installed.is_(True),
        )
        .all()
    )
    for asset in managed_assets:
        report = assess_asset(db, tenant_id, asset.agent_id)
        if report:
            reports.append(report)

    net_assets = (
        db.query(NetworkDiscoveredAsset)
        .filter(
            NetworkDiscoveredAsset.tenant_id == tenant_id,
            NetworkDiscoveredAsset.is_active.is_(True),
            NetworkDiscoveredAsset.agent_installed.is_(False),
            NetworkDiscoveredAsset.asset_confidence != "observed_host",
        )
        .all()
    )
    for net_asset in net_assets:
        report = assess_network_asset(db, tenant_id, net_asset.id)
        if report:
            reports.append(report)

    now_epoch = int(time.time())

    if not managed_assets:
        empty_controls = {
            f"A{i}": {
                "control_id": f"A{i}",
                "name": "",
                "status": "NOT_ASSESSED",
                "average_score": 0.0,
                "pass_count": 0,
                "partial_count": 0,
                "fail_count": 0,
                "not_assessed_count": 0,
                "affected_assets": [],
                "top_findings": [],
                "top_remediation": [],
            }
            for i in range(1, 9)
        }
        return {
            "tenant_id": tenant_id,
            "assessed_at_epoch": now_epoch,
            "assets_assessed": 0,
            "managed_assets_assessed": 0,
            "observed_assets_considered": len(net_assets),
            "assets_passing": 0,
            "assets_partial": 0,
            "assets_failing": 0,
            "ce_ready": False,
            "tenant_overall_score": 0.0,
            "control_summary": empty_controls,
            "visibility_gaps": {
                "observed_assets": len(net_assets),
                "unmanaged_known_assets": 0,
                "observed_unknown_assets": 0,
                "guest_assets": 0,
                "rogue_assets": 0,
            },
            "assets": [
    {
        "agent_id": r.agent_id,
        "hostname": r.hostname,
        "asset_source": r.asset_source,
        "overall_status": r.overall_status,
        "overall_score": r.overall_score,
        "summary": r.summary,
        "controls": {
            c.control_id: {
                "name": c.control_name,
                "status": c.status,
                "score": round(c.score, 3),
                "finding_count": len(c.findings),
                "findings": c.findings,
                "evidence": c.evidence,
                "remediation": c.remediation,
            }
            for c in r.controls
        },
    }
    for r in reports
],
        }

    managed_reports = [r for r in reports if r.asset_source == "agent"]
    network_reports = [r for r in reports if r.asset_source == "network"]

    passing_assets = [r for r in managed_reports if r.overall_status == "PASS"]
    partial_assets = [r for r in managed_reports if r.overall_status == "PARTIAL"]
    failing_assets = [r for r in managed_reports if r.overall_status == "FAIL"]

    control_rollup: dict[str, dict[str, Any]] = {}

    for report in managed_reports:
        for c in report.controls:
            bucket = control_rollup.setdefault(
                c.control_id,
                {
                    "control_id": c.control_id,
                    "name": c.control_name,
                    "scores": [],
                    "pass_count": 0,
                    "partial_count": 0,
                    "fail_count": 0,
                    "not_assessed_count": 0,
                    "affected_assets": [],
                    "top_findings": [],
                    "top_remediation": [],
                },
            )

            bucket["scores"].append(c.score)

            if c.status == "PASS":
                bucket["pass_count"] += 1
            elif c.status == "PARTIAL":
                bucket["partial_count"] += 1
            elif c.status == "FAIL":
                bucket["fail_count"] += 1
            else:
                bucket["not_assessed_count"] += 1

            if c.status in ("PARTIAL", "FAIL", "NOT_ASSESSED"):
                bucket["affected_assets"].append(
                    {
                        "agent_id": report.agent_id,
                        "hostname": report.hostname,
                        "asset_source": report.asset_source,
                        "overall_status": report.overall_status,
                        "control_status": c.status,
                        "control_score": round(c.score, 3),
                        "findings": c.findings,
                        "remediation": c.remediation,
                    }
                )

            for finding in c.findings[:3]:
                if finding not in bucket["top_findings"]:
                    bucket["top_findings"].append(finding)

            for fix in c.remediation[:3]:
                if fix not in bucket["top_remediation"]:
                    bucket["top_remediation"].append(fix)

    control_summary: dict[str, dict[str, Any]] = {}

    for control_id, bucket in control_rollup.items():
        avg_score = round(sum(bucket["scores"]) / len(bucket["scores"]), 3) if bucket["scores"] else 0.0

        if bucket["fail_count"] > 0:
            status = "FAIL"
        elif bucket["partial_count"] > 0 or bucket["not_assessed_count"] > 0:
            status = "PARTIAL"
        else:
            status = "PASS"

        control_summary[control_id] = {
            "control_id": control_id,
            "name": bucket["name"],
            "status": status,
            "average_score": avg_score,
            "pass_count": bucket["pass_count"],
            "partial_count": bucket["partial_count"],
            "fail_count": bucket["fail_count"],
            "not_assessed_count": bucket["not_assessed_count"],
            "affected_assets": bucket["affected_assets"][:25],
            "top_findings": bucket["top_findings"][:5],
            "top_remediation": bucket["top_remediation"][:5],
        }

    for i in range(1, 9):
        cid = f"A{i}"
        if cid not in control_summary:
            control_summary[cid] = {
                "control_id": cid,
                "name": "",
                "status": "NOT_ASSESSED",
                "average_score": 0.0,
                "pass_count": 0,
                "partial_count": 0,
                "fail_count": 0,
                "not_assessed_count": 0,
                "affected_assets": [],
                "top_findings": [],
                "top_remediation": [],
            }

    return {
        "tenant_id": tenant_id,
        "assessed_at_epoch": now_epoch,
        "assets_assessed": len(managed_reports),
        "managed_assets_assessed": len(managed_reports),
        "observed_assets_considered": len(network_reports),
        "assets_passing": len(passing_assets),
        "assets_partial": len(partial_assets),
        "assets_failing": len(failing_assets),
        "ce_ready": len(managed_reports) > 0 and len(failing_assets) == 0 and len(partial_assets) == 0,
        "tenant_overall_score": round(
            sum(r.overall_score for r in managed_reports) / len(managed_reports), 3
        ) if managed_reports else 0.0,
        "visibility_gaps": {
            "observed_assets": len(network_reports),
            "unmanaged_known_assets": db.query(CanonicalAsset).filter(
                CanonicalAsset.tenant_id == tenant_id,
                CanonicalAsset.asset_state == "unmanaged_known",
            ).count(),
            "observed_unknown_assets": db.query(CanonicalAsset).filter(
                CanonicalAsset.tenant_id == tenant_id,
                CanonicalAsset.asset_state == "observed_unknown",
            ).count(),
            "guest_assets": db.query(CanonicalAsset).filter(
                CanonicalAsset.tenant_id == tenant_id,
                CanonicalAsset.asset_state == "guest",
            ).count(),
            "rogue_assets": db.query(CanonicalAsset).filter(
                CanonicalAsset.tenant_id == tenant_id,
                CanonicalAsset.asset_state == "rogue",
            ).count(),
        },
        "control_summary": control_summary,
        "assets": [
            {
                "agent_id": r.agent_id,
                "hostname": r.hostname,
                "asset_source": r.asset_source,
                "overall_status": r.overall_status,
                "overall_score": r.overall_score,
                "summary": r.summary,
                "controls": {
                    c.control_id: {
                        "name": c.control_name,
                        "status": c.status,
                        "score": round(c.score, 3),
                        "finding_count": len(c.findings),
                        "findings": c.findings,
                        "evidence": c.evidence,
                        "remediation": c.remediation,
                    }
                    for c in r.controls
                },
            }
            for r in reports
        ],
    }

# ---------------------------------------------------------------------------
# Compliance run history — save & retrieve
# ---------------------------------------------------------------------------

def save_compliance_run(
    db: Session,
    tenant_id: str,
    triggered_by: str = "user",
) -> dict[str, Any]:
    """
    Run a full compliance assessment and persist the results as an immutable
    ComplianceRun + ComplianceRunAsset rows.

    Called when the user clicks 'Run Assessment'. Returns the same structure
    as assess_tenant() but also writes to the DB for historical tracking.

    CE v3.2 / IASME require 12 months of compliance evidence retention.
    The cleanup loop in app.py purges runs older than 12 months.
    """
    from models.compliance_run import ComplianceRun, ComplianceRunAsset

    result = assess_tenant(db, tenant_id)
    run_epoch = int(time.time())

    run = ComplianceRun(
        tenant_id=tenant_id,
        run_epoch=run_epoch,
        assets_assessed=result["assets_assessed"],
        agent_assets_assessed=result.get("managed_assets_assessed", 0),
        network_assets_assessed=result.get("observed_assets_considered", 0),
        assets_passing=result["assets_passing"],
        assets_partial=result["assets_partial"],
        assets_failing=result["assets_failing"],
        ce_ready=result["ce_ready"],
        tenant_overall_score=result["tenant_overall_score"],
        triggered_by=triggered_by,
    )
    db.add(run)
    db.flush()  # get run.id

    for asset in result.get("assets", []):
        db.add(ComplianceRunAsset(
            run_id=run.id,
            tenant_id=tenant_id,
            agent_id=asset["agent_id"],
            hostname=asset.get("hostname"),
            asset_source=asset.get("asset_source", "agent"),
            overall_status=asset.get("overall_status"),
            overall_score=asset.get("overall_score", 0.0),
            controls_json=asset.get("controls", {}),
        ))

    db.commit()
    result["run_id"] = run.id
    result["run_epoch"] = run_epoch
    return result


def get_compliance_runs(
    db: Session, tenant_id: str, limit: int = 50
) -> list[dict[str, Any]]:
    """Return all compliance runs for a tenant, newest first (up to 12 months)."""
    from models.compliance_run import ComplianceRun
    cutoff = int(time.time()) - (365 * 24 * 3600)
    runs = (
        db.query(ComplianceRun)
        .filter(
            ComplianceRun.tenant_id == tenant_id,
            ComplianceRun.run_epoch >= cutoff,
        )
        .order_by(ComplianceRun.run_epoch.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "run_epoch": r.run_epoch,
            "assets_assessed": r.assets_assessed,
            "managed_assets_assessed": r.agent_assets_assessed,
            "observed_assets_considered": r.network_assets_assessed,
            "agent_assets_assessed": r.agent_assets_assessed,
            "network_assets_assessed": r.network_assets_assessed,
            "assets_passing": r.assets_passing,
            "assets_partial": r.assets_partial,
            "assets_failing": r.assets_failing,
            "ce_ready": r.ce_ready,
            "tenant_overall_score": r.tenant_overall_score,
            "triggered_by": r.triggered_by,
        }
        for r in runs
    ]


def get_compliance_run_detail(
    db: Session, tenant_id: str, run_id: int
) -> dict[str, Any] | None:
    """Return full asset-level detail for a specific compliance run."""
    from models.compliance_run import ComplianceRun, ComplianceRunAsset
    run = db.query(ComplianceRun).filter(
        ComplianceRun.id == run_id,
        ComplianceRun.tenant_id == tenant_id,
    ).first()
    if not run:
        return None

    assets = db.query(ComplianceRunAsset).filter(
        ComplianceRunAsset.run_id == run_id
    ).all()

    return {
        "id": run.id,
        "run_epoch": run.run_epoch,
        "tenant_id": run.tenant_id,
        "assets_assessed": run.assets_assessed,
        "managed_assets_assessed": run.agent_assets_assessed,
        "observed_assets_considered": run.network_assets_assessed,
        "agent_assets_assessed": run.agent_assets_assessed,
        "network_assets_assessed": run.network_assets_assessed,
        "assets_passing": run.assets_passing,
        "assets_partial": run.assets_partial,
        "assets_failing": run.assets_failing,
        "ce_ready": run.ce_ready,
        "tenant_overall_score": run.tenant_overall_score,
        "triggered_by": run.triggered_by,
        "assets": [
            {
                "agent_id": a.agent_id,
                "hostname": a.hostname,
                "asset_source": a.asset_source,
                "overall_status": a.overall_status,
                "overall_score": a.overall_score,
                "controls": a.controls_json or {},
            }
            for a in assets
        ],
    }


def get_control_detail(
    db: Session,
    tenant_id: str,
    control_id: str,
) -> dict[str, Any]:
    """
    Return a tenant-level drilldown for one CE control (A1-A8).
    """
    tenant = assess_tenant(db, tenant_id)
    control_summary = tenant.get("control_summary", {})
    detail = control_summary.get(control_id.upper())

    if not detail:
        return {
            "tenant_id": tenant_id,
            "control_id": control_id.upper(),
            "status": "NOT_FOUND",
            "affected_assets": [],
        }

    return {
        "tenant_id": tenant_id,
        "assessed_at_epoch": tenant.get("assessed_at_epoch"),
        "control_id": detail["control_id"],
        "control_name": detail["name"],
        "status": detail["status"],
        "average_score": detail["average_score"],
        "pass_count": detail["pass_count"],
        "partial_count": detail["partial_count"],
        "fail_count": detail["fail_count"],
        "not_assessed_count": detail["not_assessed_count"],
        "top_findings": detail["top_findings"],
        "top_remediation": detail["top_remediation"],
        "affected_assets": detail["affected_assets"],
    }


def purge_old_compliance_runs(db: Session) -> int:
    """Delete compliance runs older than 12 months. Called by cleanup loop in app.py."""
    from models.compliance_run import ComplianceRun
    cutoff = int(time.time()) - (365 * 24 * 3600)
    old_runs = db.query(ComplianceRun).filter(
        ComplianceRun.run_epoch < cutoff
    ).all()
    count = len(old_runs)
    for r in old_runs:
        db.delete(r)  # CASCADE deletes ComplianceRunAsset rows
    if count:
        db.commit()
    return count
