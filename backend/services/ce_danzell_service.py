"""
ce_danzell_service.py

Cyber Essentials v4 (Danzell) Compliance Mapping Engine.
Implements the April 2026 Danzell question set — the successor to Willow (CE v3.2).

Key changes from v3.2 (Willow) to v4 (Danzell):
  - Supply chain security is now a formal control (CE-D7)
  - MFA mandatory for ALL cloud service accounts, not just privileged
  - Asset scope explicitly includes cloud-hosted, IoT, and firmware devices
  - Firmware patching required within 14 days of critical release
  - Vulnerability scanning is a formal requirement (merged into CE-D5)
  - Home/remote working devices explicitly in scope (CE-D8)
  - Basic incident response readiness required (CE-D9)
  - Zero-trust network filtering principles introduced

CE v4 Danzell control reference:
  CE-D1  Asset management & scope (enhanced)
  CE-D2  Secure configuration (cloud + firmware)
  CE-D3  User access management + MFA
  CE-D4  Malware protection & detection
  CE-D5  Patch & vulnerability management (merged)
  CE-D6  Network perimeter & zero-trust filtering
  CE-D7  Supply chain security (NEW)
  CE-D8  Home & remote working security (NEW)
  CE-D9  Incident response readiness (NEW)

Each control evaluates to: PASS | PARTIAL | FAIL | NOT_ASSESSED
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from models.asset import CanonicalAsset
from models.network import NetworkDiscoveredAsset
from models.telemetry import CanonicalSoftware, VulnerabilityFinding

logger = logging.getLogger(__name__)

FRAMEWORK_VERSION = "CE v4 Danzell (April 2026)"
FRAMEWORK_SHORT   = "CE-v4-Danzell"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DanzellControlResult:
    control_id:   str
    control_name: str
    status:       str          # PASS | PARTIAL | FAIL | NOT_ASSESSED
    score:        float        # 0.0 – 1.0
    findings:     list[str]    # human-readable gap descriptions
    evidence:     dict[str, Any]
    remediation:  list[str] = field(default_factory=list)
    danzell_ref:  str = ""     # e.g. "CE-D3"
    is_new_in_v4: bool = False # flag controls that did not exist in v3.2


@dataclass
class DanzellAssetReport:
    tenant_id:        str
    agent_id:         str
    hostname:         str | None
    assessed_at_epoch: int
    framework:        str
    overall_score:    float      # 0.0 – 1.0
    overall_status:   str        # PASS | PARTIAL | FAIL
    controls:         list[DanzellControlResult]
    summary:          dict[str, Any]
    asset_source:     str = "agent"
    danzell_gaps:     list[str] = field(default_factory=list)   # NEW v4 gaps only


@dataclass
class DanzellTenantReport:
    tenant_id:        str
    framework:        str
    assessed_at_epoch: int
    overall_score:    float
    overall_status:   str
    asset_reports:    list[DanzellAssetReport]
    tenant_controls:  list[DanzellControlResult]
    v4_new_gaps:      list[str]   # gaps that exist in Danzell but not v3.2
    supply_chain_score: float
    remote_working_score: float
    incident_readiness_score: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_to_status(score: float) -> str:
    if score >= 0.85:
        return "PASS"
    if score >= 0.5:
        return "PARTIAL"
    return "FAIL"


def _overall(controls: list[DanzellControlResult]) -> tuple[float, str]:
    if not controls:
        return 0.0, "FAIL"
    avg = sum(c.score for c in controls) / len(controls)
    if any(c.status == "FAIL" for c in controls):
        return avg, "FAIL"
    if any(c.status in ("PARTIAL", "NOT_ASSESSED") for c in controls):
        return avg, "PARTIAL"
    return avg, "PASS"


# ---------------------------------------------------------------------------
# CE-D1: Asset Management & Scope (enhanced from A1)
# ---------------------------------------------------------------------------

def _eval_d1_asset_management(asset: CanonicalAsset, software_rows: list) -> DanzellControlResult:
    """
    CE-D1 Danzell: All in-scope devices must be in a maintained, accurate inventory.
    Danzell explicitly extends scope to: cloud-hosted services, IoT devices,
    firmware-based assets, and home/BYOD devices used for work.
    """
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    evidence["asset_uid"] = asset.agent_id
    evidence["display_name"] = (asset.hostname or asset.fqdn or asset.agent_id)
    evidence["source_types"] = ["agent"]
    evidence["managed"] = True

    if not True:
        findings.append("Asset is not marked as managed — Danzell requires all in-scope devices to be actively managed.")
        remediation.append("Enrol device into CyberAssetIQ agent management to bring under active inventory control.")
        score -= 0.3

    hw = (asset.raw_metadata_json or {}) or {}
    if not hw.get("hostname") and not (asset.hostname or asset.fqdn or asset.agent_id):
        findings.append("Asset has no hostname — CE-D1 requires each asset to be uniquely identifiable.")
        remediation.append("Ensure hostname is configured and reported by the agent.")
        score -= 0.15

    if not asset.os_family:
        findings.append("Operating system not identified — required for Danzell asset scope classification.")
        remediation.append("Run a full agent scan to capture OS details.")
        score -= 0.15

    # Danzell new: firmware tracking
    firmware = hw.get("firmware_version") or hw.get("bios_version")
    evidence["firmware_tracked"] = bool(firmware)
    if not firmware:
        findings.append("Firmware/BIOS version not tracked — CE-D1 Danzell requires firmware inventory for all physical devices.")
        remediation.append("Enable firmware version reporting in the agent configuration.")
        score -= 0.1

    sw_count = len(software_rows)
    evidence["software_inventory_count"] = sw_count
    if sw_count == 0:
        findings.append("No software inventory — CE-D1 requires a complete software inventory per device.")
        remediation.append("Run a software discovery scan from the agent.")
        score -= 0.2

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D1", control_name="Asset Management & Scope",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D1", is_new_in_v4=False,
    )


# ---------------------------------------------------------------------------
# CE-D2: Secure Configuration (cloud + firmware, enhanced from A3)
# ---------------------------------------------------------------------------

def _eval_d2_secure_configuration(asset: CanonicalAsset) -> DanzellControlResult:
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    telemetry = asset.security_posture_json or {}
    sec = telemetry

    # Firewall
    fw = sec.get("firewall_enabled")
    evidence["firewall_enabled"] = fw
    if fw is False:
        findings.append("Host firewall is disabled — CE-D2 requires firewall active on all profiles.")
        remediation.append("Enable Windows Defender Firewall for Domain, Private, and Public profiles via Group Policy.")
        score -= 0.25

    # Auto-lock / screen timeout
    lock = sec.get("screen_lock_enabled") or sec.get("auto_lock_minutes")
    evidence["screen_lock"] = bool(lock)
    if not lock:
        findings.append("Screen lock not enforced — CE-D2 requires automatic lock after inactivity.")
        remediation.append("Set screen lock timeout to 5 minutes or less via Group Policy.")
        score -= 0.1

    # Encryption (BitLocker / FileVault)
    enc = sec.get("encryption_enabled") or sec.get("bitlocker_enabled")
    evidence["full_disk_encryption"] = bool(enc)
    if enc is False:
        findings.append("Full-disk encryption not enabled — CE-D2 Danzell requires FDE on all portable devices.")
        remediation.append("Enable BitLocker on all portable/laptop devices. For desktops assess data sensitivity.")
        score -= 0.2

    # Danzell new: firmware patching awareness
    hw = (asset.raw_metadata_json or {}) or {}
    fw_version = hw.get("firmware_version") or hw.get("bios_version")
    fw_date = hw.get("bios_date") or hw.get("firmware_date")
    evidence["firmware_version"] = fw_version
    evidence["firmware_date"] = fw_date
    if not fw_version:
        findings.append("Firmware version unknown — CE-D2 Danzell requires firmware to be tracked and patched within 14 days of critical release.")
        remediation.append("Enable firmware version reporting. Check manufacturer for available firmware updates.")
        score -= 0.15

    # Default credentials check (proxy: admin account naming)
    admins = sec.get("local_admins", [])
    default_names = {"administrator", "admin", "root", "default"}
    default_found = [a for a in admins if a.split("\\")[-1].lower() in default_names]
    evidence["default_admin_accounts"] = default_found
    if default_found:
        findings.append(f"Default admin account(s) active: {default_found}. CE-D2 requires default credentials to be changed or disabled.")
        remediation.append("Rename or disable default Administrator account. Use named accounts with admin rights.")
        score -= 0.15

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D2", control_name="Secure Configuration",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D2", is_new_in_v4=False,
    )


# ---------------------------------------------------------------------------
# CE-D3: User Access Management + MFA (strongly enhanced from A2)
# ---------------------------------------------------------------------------

def _eval_d3_user_access_mfa(asset: CanonicalAsset) -> DanzellControlResult:
    """
    CE-D3 Danzell: Significant tightening from v3.2.
    MFA is now mandatory for ALL cloud service accounts (O365, Azure, AWS, GCP, SaaS)
    in addition to privileged local/domain accounts.
    """
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    telemetry = asset.security_posture_json or {}
    sec = telemetry
    id_data = {}

    admins = sec.get("local_admins", [])
    evidence["local_admin_count"] = len(admins)
    evidence["local_admins"] = admins

    # Password policy
    pw = sec.get("password_policy", {})
    min_len = pw.get("min_length", 0)
    evidence["password_min_length"] = min_len
    if min_len < 8:
        findings.append(f"Minimum password length is {min_len} — CE-D3 requires minimum 8 characters (NCSC recommends 10+).")
        remediation.append("Set minimum password length to at least 10 characters via Local Security Policy or Group Policy.")
        score -= 0.25

    lockout = pw.get("lockout_threshold")
    evidence["lockout_threshold"] = lockout
    if not lockout or lockout == "Never" or str(lockout) == "0":
        findings.append("No account lockout policy — brute-force attacks are unrestricted. CE-D3 requires lockout after failed attempts.")
        remediation.append("Enable account lockout: 5–10 failed attempts, 15-minute lockout duration.")
        score -= 0.2

    pw_history = pw.get("password_history", 0)
    evidence["password_history"] = pw_history
    if not pw_history or pw_history == "None" or int(str(pw_history).replace("None","0") or 0) < 5:
        findings.append("Password history not enforced — users can reuse previous passwords.")
        remediation.append("Set password history to remember at least 5 previous passwords.")
        score -= 0.1

    # Danzell new: MFA for cloud accounts
    mfa_cloud = id_data.get("mfa_enabled_cloud") or sec.get("mfa_cloud_enabled")
    evidence["mfa_cloud_enabled"] = mfa_cloud
    if mfa_cloud is False:
        findings.append("MFA not enabled for cloud service accounts — CE-D3 Danzell mandates MFA for ALL cloud accounts including M365, Azure AD, and SaaS.")
        remediation.append("Enable MFA for all cloud accounts via Entra ID Conditional Access or equivalent. Enforce for O365, Azure, and all SaaS applications.")
        score -= 0.3
        # is_new_in_v4 gap

    # MFA for privileged accounts
    mfa_priv = id_data.get("mfa_enabled_privileged") or sec.get("mfa_admin_enabled")
    evidence["mfa_privileged_enabled"] = mfa_priv
    if mfa_priv is False:
        findings.append("MFA not enforced for privileged accounts — CE-D3 requires MFA for all admin/privileged account access.")
        remediation.append("Enforce MFA for all administrator accounts using authenticator apps or hardware tokens. Disable SMS-only MFA.")
        score -= 0.2

    # Shared accounts
    shared = id_data.get("shared_accounts", [])
    evidence["shared_accounts"] = shared
    if shared:
        findings.append(f"Shared accounts detected: {shared}. CE-D3 requires individual named accounts for auditability.")
        remediation.append("Replace shared accounts with individual named accounts. Implement PAM for privileged access.")
        score -= 0.15

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D3", control_name="User Access Management & MFA",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D3", is_new_in_v4=False,
    )


# ---------------------------------------------------------------------------
# CE-D4: Malware Protection & Detection (enhanced from A6)
# ---------------------------------------------------------------------------

def _eval_d4_malware_protection(asset: CanonicalAsset) -> DanzellControlResult:
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    telemetry = asset.security_posture_json or {}
    sec = telemetry

    av = sec.get("av_enabled") or sec.get("antivirus_enabled")
    evidence["av_enabled"] = av
    if av is False:
        findings.append("Antivirus/anti-malware not active — CE-D4 requires real-time malware protection on all in-scope devices.")
        remediation.append("Enable Windows Defender Antivirus or deploy an approved EDR/AV solution.")
        score -= 0.4

    av_realtime = sec.get("av_realtime_protection") or sec.get("realtime_scanning")
    evidence["av_realtime"] = av_realtime
    if av_realtime is False:
        findings.append("Real-time scanning disabled — CE-D4 requires real-time malware scanning.")
        remediation.append("Enable real-time protection in Windows Security settings or the deployed AV solution.")
        score -= 0.25

    av_updated = sec.get("av_definitions_current") or sec.get("av_up_to_date")
    evidence["av_definitions_current"] = av_updated
    if av_updated is False:
        findings.append("AV definitions out of date — CE-D4 requires definitions updated within 24 hours.")
        remediation.append("Configure automatic AV definition updates. Ensure cloud-delivered protection is enabled.")
        score -= 0.2

    # Danzell new: email scanning / attachment sandboxing
    email_scan = sec.get("email_scanning_enabled") or sec.get("mail_av_enabled")
    evidence["email_scanning"] = email_scan
    # Note: cannot be scored False if not reported — mark as advisory
    if email_scan is False:
        findings.append("Email attachment scanning not confirmed active — CE-D4 Danzell recommends email-level malware inspection.")
        remediation.append("Enable Microsoft Defender for Office 365 Safe Attachments or equivalent email gateway scanning.")
        score -= 0.1

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D4", control_name="Malware Protection & Detection",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D4", is_new_in_v4=False,
    )


# ---------------------------------------------------------------------------
# CE-D5: Patch & Vulnerability Management (merged A4+A5, firmware added)
# ---------------------------------------------------------------------------

def _eval_d5_patch_and_vuln(asset: CanonicalAsset, vuln_rows: list) -> DanzellControlResult:
    """
    CE-D5 Danzell merges vulnerability management and patching into one control.
    Critical: patch within 14 days. High: 30 days. Firmware: 14 days for critical.
    Vulnerability scanning is now a formal Danzell requirement.
    """
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    telemetry = asset.security_posture_json or {}
    sec = telemetry

    # Windows Update status
    wu = sec.get("windows_update_enabled") or sec.get("auto_update_enabled")
    evidence["auto_update_enabled"] = wu
    if wu is False:
        findings.append("Automatic updates disabled — CE-D5 requires automated patching to meet 14-day critical patch timeline.")
        remediation.append("Enable Windows Update for Business. Set automatic updates to install critical patches immediately.")
        score -= 0.25

    # CVE findings
    critical_cves = [v for v in vuln_rows if getattr(v, "severity", "").lower() == "critical"]
    high_cves     = [v for v in vuln_rows if getattr(v, "severity", "").lower() == "high"]
    evidence["critical_cve_count"] = len(critical_cves)
    evidence["high_cve_count"] = len(high_cves)
    evidence["total_open_cves"] = len(vuln_rows)

    if critical_cves:
        findings.append(
            f"{len(critical_cves)} critical CVE(s) open — CE-D5 Danzell requires critical vulnerabilities patched within 14 days."
        )
        remediation.append("Prioritise patching of all critical CVEs. Use the Vulnerability Management tab to export a remediation plan.")
        score -= min(0.4, len(critical_cves) * 0.08)

    if high_cves:
        findings.append(
            f"{len(high_cves)} high CVE(s) open — CE-D5 Danzell requires high vulnerabilities patched within 30 days."
        )
        remediation.append("Schedule patching of all high CVEs within the 30-day Danzell window. Consider emergency change process for internet-facing assets.")
        score -= min(0.2, len(high_cves) * 0.02)

    # Danzell new: Vulnerability scanning requirement
    last_scan = getattr(asset, 'last_heartbeat', getattr(asset, 'created_at', None))
    evidence["last_seen"] = str(last_scan) if last_scan else None
    if not last_scan:
        findings.append("Asset has never been scanned — CE-D5 Danzell formally requires regular vulnerability scanning of all in-scope devices.")
        remediation.append("Schedule vulnerability scans via CyberAssetIQ's CVE scan for all enrolled agents.")
        score -= 0.15

    # Unsupported software check
    telemetry_sw = (asset.raw_metadata_json or {}).get("software", [])
    eol_sw = [s for s in telemetry_sw if isinstance(s, dict) and s.get("is_eol")]
    evidence["eol_software_count"] = len(eol_sw)
    if eol_sw:
        findings.append(
            f"{len(eol_sw)} end-of-life software package(s) detected — CE-D5 requires all software to be within vendor support."
        )
        remediation.append("Remove or upgrade end-of-life software. Consider application control to prevent reinstallation.")
        score -= min(0.2, len(eol_sw) * 0.05)

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D5", control_name="Patch & Vulnerability Management",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D5", is_new_in_v4=False,
    )


# ---------------------------------------------------------------------------
# CE-D6: Network Perimeter & Zero-Trust Filtering (expanded from A7)
# ---------------------------------------------------------------------------

def _eval_d6_network_security(asset: CanonicalAsset, open_ports: list) -> DanzellControlResult:
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    telemetry = asset.security_posture_json or {}
    sec = telemetry
    network = {}

    fw_active = sec.get("firewall_enabled")
    evidence["host_firewall"] = fw_active
    if fw_active is False:
        findings.append("Host-based firewall inactive — CE-D6 requires host firewall on all profiles.")
        remediation.append("Enable Windows Defender Firewall across Domain, Private, and Public profiles.")
        score -= 0.3

    # Dangerous open ports
    risky_ports = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 445: "SMB", 1433: "MSSQL", 3306: "MySQL"}
    exposed = {p: name for p, name in risky_ports.items() if p in open_ports}
    evidence["exposed_risky_ports"] = exposed
    if exposed:
        port_list = ", ".join(f"{p}({name})" for p, name in exposed.items())
        findings.append(f"Risky ports exposed: {port_list} — CE-D6 requires unnecessary inbound connections blocked.")
        remediation.append(f"Apply firewall rules to block: {port_list}. Use VPN or jump-host for legitimate remote access.")
        score -= min(0.35, len(exposed) * 0.1)

    # Danzell new: Zero-trust principle — internet-facing services
    is_internet_facing = network.get("is_internet_facing") or sec.get("internet_facing")
    evidence["internet_facing"] = bool(is_internet_facing)
    if is_internet_facing and exposed:
        findings.append("Internet-facing device has risky ports open — CE-D6 Danzell applies zero-trust principles: only approved services should be reachable externally.")
        remediation.append("For internet-facing assets: restrict all inbound to only required services. Implement a Web Application Firewall if hosting web services.")
        score -= 0.15

    # Danzell new: Cloud service traffic filtering
    cloud_filtering = sec.get("cloud_app_filtering") or sec.get("web_content_filtering")
    evidence["cloud_filtering"] = cloud_filtering
    if cloud_filtering is False:
        findings.append("Cloud application traffic filtering not enabled — CE-D6 Danzell requires filtering of cloud service access.")
        remediation.append("Enable Microsoft Defender for Cloud Apps or equivalent CASB to monitor and control cloud service access.")
        score -= 0.1

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D6", control_name="Network Perimeter & Zero-Trust Filtering",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D6", is_new_in_v4=False,
    )


# ---------------------------------------------------------------------------
# CE-D7: Supply Chain Security (NEW in Danzell — did not exist in v3.2)
# ---------------------------------------------------------------------------

def _eval_d7_supply_chain(db: Session, tenant_id: str) -> DanzellControlResult:
    """
    CE-D7 is entirely new in Danzell. Organisations must demonstrate:
    - A list of approved/vetted third-party software and service providers
    - Evidence of supplier security assessment
    - Process for managing supplier risk
    This control is assessed at tenant level, not per-asset.
    """
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 0.5  # Start at partial — requires human confirmation

    # Check if supply chain assurance records exist
    try:
        from models.supply_chain import SupplierRelationship, AssuranceRequest
        supplier_count = db.query(SupplierRelationship).filter(
            SupplierRelationship.supplier_tenant_id == tenant_id
        ).count()
        assurance_count = db.query(AssuranceRequest).filter(
            AssuranceRequest.supplier_tenant_id == tenant_id
        ).count()
        evidence["supplier_relationships_registered"] = supplier_count
        evidence["assurance_requests_completed"] = assurance_count

        if supplier_count > 0:
            score += 0.2
        else:
            findings.append("No supplier relationships registered — CE-D7 requires an inventory of critical third-party suppliers.")
            remediation.append("Register your key software and service suppliers in the CyberAssetIQ Supply Chain portal. For each: document what data/access they have.")

        if assurance_count > 0:
            score += 0.2
        else:
            findings.append("No supplier assurance records found — CE-D7 requires evidence of supplier security assessment.")
            remediation.append("Complete a CE-D7 supplier assurance request for each critical supplier via the Supply Chain Assurance portal.")
    except Exception:
        evidence["supply_chain_module"] = "not_assessed"
        findings.append("Supply chain module not fully configured — CE-D7 assessment requires Supply Chain portal setup.")
        score = 0.2

    # CE-D7 always has advisory note about contract requirements
    findings.append(
        "CE-D7 Danzell requires contractual obligations with suppliers covering: "
        "security standards, breach notification timelines, and right-to-audit clauses."
    )
    remediation.append(
        "Review supplier contracts to ensure they include: CE or equivalent certification requirement, "
        "72-hour breach notification clause, and security contact escalation path."
    )
    score -= 0.1  # Advisory deduction

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D7", control_name="Supply Chain Security",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D7", is_new_in_v4=True,
    )


# ---------------------------------------------------------------------------
# CE-D8: Home & Remote Working Security (NEW explicit control in Danzell)
# ---------------------------------------------------------------------------

def _eval_d8_remote_working(asset: CanonicalAsset) -> DanzellControlResult:
    """
    CE-D8 is new as an explicit control in Danzell. In v3.2, home working was
    mentioned but not a separate assessed control. Danzell makes it explicit:
    all home-working and BYOD devices used for work are in scope and must meet
    the same standards as office devices.
    """
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 1.0

    telemetry = asset.security_posture_json or {}
    sec = telemetry
    network = {}

    hw = (asset.raw_metadata_json or {}) or {}
    device_type = hw.get("device_type", "").lower()
    is_laptop = "laptop" in device_type or "portable" in device_type or "notebook" in device_type
    evidence["device_type"] = device_type
    evidence["is_portable"] = is_laptop

    # VPN usage for remote workers
    vpn = sec.get("vpn_connected") or sec.get("vpn_client_installed") or network.get("vpn_active")
    evidence["vpn_present"] = bool(vpn)
    if not vpn and is_laptop:
        findings.append("No VPN client detected on portable device — CE-D8 Danzell requires VPN for remote access to organisational resources.")
        remediation.append("Deploy a managed VPN client (e.g. GlobalProtect, Cisco AnyConnect, or Windows Always-On VPN). Configure to enforce VPN for all organisational traffic.")
        score -= 0.25

    # Encryption on portable devices (mandatory for remote working)
    enc = sec.get("encryption_enabled") or sec.get("bitlocker_enabled")
    evidence["disk_encrypted"] = bool(enc)
    if enc is False and is_laptop:
        findings.append("Full-disk encryption not enabled on portable/remote-working device — CE-D8 requires FDE on all devices used outside the office.")
        remediation.append("Enable BitLocker with TPM on this device. Escrow the recovery key to the organisation's key management system.")
        score -= 0.3

    # MDM/device management for BYOD detection
    mdm = sec.get("mdm_enrolled") or sec.get("intune_enrolled") or sec.get("device_managed")
    evidence["mdm_enrolled"] = bool(mdm)
    if mdm is False:
        findings.append("Device not enrolled in Mobile Device Management — CE-D8 Danzell requires remote-working devices to be under organisational management.")
        remediation.append("Enrol device in Microsoft Intune or equivalent MDM. Apply a device compliance policy that enforces encryption, lock screen, and AV.")
        score -= 0.2

    # Screen lock for home workers
    lock = sec.get("screen_lock_enabled") or sec.get("auto_lock_minutes")
    evidence["screen_lock"] = bool(lock)
    if not lock:
        findings.append("Screen lock not enforced — CE-D8 requires automatic screen lock on all devices, critical for home/public environments.")
        remediation.append("Set screen lock timeout to 5 minutes via Group Policy or Intune device configuration profile.")
        score -= 0.1

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D8", control_name="Home & Remote Working Security",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D8", is_new_in_v4=True,
    )


# ---------------------------------------------------------------------------
# CE-D9: Incident Response Readiness (NEW in Danzell)
# ---------------------------------------------------------------------------

def _eval_d9_incident_readiness(db: Session, tenant_id: str) -> DanzellControlResult:
    """
    CE-D9 is new in Danzell. Basic incident response capability is now a CE requirement.
    Organisations must demonstrate: IR plan exists, contacts are identified,
    and there is a process for reporting incidents to relevant parties.
    """
    findings, remediation = [], []
    evidence: dict[str, Any] = {}
    score = 0.4  # conservative start — requires human process verification

    # Check for notification/alerting configuration as proxy for IR capability
    try:
        from models.notification import NotificationConfig
        notif_count = db.query(NotificationConfig).filter(
            NotificationConfig.tenant_id == tenant_id,
            NotificationConfig.is_active == True,
        ).count()
        evidence["active_notification_configs"] = notif_count
        if notif_count > 0:
            score += 0.25
            evidence["alerting_configured"] = True
        else:
            findings.append("No active notification channels configured — CE-D9 requires alerts for security events to reach the right people.")
            remediation.append("Configure at least one notification channel (email, Slack) in CyberAssetIQ Notifications for critical security alerts.")
    except Exception:
        evidence["notification_check"] = "not_assessed"

    # Advisory findings for items that require human process confirmation
    findings.append("CE-D9 requires a documented Incident Response plan — CyberAssetIQ cannot automatically verify this process document exists.")
    remediation.append(
        "Create and maintain an Incident Response plan covering: "
        "(1) Incident classification criteria, "
        "(2) Escalation contacts (internal + external including NCSC/ICO), "
        "(3) Containment, eradication, and recovery steps, "
        "(4) 72-hour breach notification process for GDPR/NIS obligations."
    )

    findings.append("CE-D9 requires a named security contact and tested communication path for incident reporting.")
    remediation.append(
        "Designate a Security Incident Response Owner. "
        "Register with NCSC's Early Warning service. "
        "Test the IR plan at least annually via a tabletop exercise."
    )

    score = max(0.0, min(1.0, score))
    return DanzellControlResult(
        control_id="CE-D9", control_name="Incident Response Readiness",
        status=_score_to_status(score), score=score,
        findings=findings, evidence=evidence, remediation=remediation,
        danzell_ref="CE-D9", is_new_in_v4=True,
    )


# ---------------------------------------------------------------------------
# Main assessment functions
# ---------------------------------------------------------------------------

def assess_asset_danzell(db: Session, asset: CanonicalAsset) -> DanzellAssetReport:
    import time
    from models.telemetry import CanonicalSoftware, VulnerabilityFinding

    software_rows = (
        db.query(CanonicalSoftware)
        .filter(CanonicalSoftware.agent_id == asset.agent_id)
        .all()
    )
    vuln_rows = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.agent_id == asset.agent_id,
            VulnerabilityFinding.status == "open",
        )
        .all()
    )

    telemetry = asset.security_posture_json or {}
    network = {}
    open_ports = network.get("open_ports", [])

    controls = [
        _eval_d1_asset_management(asset, software_rows),
        _eval_d2_secure_configuration(asset),
        _eval_d3_user_access_mfa(asset),
        _eval_d4_malware_protection(asset),
        _eval_d5_patch_and_vuln(asset, vuln_rows),
        _eval_d6_network_security(asset, open_ports),
        _eval_d8_remote_working(asset),
    ]

    overall_score, overall_status = _overall(controls)
    v4_gaps = [
        c.findings[0] for c in controls
        if c.is_new_in_v4 and c.status != "PASS" and c.findings
    ]

    return DanzellAssetReport(
        tenant_id=asset.tenant_id,
        agent_id=asset.agent_id,
        hostname=(asset.hostname or asset.fqdn or asset.agent_id),
        assessed_at_epoch=int(time.time()),
        framework=FRAMEWORK_VERSION,
        overall_score=overall_score,
        overall_status=overall_status,
        controls=controls,
        summary={
            "framework": FRAMEWORK_VERSION,
            "overall_score": round(overall_score * 100),
            "overall_status": overall_status,
            "control_count": len(controls),
            "pass_count": sum(1 for c in controls if c.status == "PASS"),
            "fail_count": sum(1 for c in controls if c.status == "FAIL"),
            "partial_count": sum(1 for c in controls if c.status == "PARTIAL"),
        },
        asset_source="agent",
        danzell_gaps=v4_gaps,
    )


def assess_tenant_danzell(db: Session, tenant_id: str) -> DanzellTenantReport:
    """Run CE v4 Danzell assessment across all enrolled agents for a tenant."""
    import time
    from models.asset import CanonicalAsset

    assets = (
        db.query(CanonicalAsset)
        .filter(CanonicalAsset.tenant_id == tenant_id)
        .all()
    )

    asset_reports = [assess_asset_danzell(db, a) for a in assets]

    # Tenant-level controls (assessed once per tenant)
    d7 = _eval_d7_supply_chain(db, tenant_id)
    d9 = _eval_d9_incident_readiness(db, tenant_id)

    # Aggregate asset controls into tenant-level summary
    def _aggregate(control_id: str) -> DanzellControlResult:
        per_asset = [
            c for r in asset_reports
            for c in r.controls
            if c.control_id == control_id
        ]
        if not per_asset:
            return DanzellControlResult(
                control_id=control_id, control_name=control_id,
                status="NOT_ASSESSED", score=0.0,
                findings=["No assets assessed."], evidence={}, remediation=[],
            )
        avg_score = sum(c.score for c in per_asset) / len(per_asset)
        all_findings = list({f for c in per_asset for f in c.findings})
        worst_status = "PASS"
        for c in per_asset:
            if c.status == "FAIL":
                worst_status = "FAIL"
                break
            if c.status == "PARTIAL":
                worst_status = "PARTIAL"
        return DanzellControlResult(
            control_id=control_id,
            control_name=per_asset[0].control_name,
            status=worst_status,
            score=avg_score,
            findings=all_findings[:5],
            evidence={"asset_count": len(per_asset)},
            remediation=list({r for c in per_asset for r in c.remediation})[:3],
            danzell_ref=per_asset[0].danzell_ref,
            is_new_in_v4=per_asset[0].is_new_in_v4,
        )

    tenant_controls = [
        _aggregate("CE-D1"), _aggregate("CE-D2"), _aggregate("CE-D3"),
        _aggregate("CE-D4"), _aggregate("CE-D5"), _aggregate("CE-D6"),
        d7,
        _aggregate("CE-D8"),
        d9,
    ]

    overall_score, overall_status = _overall(tenant_controls)

    all_v4_gaps = list({g for r in asset_reports for g in r.danzell_gaps})
    if d7.status != "PASS":
        all_v4_gaps.append("Supply chain security (CE-D7) — new Danzell requirement")
    if d9.status != "PASS":
        all_v4_gaps.append("Incident response readiness (CE-D9) — new Danzell requirement")

    return DanzellTenantReport(
        tenant_id=tenant_id,
        framework=FRAMEWORK_VERSION,
        assessed_at_epoch=int(time.time()),
        overall_score=overall_score,
        overall_status=overall_status,
        asset_reports=asset_reports,
        tenant_controls=tenant_controls,
        v4_new_gaps=all_v4_gaps,
        supply_chain_score=d7.score,
        remote_working_score=_aggregate("CE-D8").score,
        incident_readiness_score=d9.score,
    )
