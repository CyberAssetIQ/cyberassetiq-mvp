"""
AI MITRE Service
Maps detection types and event patterns to MITRE ATT&CK tactics and techniques.
Reference: https://attack.mitre.org/
"""
from typing import Optional, Tuple

# Mapping: detection_type / alert_type -> (tactic, technique_id, technique_name)
DETECTION_TO_MITRE = {
    # Initial Access
    "phishing":                     ("Initial Access",          "T1566",  "Phishing"),
    "external_login":               ("Initial Access",          "T1078",  "Valid Accounts"),
    "vpn_anomaly":                  ("Initial Access",          "T1133",  "External Remote Services"),
    "exposed_rdp":                  ("Initial Access",          "T1133",  "External Remote Services"),

    # Credential Access
    "brute_force":                  ("Credential Access",       "T1110",  "Brute Force"),
    "brute_force_success":          ("Credential Access",       "T1110",  "Brute Force"),
    "password_spray":               ("Credential Access",       "T1110.003", "Password Spraying"),
    "credential_dumping":           ("Credential Access",       "T1003",  "OS Credential Dumping"),
    "api_key_exposure":             ("Credential Access",       "T1552",  "Unsecured Credentials"),
    "credential_exposure":          ("Credential Access",       "T1552",  "Unsecured Credentials"),

    # Defense Evasion
    "log_cleared":                  ("Defense Evasion",         "T1070",  "Indicator Removal"),
    "audit_disabled":               ("Defense Evasion",         "T1562",  "Impair Defenses"),
    "av_disabled":                  ("Defense Evasion",         "T1562.001", "Disable or Modify Tools"),

    # Discovery
    "port_scan":                    ("Discovery",               "T1046",  "Network Service Discovery"),
    "asset_discovery":              ("Discovery",               "T1018",  "Remote System Discovery"),
    "user_enumeration":             ("Discovery",               "T1087",  "Account Discovery"),

    # Lateral Movement
    "lateral_movement":             ("Lateral Movement",        "T1021",  "Remote Services"),
    "smb_lateral":                  ("Lateral Movement",        "T1021.002", "SMB/Windows Admin Shares"),
    "rdp_lateral":                  ("Lateral Movement",        "T1021.001", "Remote Desktop Protocol"),

    # Privilege Escalation
    "privilege_escalation":         ("Privilege Escalation",    "T1068",  "Exploitation for Privilege Escalation"),
    "new_admin_account":            ("Privilege Escalation",    "T1136",  "Create Account"),
    "admin_account_created":        ("Privilege Escalation",    "T1136.001", "Local Account"),
    "sudo_abuse":                   ("Privilege Escalation",    "T1548",  "Abuse Elevation Control Mechanism"),

    # Persistence
    "new_service":                  ("Persistence",             "T1543",  "Create or Modify System Process"),
    "scheduled_task":               ("Persistence",             "T1053",  "Scheduled Task/Job"),
    "registry_run_key":             ("Persistence",             "T1547.001", "Registry Run Keys"),
    "startup_script":               ("Persistence",             "T1037",  "Boot or Logon Initialization Scripts"),

    # Execution
    "powershell_suspicious":        ("Execution",               "T1059.001", "PowerShell"),
    "suspicious_script":            ("Execution",               "T1059",  "Command and Scripting Interpreter"),
    "wmi_execution":                ("Execution",               "T1047",  "Windows Management Instrumentation"),

    # Exfiltration
    "data_exfiltration":            ("Exfiltration",            "T1041",  "Exfiltration Over C2 Channel"),
    "unusual_outbound":             ("Exfiltration",            "T1048",  "Exfiltration Over Alternative Protocol"),
    "large_upload":                 ("Exfiltration",            "T1030",  "Data Transfer Size Limits"),

    # Command and Control
    "c2_beacon":                    ("Command and Control",     "T1071",  "Application Layer Protocol"),
    "dns_tunneling":                ("Command and Control",     "T1071.004", "DNS"),
    "unusual_outbound_port":        ("Command and Control",     "T1571",  "Non-Standard Port"),

    # Impact
    "ransomware_indicator":         ("Impact",                  "T1486",  "Data Encrypted for Impact"),
    "data_destruction":             ("Impact",                  "T1485",  "Data Destruction"),

    # Collection
    "email_collection":             ("Collection",              "T1114",  "Email Collection"),

    # Reconnaissance
    "vulnerability_scan":           ("Reconnaissance",          "T1595",  "Active Scanning"),
    "osint":                        ("Reconnaissance",          "T1593",  "Search Open Websites/Domains"),

    # Default
    "impossible_travel":            ("Credential Access",       "T1078",  "Valid Accounts"),
    "off_hours_access":             ("Defense Evasion",         "T1078",  "Valid Accounts"),
    "attack_chain":                 ("Lateral Movement",        "T1021",  "Remote Services"),
}

# Tactic ordering for attack chain display (kill-chain order)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class AIMitreService:

    def map_detection(self, detection_type: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Returns (tactic, technique_id, technique_name) for a detection type.
        Falls back to a generic mapping if not found.
        """
        key = (detection_type or "").lower().replace(" ", "_").replace("-", "_")
        if key in DETECTION_TO_MITRE:
            return DETECTION_TO_MITRE[key]

        # Try partial match
        for k, v in DETECTION_TO_MITRE.items():
            if k in key or key in k:
                return v

        return (None, None, None)

    def tactic_order(self, tactic: str) -> int:
        """Return the kill-chain order index for sorting attack steps."""
        try:
            return TACTIC_ORDER.index(tactic)
        except ValueError:
            return 99

    def get_full_mapping(self) -> dict:
        return DETECTION_TO_MITRE

    def tactic_badge_colour(self, tactic: str) -> str:
        """Return a CSS colour class for the given tactic for UI display."""
        colours = {
            "Reconnaissance":       "#6c757d",
            "Initial Access":       "#dc3545",
            "Credential Access":    "#fd7e14",
            "Privilege Escalation": "#e83e8c",
            "Defense Evasion":      "#6f42c1",
            "Lateral Movement":     "#0dcaf0",
            "Discovery":            "#0d6efd",
            "Execution":            "#ffc107",
            "Persistence":          "#198754",
            "Collection":           "#20c997",
            "Command and Control":  "#0d6efd",
            "Exfiltration":         "#dc3545",
            "Impact":               "#343a40",
        }
        return colours.get(tactic, "#6c757d")
