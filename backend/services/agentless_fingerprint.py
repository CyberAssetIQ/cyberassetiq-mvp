from __future__ import annotations

import re
from typing import List, Dict

COMMON_PORT_MAP = {
    22: "OpenSSH",
    80: "Apache HTTP Server",
    443: "nginx",
    445: "Microsoft Windows",
    3389: "Microsoft Windows",
    139: "Samba",
    21: "vsftpd",
    25: "Postfix",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "Apache Tomcat",
    8443: "nginx",
}

OS_HINTS = {
    "windows": "Microsoft Windows",
    "linux": "Linux Kernel",
    "printer": "HP Printer Firmware",
    "router": "Cisco IOS",
    "switch": "Cisco IOS",
    "android": "Android",
    "mac": "macOS",
}

def infer_software_from_ports(open_ports: List[int]) -> List[Dict]:
    inferred = []

    for port in open_ports:
        if port in COMMON_PORT_MAP:
            inferred.append({
                "name": COMMON_PORT_MAP[port],
                "version": None,
                "confidence": 0.6
            })

    return inferred


def infer_software_from_os(os_name: str | None):
    if not os_name:
        return []

    os_lower = os_name.lower()

    for key, value in OS_HINTS.items():
        if key in os_lower:
            return [{
                "name": value,
                "version": None,
                "confidence": 0.8
            }]

    return []


def infer_from_banner(banner: str | None):
    if not banner:
        return []

    banner = banner.lower()
    found = []

    # Version-aware detection (preferred)
    version_patterns = [
        (r"nginx[/ ]([\d\.]+)", "nginx"),
        (r"apache[/ ]([\d\.]+)", "Apache HTTP Server"),
        (r"openssh[_/ ]([\d\.]+)", "OpenSSH"),
        (r"samba[\s/]([\d\.]+)", "Samba"),
        (r"microsoft-iis[/ ]([\d\.]+)", "Microsoft IIS"),
    ]

    for regex, name in version_patterns:
        m = re.search(regex, banner)
        if m:
            found.append({
                "name": name,
                "version": m.group(1),
                "confidence": 0.95
            })

    # Fallback detection (no version)
    fallback_patterns = [
        ("nginx", "nginx"),
        ("apache", "Apache HTTP Server"),
        ("openssh", "OpenSSH"),
        ("microsoft-iis", "Microsoft IIS"),
        ("jetdirect", "HP Printer Firmware"),
        ("cisco", "Cisco IOS"),
        ("mikrotik", "Mikrotik RouterOS"),
    ]

    for pattern, name in fallback_patterns:
        if pattern in banner and not any(f["name"] == name for f in found):
            found.append({
                "name": name,
                "version": None,
                "confidence": 0.75
            })

    return found


def fingerprint_asset(asset: dict):
    software = []

    software += infer_software_from_ports(asset.get("open_ports", []))
    software += infer_software_from_os(asset.get("os"))
    software += infer_from_banner(asset.get("banner"))

    return software