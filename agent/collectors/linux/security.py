from __future__ import annotations

import shutil
import subprocess


def collect_security() -> dict:
    security = {
        "firewall": {},
        "disk_encryption": {},
    }

    if shutil.which("ufw"):
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=20)
        security["firewall"]["ufw"] = result.stdout.strip()

    if shutil.which("firewall-cmd"):
        result = subprocess.run(
            ["firewall-cmd", "--state"], capture_output=True, text=True, timeout=20
        )
        security["firewall"]["firewalld"] = result.stdout.strip()

    if shutil.which("lsblk"):
        result = subprocess.run(
            ["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        security["disk_encryption"]["lsblk"] = result.stdout.strip()

    return security
