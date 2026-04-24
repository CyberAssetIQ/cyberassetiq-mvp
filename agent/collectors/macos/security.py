from __future__ import annotations

import subprocess


def collect_security() -> dict:
    result = {"filevault": None, "firewall": None}

    try:
        fv = subprocess.run(
            ["fdesetup", "status"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        result["filevault"] = fv.stdout.strip()
    except Exception:
        pass

    try:
        fw = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        result["firewall"] = fw.stdout.strip()
    except Exception:
        pass

    return result
