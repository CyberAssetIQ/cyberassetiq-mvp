from __future__ import annotations

import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 60) -> str:
    """Run a command and return stdout, or empty string on any error."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Software collector command failed %s: %s", cmd[0], exc)
        return ""


def collect_software() -> list[dict]:
    if shutil.which("dpkg-query"):
        output = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
        items = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[0].strip():
                items.append({"name": parts[0].strip(), "version": parts[1].strip() or None,
                              "publisher": None, "install_date": None})
        return items

    if shutil.which("rpm"):
        output = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
        items = []
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[0].strip():
                items.append({"name": parts[0].strip(), "version": parts[1].strip() or None,
                              "publisher": None, "install_date": None})
        return items

    return []
