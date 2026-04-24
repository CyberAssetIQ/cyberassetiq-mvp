from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def _collect_via_system_profiler() -> list[dict[str, Any]]:
    """
    Use system_profiler SPApplicationsDataType to get installed apps with versions.
    This is the most accurate source on macOS — covers App Store and direct installs.
    """
    try:
        result = subprocess.run(
            ["system_profiler", "SPApplicationsDataType", "-json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        apps = data.get("SPApplicationsDataType", [])
        items = []
        for app in apps:
            name = app.get("_name") or app.get("kMDItemDisplayName", "")
            version = app.get("version") or app.get("kMDItemVersion")
            if name:
                items.append({"name": name, "version": version, "publisher": None, "install_date": None})
        return items
    except Exception:
        return []


def _collect_via_brew() -> list[dict[str, Any]]:
    """Collect Homebrew packages if brew is installed."""
    try:
        result = subprocess.run(
            ["brew", "list", "--versions"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return []
        items = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                items.append({
                    "name": parts[0],
                    "version": parts[1],
                    "publisher": "homebrew",
                    "install_date": None,
                })
            elif len(parts) == 1:
                items.append({"name": parts[0], "version": None, "publisher": "homebrew", "install_date": None})
        return items
    except Exception:
        return []


def _collect_app_bundles_fallback() -> list[dict[str, Any]]:
    """
    Fallback: walk /Applications and ~/Applications for .app bundles.
    Reads version from Info.plist when available.
    """
    import plistlib

    items = []
    search_dirs = ["/Applications", os.path.expanduser("~/Applications")]

    for apps_dir in search_dirs:
        if not os.path.exists(apps_dir):
            continue
        for entry in os.listdir(apps_dir):
            if not entry.endswith(".app"):
                continue
            name = entry.replace(".app", "")
            version = None
            plist_path = os.path.join(apps_dir, entry, "Contents", "Info.plist")
            if os.path.exists(plist_path):
                try:
                    with open(plist_path, "rb") as f:
                        plist = plistlib.load(f)
                    version = (
                        plist.get("CFBundleShortVersionString")
                        or plist.get("CFBundleVersion")
                    )
                except Exception:
                    pass
            items.append({"name": name, "version": version, "publisher": None, "install_date": None})

    return items


def collect_software() -> list[dict[str, Any]]:
    """
    Collect installed software on macOS.
    Tries system_profiler first (most complete), then adds Homebrew packages,
    falls back to .app bundle enumeration if system_profiler is unavailable.
    """
    items = _collect_via_system_profiler()

    if not items:
        items = _collect_app_bundles_fallback()

    # Always append Homebrew packages (additive — brew packages not in SPApplications)
    brew_items = _collect_via_brew()
    # Deduplicate by name (case-insensitive)
    existing_names = {i["name"].lower() for i in items}
    for b in brew_items:
        if b["name"].lower() not in existing_names:
            items.append(b)

    return items
