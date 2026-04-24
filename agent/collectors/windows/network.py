from __future__ import annotations

import socket

import psutil


def collect_network() -> dict[str, list[str]]:
    ips = []
    macs = []

    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if getattr(addr, "family", None) in (socket.AF_INET, socket.AF_INET6):
                ips.append(addr.address)
            elif getattr(addr, "family", None) == psutil.AF_LINK:
                macs.append(addr.address)

    return {
        "ips": sorted(set(ips)),
        "macs": sorted(set(macs)),
    }
