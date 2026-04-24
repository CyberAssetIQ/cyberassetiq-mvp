from __future__ import annotations

import platform
import socket
import time
from typing import Any

import psutil


def build_health_snapshot(agent_id: str | None) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "boot_time": psutil.boot_time(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "timestamp": int(time.time()),
    }
