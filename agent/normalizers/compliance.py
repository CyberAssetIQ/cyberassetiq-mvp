from __future__ import annotations

import time
from typing import Any


def normalize_security_posture(
    tenant_id: str,
    agent_id: str,
    security: dict[str, Any],
    identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the security_posture payload for backend ingestion.
    Embeds a subset of identity data (local_admins, os_family) so that the
    CE A2 user-access-control evaluator can assess admin account membership
    without needing a separate identity telemetry event.
    """
    posture: dict[str, Any] = dict(security)

    # Embed identity subset for compliance evaluation (A2 user access control)
    if identity:
        posture["identity"] = {
            "local_admins": identity.get("local_admins", []),
            "os_family": identity.get("os_family"),
        }

    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "timestamp": int(time.time()),
        "security_posture": posture,
    }
