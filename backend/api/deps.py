from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from db.session import get_db
from models.auth import TenantAPIKey

# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Return (plaintext, hash). Plaintext shown once; only hash is stored."""
    raw = "ciq_" + secrets.token_urlsafe(32)
    return raw, _hash_key(raw)


def ensure_bootstrap_key(db: Session, tenant_id: str) -> str | None:
    """
    Create a bootstrap admin key for development if none exist for the tenant.
    Returns the plaintext key (only on first creation) or None if already set.
    """
    existing = (
        db.query(TenantAPIKey)
        .filter(TenantAPIKey.tenant_id == tenant_id, TenantAPIKey.is_active.is_(True))
        .first()
    )
    if existing:
        return None

    env_key = os.getenv("CYBERASSETIQ_BOOTSTRAP_KEY")
    if env_key:
        plaintext = env_key
        key_hash = _hash_key(env_key)
    else:
        plaintext, key_hash = generate_api_key()

    db.add(TenantAPIKey(
        tenant_id=tenant_id,
        key_hash=key_hash,
        label="Bootstrap admin key",
        role="admin",
        is_active=True,
    ))
    db.commit()
    return plaintext


# ---------------------------------------------------------------------------
# Auth request object
# ---------------------------------------------------------------------------

class AuthenticatedRequest:
    def __init__(self, tenant_id: str, agent_id: str | None, role: str, key_id: int | None = None):
        self.tenant_id = tenant_id
        self.agent_id  = agent_id
        self.role      = role
        self.key_id    = key_id  # DB id of the API key used — for audit trail

    def require_role(self, *roles: str) -> None:
        if self.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{self.role}' is not permitted for this operation.",
            )


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------

def _resolve_auth(
    x_api_key:   str | None,
    x_tenant_id: str | None,
    x_agent_id:  str | None,
    db: Session,
) -> AuthenticatedRequest:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Api-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Tenant-Id header.",
        )

    # Auto-bootstrap for development tenants on first hit
    ensure_bootstrap_key(db, x_tenant_id)

    key_hash = _hash_key(x_api_key)
    record = (
        db.query(TenantAPIKey)
        .filter(
            TenantAPIKey.tenant_id == x_tenant_id,
            TenantAPIKey.key_hash  == key_hash,
            TenantAPIKey.is_active.is_(True),
        )
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key.",
        )

    # Touch last_used (best-effort)
    try:
        record.last_used_epoch = int(time.time())
        db.commit()
    except Exception:
        db.rollback()

    return AuthenticatedRequest(
        tenant_id=x_tenant_id,
        agent_id=x_agent_id,
        role=record.role,
        key_id=record.id,
    )


# ---------------------------------------------------------------------------
# FastAPI dependency functions
# ---------------------------------------------------------------------------

def require_auth(
    x_api_key:   Annotated[str | None, Header()] = None,
    x_tenant_id: Annotated[str | None, Header()] = None,
    x_agent_id:  Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> AuthenticatedRequest:
    """Base auth — any valid API key accepted."""
    return _resolve_auth(x_api_key, x_tenant_id, x_agent_id, db)


def require_agent(
    auth: AuthenticatedRequest = Depends(require_auth),
) -> AuthenticatedRequest:
    """
    Agent-only endpoints — accepts role 'agent' or 'admin'.

    Industry standard separation (matches CrowdStrike / SentinelOne / Qualys):
      - Agents use dedicated agent keys (role='agent')
      - Agent keys can only POST telemetry and scan results
      - Agent keys CANNOT read assets, manage keys, or access admin functions
      - If an agent is compromised, blast radius is limited to telemetry endpoints only
      - Admin keys can also call agent endpoints (for testing/debugging)
    """
    auth.require_role("agent", "admin")
    return auth


def require_read(
    auth: AuthenticatedRequest = Depends(require_auth),
) -> AuthenticatedRequest:
    """
    Read-or-above — accepts role 'read' or 'admin'.
    Used for GET endpoints returning assets, compliance, vulnerabilities etc.
    Agents cannot call read endpoints — they can only POST telemetry.
    """
    auth.require_role("read", "admin")
    return auth


def require_admin(
    auth: AuthenticatedRequest = Depends(require_auth),
) -> AuthenticatedRequest:
    """
    Admin-only — accepts role 'admin' only.
    Used for destructive operations: key management, scan triggers, config changes.
    """
    auth.require_role("admin")
    return auth


# ---------------------------------------------------------------------------
# Role hierarchy summary
# ---------------------------------------------------------------------------
#
#  Role     | Agent endpoints | Read endpoints | Admin endpoints
#  ---------|-----------------|----------------|----------------
#  agent    | YES             | NO             | NO
#  read     | NO              | YES            | NO
#  admin    | YES             | YES            | YES
#
#  This matches enterprise scanner architecture:
#  - Qualys Cloud Agent uses a separate agent activation key
#  - CrowdStrike Falcon uses a separate sensor installation token
#  - Tenable Nessus Agent uses a separate linking key
#  - All separate from the API keys used by human operators
#
# ---------------------------------------------------------------------------
