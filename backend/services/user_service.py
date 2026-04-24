"""services/user_service.py

Business logic for named user management.

Dependencies added to requirements.txt:
  pyjwt>=2.8.0
  passlib[bcrypt]>=1.7.4

JWT_SECRET must be set in .env (min 32 chars).
Falls back to a dev-only secret with a warning if not set.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from models.user import TenantUser, UserInvitation

logger = logging.getLogger("cyberassetiq.users")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))
INVITATION_EXPIRE_HOURS = 72

if not JWT_SECRET:
    import secrets as _s
    JWT_SECRET = _s.token_hex(32)
    logger.warning(
        "JWT_SECRET not set in .env — using a generated secret. "
        "All tokens will be invalidated on restart. "
        "Set JWT_SECRET in backend/.env for production."
    )

# ---------------------------------------------------------------------------
# Password hashing (bcrypt via passlib)
# ---------------------------------------------------------------------------

def _hash_password(plaintext: str) -> str:
    """Hash a plaintext password using bcrypt."""
    try:
        from passlib.context import CryptContext
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return ctx.hash(plaintext)
    except ImportError:
        # Fallback: SHA-256 (weak — only used if passlib not installed)
        logger.warning("passlib not installed — using SHA-256 fallback. Install passlib[bcrypt].")
        return hashlib.sha256(plaintext.encode()).hexdigest()


def _verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a plaintext password against its hash."""
    try:
        from passlib.context import CryptContext
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return ctx.verify(plaintext, hashed)
    except ImportError:
        return hashlib.sha256(plaintext.encode()).hexdigest() == hashed


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def _create_token(payload: dict, expire_hours: int = JWT_EXPIRE_HOURS) -> str:
    """Create a signed JWT."""
    try:
        import jwt
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PyJWT not installed. Run: pip install pyjwt>=2.8.0",
        )
    now = datetime.now(timezone.utc)
    data = {
        **payload,
        "iat": now,
        "exp": now + timedelta(hours=expire_hours),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT. Returns payload dict.
    Raises HTTP 401 on invalid/expired token.
    """
    try:
        import jwt
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        # Check token blacklist (logout support)
        jti = payload.get("jti")
        if jti:
            from db.session import SessionLocal
            from models.auth import RevokedToken
            _db = SessionLocal()
            try:
                revoked = _db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
                if revoked:
                    raise Exception("Token has been revoked (logged out).")
            finally:
                _db.close()
        return payload
    except ImportError:
        raise HTTPException(status_code=500, detail="PyJWT not installed.")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

def get_user_by_email(db: Session, tenant_id: str, email: str) -> TenantUser | None:
    return (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.email == email.lower().strip(),
            TenantUser.is_active.is_(True),
        )
        .first()
    )


def get_user_by_id(db: Session, tenant_id: str, user_id: int) -> TenantUser | None:
    return (
        db.query(TenantUser)
        .filter(TenantUser.id == user_id, TenantUser.tenant_id == tenant_id)
        .first()
    )


def list_users(db: Session, tenant_id: str) -> list[dict]:
    users = (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == tenant_id)
        .order_by(TenantUser.created_at.asc())
        .all()
    )
    return [_user_to_dict(u) for u in users]


def _user_to_dict(u: TenantUser) -> dict:
    return {
        "id":               u.id,
        "email":            u.email,
        "full_name":        u.full_name,
        "role":             u.role,
        "is_active":        u.is_active,
        "email_verified":   u.email_verified,
        "job_title":        u.job_title,
        "last_login_at":    u.last_login_at.isoformat() if u.last_login_at else None,
        "login_count":      u.login_count,
        "created_at":       u.created_at.isoformat() if u.created_at else None,
        "invited_by_user_id": u.invited_by_user_id,
    }


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def login(
    db: Session,
    tenant_id: str,
    email: str,
    password: str,
    ip: str | None = None,
) -> dict[str, Any]:
    """
    Authenticate a user with email + password.
    Returns access_token, token_type, expires_in, and user profile.
    """
    user = get_user_by_email(db, tenant_id, email)

    if not user or not _verify_password(password, user.password_hash):
        # Same error for both missing user and wrong password (security: no enumeration)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator.",
        )

    # Update login tracking
    now = datetime.now(timezone.utc)
    user.last_login_at = now
    user.login_count += 1
    if ip:
        user.last_ip = ip
    db.commit()

    token = _create_token({
        "sub":       str(user.id),
        "tenant_id": tenant_id,
        "email":     user.email,
        "role":      user.role,
        "type":      "user",
    })

    logger.info("User %s logged in to tenant %s", user.email, tenant_id)

    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   JWT_EXPIRE_HOURS * 3600,
        "user":         _user_to_dict(user),
    }


# ---------------------------------------------------------------------------
# Invitation flow
# ---------------------------------------------------------------------------

def create_invitation(
    db: Session,
    tenant_id: str,
    email: str,
    role: str,
    invited_by_user_id: int | None,
    invited_by_name: str,
    message: str = "",
) -> dict[str, Any]:
    """
    Create an invitation for a new user.
    Returns the plaintext token (to embed in the email link).
    """
    email = email.lower().strip()

    # Check not already a user
    existing = (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == tenant_id, TenantUser.email == email)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"A user with email '{email}' already exists in this tenant.",
        )

    # Invalidate any existing pending invitation for this email
    db.query(UserInvitation).filter(
        UserInvitation.tenant_id == tenant_id,
        UserInvitation.email == email,
        UserInvitation.is_used.is_(False),
    ).delete(synchronize_session=False)

    if role not in ("admin", "read"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'read'.")

    plaintext = "inv_" + secrets.token_urlsafe(32)
    token_hash = _token_hash(plaintext)
    now = datetime.now(timezone.utc)

    inv = UserInvitation(
        tenant_id=tenant_id,
        email=email,
        role=role,
        token_hash=token_hash,
        invited_by_user_id=invited_by_user_id,
        invited_by_name=invited_by_name,
        created_at=now,
        expires_at=now + timedelta(hours=INVITATION_EXPIRE_HOURS),
        message=message,
        is_used=False,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)

    logger.info("Invitation created for %s in tenant %s", email, tenant_id)

    return {
        "invitation_id":  inv.id,
        "email":          email,
        "role":           role,
        "expires_at":     inv.expires_at.isoformat(),
        "token":          plaintext,   # send this in the email link
        "accept_url":     f"/api/users/accept-invitation?token={plaintext}",
        "note":           "Token shown once — embed in invitation email. Not stored in plaintext.",
    }


def accept_invitation(
    db: Session,
    token: str,
    full_name: str,
    password: str,
) -> dict[str, Any]:
    """
    Accept an invitation by setting a password and creating the user account.
    Returns login credentials immediately on success.
    """
    token_hash = _token_hash(token)
    now = datetime.now(timezone.utc)

    inv = (
        db.query(UserInvitation)
        .filter(
            UserInvitation.token_hash == token_hash,
            UserInvitation.is_used.is_(False),
        )
        .first()
    )

    if not inv:
        raise HTTPException(status_code=400, detail="Invalid or already used invitation token.")

    if inv.expires_at.replace(tzinfo=timezone.utc) < now:
        raise HTTPException(
            status_code=400,
            detail=f"Invitation has expired. Ask your administrator to send a new invitation.",
        )

    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters.")

    # Create user
    user = TenantUser(
        tenant_id=inv.tenant_id,
        email=inv.email,
        full_name=full_name.strip(),
        password_hash=_hash_password(password),
        role=inv.role,
        is_active=True,
        email_verified=True,   # invitation = implicit email verification
        invited_by_user_id=inv.invited_by_user_id,
    )
    db.add(user)

    # Mark invitation used
    inv.is_used = True
    inv.accepted_at = now
    db.commit()
    db.refresh(user)

    logger.info("User %s accepted invitation for tenant %s", inv.email, inv.tenant_id)

    # Auto-login
    token_out = _create_token({
        "sub":       str(user.id),
        "tenant_id": inv.tenant_id,
        "email":     user.email,
        "role":      user.role,
        "type":      "user",
    })

    return {
        "message":      f"Account created successfully. Welcome, {full_name}.",
        "access_token": token_out,
        "token_type":   "bearer",
        "expires_in":   JWT_EXPIRE_HOURS * 3600,
        "user":         _user_to_dict(user),
    }


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def create_first_admin(
    db: Session,
    tenant_id: str,
    email: str,
    full_name: str,
    password: str,
) -> dict[str, Any]:
    """
    Bootstrap the first admin user for a tenant.
    Only allowed if tenant has zero users.
    """
    existing_count = (
        db.query(func.count(TenantUser.id))
        .filter(TenantUser.tenant_id == tenant_id)
        .scalar()
    )
    if existing_count > 0:
        raise HTTPException(
            status_code=400,
            detail="Tenant already has users. Use the invite flow to add more.",
        )

    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters.")

    user = TenantUser(
        tenant_id=tenant_id,
        email=email.lower().strip(),
        full_name=full_name.strip(),
        password_hash=_hash_password(password),
        role="admin",
        is_active=True,
        email_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("First admin user created: %s for tenant %s", email, tenant_id)
    return _user_to_dict(user)


def update_user_role(
    db: Session,
    tenant_id: str,
    user_id: int,
    new_role: str,
    acting_user_id: int | None,
) -> dict:
    if new_role not in ("admin", "read"):
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'read'.")
    if acting_user_id and acting_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot change your own role.")

    user = get_user_by_id(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.role = new_role
    db.commit()
    return _user_to_dict(user)


def deactivate_user(
    db: Session,
    tenant_id: str,
    user_id: int,
    acting_user_id: int | None,
) -> dict:
    if acting_user_id and acting_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account.")

    user = get_user_by_id(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Prevent deactivating the last admin
    admin_count = (
        db.query(func.count(TenantUser.id))
        .filter(
            TenantUser.tenant_id == tenant_id,
            TenantUser.role == "admin",
            TenantUser.is_active.is_(True),
        )
        .scalar()
    )
    if user.role == "admin" and admin_count <= 1:
        raise HTTPException(
            status_code=400,
            detail="Cannot deactivate the last admin. Promote another user first.",
        )

    user.is_active = False
    db.commit()
    return {"message": f"User {user.email} deactivated.", "user": _user_to_dict(user)}


def reactivate_user(db: Session, tenant_id: str, user_id: int) -> dict:
    user = get_user_by_id(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_active = True
    db.commit()
    return {"message": f"User {user.email} reactivated.", "user": _user_to_dict(user)}


def update_own_profile(
    db: Session,
    tenant_id: str,
    user_id: int,
    full_name: str | None,
    job_title: str | None,
    phone: str | None,
    current_password: str | None,
    new_password: str | None,
) -> dict:
    user = get_user_by_id(db, tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if full_name is not None:
        user.full_name = full_name.strip()
    if job_title is not None:
        user.job_title = job_title
    if phone is not None:
        user.phone = phone

    if new_password:
        if not current_password:
            raise HTTPException(status_code=400, detail="Current password required to set a new one.")
        if not _verify_password(current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        if len(new_password) < 10:
            raise HTTPException(status_code=400, detail="New password must be at least 10 characters.")
        user.password_hash = _hash_password(new_password)

    db.commit()
    return _user_to_dict(user)


def list_invitations(db: Session, tenant_id: str) -> list[dict]:
    invs = (
        db.query(UserInvitation)
        .filter(UserInvitation.tenant_id == tenant_id)
        .order_by(UserInvitation.created_at.desc())
        .limit(100)
        .all()
    )
    now = datetime.now(timezone.utc)
    return [
        {
            "id":              i.id,
            "email":           i.email,
            "role":            i.role,
            "invited_by":      i.invited_by_name,
            "created_at":      i.created_at.isoformat(),
            "expires_at":      i.expires_at.isoformat(),
            "is_used":         i.is_used,
            "is_expired":      i.expires_at.replace(tzinfo=timezone.utc) < now and not i.is_used,
            "accepted_at":     i.accepted_at.isoformat() if i.accepted_at else None,
            "status": (
                "accepted" if i.is_used else
                "expired" if i.expires_at.replace(tzinfo=timezone.utc) < now else
                "pending"
            ),
        }
        for i in invs
    ]


def cancel_invitation(db: Session, tenant_id: str, invitation_id: int) -> dict:
    inv = (
        db.query(UserInvitation)
        .filter(UserInvitation.id == invitation_id, UserInvitation.tenant_id == tenant_id)
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    if inv.is_used:
        raise HTTPException(status_code=400, detail="Invitation already accepted.")
    db.delete(inv)
    db.commit()
    return {"message": f"Invitation for {inv.email} cancelled."}
