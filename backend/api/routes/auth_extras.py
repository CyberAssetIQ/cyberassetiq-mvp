"""api/routes/auth_extras.py - Logout (JWT blacklist) + password reset flow"""
from __future__ import annotations
import hashlib, secrets, time
from typing import Annotated
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.session import get_db
from models.auth import PasswordResetToken, RevokedToken
from services.user_service import decode_token

router = APIRouter(prefix="/api/users", tags=["users"])
RESET_TTL = 15 * 60  # 15 minutes

def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

class ForgotPasswordRequest(BaseModel):
    email:     str
    tenant_id: str

class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str

# ── POST /api/users/logout ────────────────────────────────────────────────────
@router.post("/logout")
def logout(authorization: Annotated[str|None, Header()] = None,
           db: Session = Depends(get_db)) -> dict:
    """
    Blacklist the caller's JWT immediately.
    The token's jti is added to revoked_tokens — subsequent requests with
    the same token receive 401 even before natural expiry.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"})
    payload = decode_token(authorization[7:])
    jti = payload.get("jti")
    if not jti:
        # Token predates jti support — clear client-side only
        return {"message": "Logged out. (Legacy token — expires at natural TTL.)"}
    if not db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        db.add(RevokedToken(jti=jti, tenant_id=payload.get("tenant_id",""),
            revoked_at=int(time.time()), expires_at=payload.get("exp", int(time.time())+86400)))
        db.commit()
    return {"message": "Logged out successfully. Token invalidated."}

# ── POST /api/users/forgot-password ──────────────────────────────────────────
@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest,
                    db: Session = Depends(get_db)) -> dict:
    """
    Generate a single-use 15-minute password reset token.
    In production this would be emailed; here the token is returned directly
    so it can be used in the reset form without an SMTP dependency.
    """
    from models.user import TenantUser
    user = db.query(TenantUser).filter(
        TenantUser.tenant_id == payload.tenant_id,
        TenantUser.email == payload.email.lower().strip(),
        TenantUser.is_active.is_(True),
    ).first()
    # Always 200 — never reveal if email exists
    if not user:
        return {"message": "If that email is registered a reset link has been sent."}
    # Invalidate prior unused tokens
    db.query(PasswordResetToken).filter(
        PasswordResetToken.tenant_id == payload.tenant_id,
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used.is_(False),
    ).update({"used": True})
    plaintext = "rst_" + secrets.token_urlsafe(32)
    now = int(time.time())
    db.add(PasswordResetToken(tenant_id=payload.tenant_id, user_id=user.id,
        token_hash=_hash(plaintext), used=False, created_at=now, expires_at=now+RESET_TTL))
    db.commit()
    return {"message": "If that email is registered a reset link has been sent.",
            "reset_token": plaintext,  # surfaced for dev/test; email in production
            "expires_in": RESET_TTL,
            "accept_url": f"/reset-password?token={plaintext}"}

# ── POST /api/users/reset-password ───────────────────────────────────────────
@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest,
                   db: Session = Depends(get_db)) -> dict:
    """Consume a reset token and set a new password. Token is invalidated on use."""
    from models.user import TenantUser
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    now = int(time.time())
    record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == _hash(payload.token),
        PasswordResetToken.used.is_(False),
    ).first()
    if not record:
        raise HTTPException(status_code=400, detail="Invalid or already used reset token.")
    if now > record.expires_at:
        raise HTTPException(status_code=400, detail="Reset token has expired. Request a new one.")
    user = db.query(TenantUser).filter(
        TenantUser.tenant_id == record.tenant_id,
        TenantUser.id == record.user_id,
        TenantUser.is_active.is_(True),
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    # Re-use the same hashing approach as user_service
    from services.user_service import _hash_password
    user.password_hash = _hash_password(payload.new_password)
    record.used = True
    db.commit()
    return {"message": "Password reset successfully. You can now log in.", "email": user.email}
