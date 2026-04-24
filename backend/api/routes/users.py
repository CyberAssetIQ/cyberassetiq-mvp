"""api/routes/users.py

Named user management endpoints.

Routes:
  POST /api/users/register          — Create first admin (bootstrap — zero users only)
  POST /api/users/login             — Authenticate with email + password → JWT
  GET  /api/users/me                — Get current user profile (JWT auth)
  PUT  /api/users/me                — Update own profile / change password
  GET  /api/users                   — List all users in tenant (admin only)
  POST /api/users/invite            — Invite a new user (admin only)
  GET  /api/users/invitations       — List invitations (admin only)
  DELETE /api/users/invitations/{id}— Cancel invitation (admin only)
  POST /api/users/accept-invitation — Accept invite, set password → JWT
  PATCH /api/users/{id}/role        — Change user role (admin only)
  PATCH /api/users/{id}/deactivate  — Deactivate user (admin only)
  PATCH /api/users/{id}/reactivate  — Reactivate user (admin only)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from typing import Annotated

from api.deps import AuthenticatedRequest, require_admin, require_read
from db.session import get_db
from services.user_service import (
    login,
    create_first_admin,
    create_invitation,
    accept_invitation,
    list_users,
    list_invitations,
    cancel_invitation,
    update_user_role,
    update_own_profile,
    deactivate_user,
    reactivate_user,
    decode_token,
    get_user_by_id,
    _user_to_dict,
)

router = APIRouter(prefix="/api/users", tags=["users"])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_request_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _resolve_user_from_jwt(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> dict:
    """
    Resolve a user from a Bearer JWT token.
    Used for /me and other user-centric endpoints.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[7:]
    payload = decode_token(token)

    if payload.get("type") != "user":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not a user token.",
        )
    return payload


# ── Schemas ──────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    full_name: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str
    tenant_id: str


class InviteRequest(BaseModel):
    email: str
    role: str = "read"
    message: str = ""


class AcceptInvitationRequest(BaseModel):
    token: str
    full_name: str
    password: str


class UpdateProfileRequest(BaseModel):
    full_name: str | None = None
    job_title: str | None = None
    phone: str | None = None
    current_password: str | None = None
    new_password: str | None = None


class ChangeRoleRequest(BaseModel):
    role: str


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
def register_first_admin(
    payload: RegisterRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Bootstrap the first named admin user for a tenant.
    Only succeeds if the tenant has zero named users.
    Requires an existing API key (admin role) for authentication.
    """
    user = create_first_admin(
        db,
        tenant_id=auth.tenant_id,
        email=payload.email,
        full_name=payload.full_name,
        password=payload.password,
    )
    return {
        "message": "First admin user created successfully.",
        "user": user,
        "next_step": "Share the platform URL with your team and use POST /api/users/invite to add more users.",
    }


@router.post("/login")
def user_login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    """
    Authenticate with email + password. Returns a JWT access token.
    The JWT can be used as: Authorization: Bearer <token>
    tenant_id must be provided (users are tenant-scoped).
    """
    return login(
        db,
        tenant_id=payload.tenant_id,
        email=payload.email,
        password=payload.password,
        ip=_get_request_ip(request),
    )


@router.get("/me")
def get_my_profile(
    jwt_payload: dict = Depends(_resolve_user_from_jwt),
    db: Session = Depends(get_db),
) -> dict:
    """
    Get the profile of the currently authenticated user.
    Requires: Authorization: Bearer <token>
    """
    user = get_user_by_id(db, jwt_payload["tenant_id"], int(jwt_payload["sub"]))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return _user_to_dict(user)


@router.put("/me")
def update_my_profile(
    payload: UpdateProfileRequest,
    jwt_payload: dict = Depends(_resolve_user_from_jwt),
    db: Session = Depends(get_db),
) -> dict:
    """
    Update own profile or change password.
    Requires: Authorization: Bearer <token>
    To change password, provide both current_password and new_password.
    """
    return update_own_profile(
        db,
        tenant_id=jwt_payload["tenant_id"],
        user_id=int(jwt_payload["sub"]),
        full_name=payload.full_name,
        job_title=payload.job_title,
        phone=payload.phone,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )


@router.get("")
def get_all_users(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """List all named users in this tenant. Admin only."""
    users = list_users(db, auth.tenant_id)
    return {
        "tenant_id": auth.tenant_id,
        "total": len(users),
        "users": users,
    }


@router.post("/invite", status_code=201)
def invite_user(
    payload: InviteRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """
    Send an invitation to a new user. Admin only.
    Returns the invitation token — embed this in an email link:
      https://yourdomain.com/accept-invitation?token=<token>
    The token expires in 72 hours and is single-use.
    """
    # Try to get acting user's name from JWT if they logged in via email
    invited_by_name = f"Admin (API key: {auth.tenant_id})"

    result = create_invitation(
        db,
        tenant_id=auth.tenant_id,
        email=payload.email,
        role=payload.role,
        invited_by_user_id=None,
        invited_by_name=invited_by_name,
        message=payload.message,
    )
    return result


@router.get("/invitations")
def get_invitations(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """List all invitations for this tenant. Admin only."""
    invs = list_invitations(db, auth.tenant_id)
    return {
        "tenant_id": auth.tenant_id,
        "total": len(invs),
        "pending": sum(1 for i in invs if i["status"] == "pending"),
        "invitations": invs,
    }


@router.delete("/invitations/{invitation_id}")
def delete_invitation(
    invitation_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Cancel a pending invitation. Admin only."""
    return cancel_invitation(db, auth.tenant_id, invitation_id)


@router.post("/accept-invitation")
def accept_invite(
    payload: AcceptInvitationRequest,
    db: Session = Depends(get_db),
) -> dict:
    """
    Accept an invitation and create your user account.
    No authentication required — the invitation token IS the auth.
    Sets your full name and password, then logs you in immediately.
    """
    return accept_invitation(
        db,
        token=payload.token,
        full_name=payload.full_name,
        password=payload.password,
    )


@router.patch("/{user_id}/role")
def change_role(
    user_id: int,
    payload: ChangeRoleRequest,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Change a user's role. Admin only. Cannot change your own role."""
    return update_user_role(
        db,
        tenant_id=auth.tenant_id,
        user_id=user_id,
        new_role=payload.role,
        acting_user_id=None,
    )


@router.patch("/{user_id}/deactivate")
def deactivate(
    user_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Deactivate a user account. Admin only. Cannot deactivate last admin."""
    return deactivate_user(
        db,
        tenant_id=auth.tenant_id,
        user_id=user_id,
        acting_user_id=None,
    )


@router.patch("/{user_id}/reactivate")
def reactivate(
    user_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Reactivate a deactivated user account. Admin only."""
    return reactivate_user(db, auth.tenant_id, user_id)
