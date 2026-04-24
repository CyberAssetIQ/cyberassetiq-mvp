from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read, require_admin
from db.session import get_db

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


class CreateRuleBody(BaseModel):
    name:             str
    trigger_type:     str
    threshold:        Optional[int] = None
    cooldown_minutes: int = 60
    channel:          str
    destination:      str
    is_active:        bool = True


class ToggleBody(BaseModel):
    is_active: bool


@router.get("/rules")
def list_rules(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.notification_service import list_rules
    return list_rules(db, auth.tenant_id)


@router.post("/rules")
def create_rule(
    body: CreateRuleBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.notification_service import create_rule
    return create_rule(db, auth.tenant_id, body.dict())


@router.patch("/rules/{rule_id}/toggle")
def toggle_rule(
    rule_id: int,
    body: ToggleBody,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.notification_service import toggle_rule
    return toggle_rule(db, auth.tenant_id, rule_id, body.is_active)


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.notification_service import delete_rule
    return delete_rule(db, auth.tenant_id, rule_id)


@router.post("/rules/{rule_id}/test")
def test_rule(
    rule_id: int,
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.notification_service import test_rule
    return test_rule(db, auth.tenant_id, rule_id)


@router.get("/logs")
def get_logs(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.notification_service import list_logs
    return list_logs(db, auth.tenant_id)


@router.post("/evaluate")
def trigger_evaluation(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from services.notification_service import evaluate_rules
    sent = evaluate_rules(db, auth.tenant_id)
    return {"notifications_sent": sent}


@router.get("/smtp-status")
def smtp_status(
    auth: AuthenticatedRequest = Depends(require_read),
):
    from services.notification_service import get_smtp_status
    return get_smtp_status()


@router.get("/triggers")
def get_triggers(
    auth: AuthenticatedRequest = Depends(require_read),
):
    from services.notification_service import TRIGGER_LABELS, TRIGGER_DEFAULTS
    return [
        {
            "value":     k,
            "label":     v,
            "default_threshold": TRIGGER_DEFAULTS[k]["threshold"],
            "desc":      TRIGGER_DEFAULTS[k]["desc"],
        }
        for k, v in TRIGGER_LABELS.items()
    ]
