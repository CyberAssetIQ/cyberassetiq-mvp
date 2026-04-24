from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthenticatedRequest, require_read
from db.session import get_db

router = APIRouter(prefix="/api/training", tags=["training"])


class QuizSubmitBody(BaseModel):
    answers: list[int]
    user_label: str = "default"


@router.get("/modules")
def list_modules(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.training_service import list_modules
    return list_modules(db, auth.tenant_id)


@router.get("/modules/{module_id}")
def get_module(
    module_id: int,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.training_service import get_module
    m = get_module(db, module_id, auth.tenant_id)
    if not m:
        raise HTTPException(status_code=404, detail="Module not found")
    return m


@router.post("/modules/{module_id}/attempt")
def submit_quiz(
    module_id: int,
    body: QuizSubmitBody,
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.training_service import submit_quiz
    return submit_quiz(db, module_id, auth.tenant_id, body.answers, body.user_label)


@router.get("/progress")
def get_progress(
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
):
    from services.training_service import get_progress_summary
    return get_progress_summary(db, auth.tenant_id)
