from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.sql import func

from models.mixins import Base


class TrainingModule(Base):
    __tablename__ = "training_modules"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id          = Column(String, nullable=True, index=True)   # NULL = global seed module
    title              = Column(String, nullable=False)
    category           = Column(String, nullable=False)
    description        = Column(String, nullable=False)
    content_html       = Column(String, nullable=False)
    difficulty         = Column(String, default="Beginner")          # Beginner / Intermediate / Advanced
    estimated_minutes  = Column(Integer, default=15)
    pass_mark          = Column(Integer, default=80)                 # % required to pass
    questions_json     = Column(JSON, default=list)                  # [{question, options, correct_index, explanation}]
    is_active          = Column(Boolean, default=True)
    created_at         = Column(DateTime(timezone=True), server_default=func.now())


class TrainingProgress(Base):
    __tablename__ = "training_progress"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id          = Column(String, nullable=False, index=True)
    module_id          = Column(Integer, ForeignKey("training_modules.id"), nullable=False)
    user_label         = Column(String, default="default")
    status             = Column(String, default="not_started")       # not_started / in_progress / completed
    best_score         = Column(Integer, default=0)
    attempts           = Column(Integer, default=0)
    last_attempted_at  = Column(DateTime(timezone=True), nullable=True)
    completed_at       = Column(DateTime(timezone=True), nullable=True)
    created_at         = Column(DateTime(timezone=True), server_default=func.now())


class TrainingQuizAttempt(Base):
    __tablename__ = "training_quiz_attempts"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id     = Column(String, nullable=False, index=True)
    module_id     = Column(Integer, ForeignKey("training_modules.id"), nullable=False)
    user_label    = Column(String, default="default")
    answers_json  = Column(JSON, default=list)   # [selected_index, ...]
    score         = Column(Integer, default=0)   # 0-100
    passed        = Column(Boolean, default=False)
    attempted_at  = Column(DateTime(timezone=True), server_default=func.now())
