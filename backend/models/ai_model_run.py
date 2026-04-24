from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON
from sqlalchemy.sql import func

from db.session import Base


class AIModelRun(Base):
    """
    Audit log for every LLM call and ML model run.
    Used for cost tracking, performance monitoring, and debugging.
    """
    __tablename__ = "ai_model_runs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(128), nullable=False, index=True, default="tenant-001")

    model_name = Column(String(128), nullable=False, index=True)
    provider_name = Column(String(64), nullable=True)   # anthropic | openai | local

    run_type = Column(String(64), nullable=False, index=True)
    # copilot_query | alert_explanation | daily_brief | investigation | risk_score | detection

    input_ref = Column(String(255), nullable=True)    # reference to the triggering entity
    output_ref = Column(String(255), nullable=True)   # reference to the created entity

    latency_ms = Column(Integer, nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)

    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text, nullable=True)

    # Optional: store redacted prompt for debugging (never store raw secrets)
    debug_context_json = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
