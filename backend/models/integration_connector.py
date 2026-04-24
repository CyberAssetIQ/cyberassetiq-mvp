"""
models/integration_connector.py
SQLAlchemy ORM model for the integration_connectors table.
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, Integer, String, Text, DateTime, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from models.mixins import Base


class IntegrationConnector(Base):
    __tablename__ = "integration_connectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_test_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_test_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_events_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<IntegrationConnector id={self.id} tenant={self.tenant_id!r} type={self.connector_type!r} enabled={self.enabled}>"
