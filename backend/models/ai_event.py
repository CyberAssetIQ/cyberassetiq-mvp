from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func

from db.session import Base


class AIEvent(Base):
    __tablename__ = "ai_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(50), nullable=False, default="medium", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    source = Column(String(100), nullable=True, index=True)  # siem, darkweb, cve, compliance, scanner
    asset_id = Column(String(100), nullable=True, index=True)
    asset_name = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(100), nullable=True, index=True)
    hostname = Column(String(255), nullable=True, index=True)

    status = Column(String(50), nullable=False, default="open", index=True)  # open, investigating, resolved
    risk_score = Column(Integer, nullable=False, default=0, index=True)

    raw_payload = Column(JSON, nullable=True)
    ai_summary = Column(Text, nullable=True)
    ai_recommendation = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)