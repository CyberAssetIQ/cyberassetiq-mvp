from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON
from sqlalchemy.sql import func

from db.session import Base


class AICorrelation(Base):
    """
    Links multiple AI events and alerts into a single attack narrative / chain.
    Represents a correlated incident: e.g. CVE + suspicious login + data exfiltration.
    """
    __tablename__ = "ai_correlations"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(128), nullable=False, index=True, default="tenant-001")

    correlation_type = Column(String(64), nullable=False, index=True)
    # e.g. attack_chain, impossible_travel, brute_force_success, privilege_escalation

    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=True)

    status = Column(String(32), nullable=False, default="open", index=True)
    # open, investigating, resolved, false_positive

    confidence_score = Column(Float, nullable=True)    # 0.0 - 1.0
    risk_score = Column(Float, nullable=True)          # 0.0 - 100.0

    asset_id = Column(Integer, nullable=True, index=True)
    asset_name = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    hostname = Column(String(255), nullable=True)
    user_ref = Column(String(255), nullable=True, index=True)

    # JSON arrays of event IDs and alert IDs that contributed
    event_refs_json = Column(JSON, nullable=True)
    alert_refs_json = Column(JSON, nullable=True)

    # Ordered list of attack steps for timeline display
    attack_chain_json = Column(JSON, nullable=True)

    # MITRE ATT&CK tactic / technique mapping
    mitre_tactic = Column(String(64), nullable=True)
    mitre_technique = Column(String(64), nullable=True)
    mitre_map_json = Column(JSON, nullable=True)   # full mapping list

    llm_narrative = Column(Text, nullable=True)    # LLM-generated attack story

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
