from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String
from sqlalchemy.sql import func

from models.mixins import Base


class ExternalScan(Base):
    __tablename__ = "external_scans"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id        = Column(String, nullable=False, index=True)
    scanned_at       = Column(DateTime(timezone=True), server_default=func.now())
    public_ip        = Column(String, nullable=True)
    scan_status      = Column(String, default="pending")   # pending / running / completed / failed
    error            = Column(String, nullable=True)
    total_findings   = Column(Integer, default=0)
    critical_count   = Column(Integer, default=0)
    high_count       = Column(Integer, default=0)
    open_ports_json  = Column(JSON, default=list)          # [{port, service, banner}]
    findings_json    = Column(JSON, default=list)          # [{port, severity, title, description, remediation}]
    scan_duration_s  = Column(Integer, nullable=True)


class ExternalFinding(Base):
    __tablename__ = "external_findings"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id    = Column(String, nullable=False, index=True)
    scan_id      = Column(Integer, nullable=False, index=True)
    scanned_at   = Column(DateTime(timezone=True), server_default=func.now())
    public_ip    = Column(String, nullable=True)
    port         = Column(Integer, nullable=True)
    protocol     = Column(String, default="tcp")
    service      = Column(String, nullable=True)
    banner       = Column(String, nullable=True)
    severity     = Column(String, nullable=False)
    title        = Column(String, nullable=False)
    description  = Column(String, nullable=True)
    remediation  = Column(String, nullable=True)
    status       = Column(String, default="open")   # open / resolved / accepted_risk
