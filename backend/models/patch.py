from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String
from sqlalchemy.sql import func

from models.mixins import Base


class PatchReport(Base):
    __tablename__ = "patch_reports"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id         = Column(String, nullable=False, index=True)
    agent_id          = Column(String, nullable=False, index=True)
    reported_at       = Column(DateTime(timezone=True), server_default=func.now())

    # OS info
    os_name           = Column(String, nullable=True)
    os_version        = Column(String, nullable=True)
    os_build          = Column(Integer, nullable=True)
    os_supported      = Column(Boolean, default=True)
    os_arch           = Column(String, nullable=True)

    # Patch counts
    patch_score       = Column(Integer, default=100)
    pending_total     = Column(Integer, default=0)
    pending_critical  = Column(Integer, default=0)
    pending_important = Column(Integer, default=0)
    outdated_count    = Column(Integer, default=0)

    # Detail JSON
    windows_updates_json   = Column(JSON, default=list)   # [{title, severity, kb}]
    outdated_software_json = Column(JSON, default=list)   # [{name, installed_version, min_safe_version, winget_id, has_cves}]


class PatchApproval(Base):
    """Admin-approved patches waiting to be dispatched to the agent."""
    __tablename__ = "patch_approvals"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id     = Column(String, nullable=False, index=True)
    agent_id      = Column(String, nullable=False, index=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())
    approved_at   = Column(DateTime(timezone=True), nullable=True)

    software_name = Column(String, nullable=False)
    winget_id     = Column(String, nullable=True)
    patch_type    = Column(String, default="software")   # software / windows_update

    status        = Column(String, default="pending")    # pending / dispatched / completed / failed
    result_json   = Column(JSON, nullable=True)
    command_uuid  = Column(String, nullable=True)        # linked AgentCommand uuid
