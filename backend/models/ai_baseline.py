from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.sql import func

from db.session import Base


class AIBaseline(Base):
    """
    Stores behavioural baselines for anomaly detection.
    One row per (tenant, entity_type, entity_ref, baseline_type).
    Updated periodically as the platform learns normal behaviour.

    entity_type: asset | user | network | process
    baseline_type: login_times | login_sources | process_names | outbound_ports | auth_volume
    """
    __tablename__ = "ai_baselines"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(128), nullable=False, index=True, default="tenant-001")

    entity_type = Column(String(32), nullable=False, index=True)
    entity_ref = Column(String(255), nullable=False, index=True)
    # For users: email / username. For assets: hostname or asset_id. For network: CIDR.

    baseline_type = Column(String(64), nullable=False, index=True)

    # The baseline data — structure depends on baseline_type:
    # login_times:    {"hours": [8, 9, 10, 17, 18], "days": [0,1,2,3,4]}
    # login_sources:  {"ips": ["10.0.0.0/8"], "countries": ["GB"]}
    # process_names:  {"processes": ["svchost.exe", "chrome.exe"]}
    # outbound_ports: {"ports": [80, 443, 8080]}
    # auth_volume:    {"mean_per_hour": 2.4, "std_dev": 1.1, "max_observed": 12}
    baseline_json = Column(JSON, nullable=False)

    observation_count = Column(Integer, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False, index=True)
