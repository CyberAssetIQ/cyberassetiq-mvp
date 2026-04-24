from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set. Reset the same database your backend is using.")

from db.session import SessionLocal  # noqa: E402
from models.agent import Agent  # noqa: E402
from models.asset import CanonicalAsset  # noqa: E402
from models.darkweb import DarkWebFinding, DarkWebSourceItem, DarkWebWatchlist  # noqa: E402
from models.network import NetworkDiscoveredAsset, NetworkScanJob  # noqa: E402
from models.telemetry import CanonicalSoftware, LocalFindingsEvent, VulnerabilityFinding  # noqa: E402


def reset_demo(tenant_id: str = "tenant-001") -> None:
    db = SessionLocal()
    try:
        models = [
            LocalFindingsEvent,
            VulnerabilityFinding,
            CanonicalSoftware,
            DarkWebFinding,
            DarkWebSourceItem,
            DarkWebWatchlist,
            NetworkDiscoveredAsset,
            NetworkScanJob,
            CanonicalAsset,
            Agent,
        ]
        for model in models:
            db.query(model).filter(getattr(model, "tenant_id") == tenant_id).delete(synchronize_session=False)
        db.commit()
        print(f"Reset demo data for {tenant_id}")
    finally:
        db.close()


if __name__ == "__main__":
    reset_demo(os.getenv("CYBERASSETIQ_DEFAULT_TENANT", "tenant-001"))
