from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentConfig:
    backend_url: str
    tenant_id: str
    api_key: str
    agent_id: str | None
    enrollment_token: str | None
    poll_interval_seconds: int
    command_poll_interval_seconds: int
    queue_db_path: str
    log_level: str
    verify_tls: bool
    hostname_override: str | None = None
    log_ingest_enabled: bool = True
    log_ingest_interval_seconds: int = 300
    log_ingest_max_events: int = 100


def load_config() -> AgentConfig:
    return AgentConfig(
        backend_url=os.getenv("CYBERASSETIQ_BACKEND_URL", "http://localhost:8000"),
        tenant_id=os.getenv("CYBERASSETIQ_TENANT_ID", "dev-tenant"),
        api_key=os.getenv("CYBERASSETIQ_API_KEY", ""),
        agent_id=os.getenv("CYBERASSETIQ_AGENT_ID") or None,
        enrollment_token=os.getenv("CYBERASSETIQ_ENROLLMENT_TOKEN") or None,
        poll_interval_seconds=int(os.getenv("CYBERASSETIQ_POLL_INTERVAL", "300")),
        command_poll_interval_seconds=int(os.getenv("CYBERASSETIQ_COMMAND_POLL_INTERVAL", "60")),
        queue_db_path=os.getenv(
            "CYBERASSETIQ_QUEUE_DB",
            str(Path("agent_queue.db").resolve()),
        ),
        log_level=os.getenv("CYBERASSETIQ_LOG_LEVEL", "INFO"),
        verify_tls=os.getenv("CYBERASSETIQ_VERIFY_TLS", "true").lower() == "true",
        hostname_override=os.getenv("CYBERASSETIQ_HOSTNAME_OVERRIDE") or None,
        log_ingest_enabled=os.getenv("CYBERASSETIQ_LOG_INGEST_ENABLED", "true").lower() == "true",
        log_ingest_interval_seconds=int(os.getenv("CYBERASSETIQ_LOG_INGEST_INTERVAL", "300")),
        log_ingest_max_events=int(os.getenv("CYBERASSETIQ_LOG_INGEST_MAX_EVENTS", "100")),
    )
