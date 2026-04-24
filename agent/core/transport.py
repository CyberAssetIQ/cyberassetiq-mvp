from __future__ import annotations

"""
BackendClient — authenticated transport layer for the CyberAssetIQ agent.
"""

from typing import Any

import requests


class BackendClient:
    def __init__(self, backend_url: str, verify_tls: bool = True, api_key: str = ""):
        self.backend_url = backend_url.rstrip("/")
        self.verify_tls = verify_tls
        self._api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _auth_headers(self, tenant_id: str, agent_id: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {
            "X-Api-Key": self._api_key,
            "X-Tenant-Id": tenant_id,
        }
        if agent_id:
            headers["X-Agent-Id"] = agent_id
        return headers

    def enroll(self, tenant_id: str, enrollment_token: str, hostname: str) -> dict[str, Any]:
        response = self.session.post(
            f"{self.backend_url}/api/agents/enroll",
            json={"tenant_id": tenant_id, "enrollment_token": enrollment_token, "hostname": hostname},
            headers=self._auth_headers(tenant_id),
            timeout=20,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        return response.json()

    def fetch_policy(self, tenant_id: str, agent_id: str) -> dict[str, Any]:
        response = self.session.get(
            f"{self.backend_url}/api/agents/{agent_id}/policy",
            headers=self._auth_headers(tenant_id, agent_id),
            timeout=20,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        return response.json()

    def fetch_commands(self, tenant_id: str, agent_id: str) -> dict[str, Any]:
        response = self.session.get(
            f"{self.backend_url}/api/agents/{agent_id}/commands",
            headers=self._auth_headers(tenant_id, agent_id),
            timeout=20,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        return response.json()

    def ack_command(self, tenant_id: str, agent_id: str, command_id: str, acked_epoch: int) -> dict[str, Any]:
        response = self.session.post(
            f"{self.backend_url}/api/agents/{agent_id}/commands/{command_id}/ack",
            json={"tenant_id": tenant_id, "acked_epoch": acked_epoch},
            headers=self._auth_headers(tenant_id, agent_id),
            timeout=20,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        return response.json()

    def complete_command(
        self,
        tenant_id: str,
        agent_id: str,
        command_id: str,
        status: str,
        started_epoch: int | None,
        completed_epoch: int | None,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        response = self.session.post(
            f"{self.backend_url}/api/agents/{agent_id}/commands/{command_id}/result",
            json={
                "tenant_id": tenant_id,
                "status": status,
                "started_epoch": started_epoch,
                "completed_epoch": completed_epoch,
                "result": result,
            },
            headers=self._auth_headers(tenant_id, agent_id),
            timeout=20,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        return response.json()

    def send_payload(self, payload_type: str, payload: dict[str, Any]) -> None:
        tenant_id = payload.get("tenant_id", "")
        agent_id = payload.get("agent_id")
        response = self.session.post(
            f"{self.backend_url}/api/agents/telemetry/{payload_type}",
            json=payload,
            headers=self._auth_headers(tenant_id, agent_id),
            timeout=30,
            verify=self.verify_tls,
        )
        response.raise_for_status()

    def send_heartbeat(self, payload: dict[str, Any]) -> None:
        tenant_id = payload.get("tenant_id", "")
        agent_id = payload.get("agent_id")
        response = self.session.post(
            f"{self.backend_url}/api/agents/heartbeat",
            json=payload,
            headers=self._auth_headers(tenant_id, agent_id),
            timeout=15,
            verify=self.verify_tls,
        )
        response.raise_for_status()
