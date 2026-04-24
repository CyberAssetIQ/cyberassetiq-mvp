"""
Base connector class.
All connectors must implement: test() and send_event().
"""

from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from typing import Any
import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10  # seconds


class ConnectorError(Exception):
    """Raised when a connector call fails non-transiently."""
    pass


class BaseConnector(ABC):
    """
    Abstract base connector.

    Subclasses receive the stored `config` dict from IntegrationConnector.config
    and implement test() + send_event().
    """

    category: str = ""       # siem | edr | iam | soar | msp | itsm
    connector_type: str = "" # e.g. sentinel

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------ #
    # Abstract interface                                                   #
    # ------------------------------------------------------------------ #

    @abstractmethod
    async def test(self) -> tuple[bool, str]:
        """
        Validate credentials / connectivity.
        Returns (success: bool, message: str).
        """

    @abstractmethod
    async def send_event(self, event: dict[str, Any]) -> bool:
        """
        Push a normalised CyberAssetIQ event to the integration target.
        Returns True on success.  Raises ConnectorError on failure.
        """

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _require(self, *keys: str) -> None:
        """Assert that required config keys are present."""
        missing = [k for k in keys if not self.config.get(k)]
        if missing:
            raise ConnectorError(f"Missing config keys: {', '.join(missing)}")

    async def _post(
        self,
        url: str,
        payload: Any,
        headers: dict | None = None,
        auth: tuple | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> httpx.Response:
        """Generic async POST with error wrapping."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers=headers or {},
                    auth=auth,
                )
            if resp.status_code >= 400:
                raise ConnectorError(
                    f"HTTP {resp.status_code} from {url}: {resp.text[:300]}"
                )
            return resp
        except httpx.RequestError as exc:
            raise ConnectorError(f"Request error to {url}: {exc}") from exc

    async def _get(
        self,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        auth: tuple | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> httpx.Response:
        """Generic async GET with error wrapping."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(
                    url,
                    headers=headers or {},
                    params=params or {},
                    auth=auth,
                )
            if resp.status_code >= 400:
                raise ConnectorError(
                    f"HTTP {resp.status_code} from {url}: {resp.text[:300]}"
                )
            return resp
        except httpx.RequestError as exc:
            raise ConnectorError(f"Request error to {url}: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Normalised event builder                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def build_cef_event(event: dict[str, Any]) -> str:
        """
        Build a CEF (Common Event Format) string from a CyberAssetIQ event dict.

        Expected event keys (all optional except event_type):
          event_type, severity (0-10), asset_name, asset_ip, tenant_id,
          description, cve_id, ce_control, secret_score, remediation_class
        """
        sev = event.get("severity", 5)
        name = event.get("event_type", "CyberAssetIQEvent")
        asset = event.get("asset_name", "unknown")
        desc = event.get("description", "")
        ext_parts = [
            f"cs1={event.get('tenant_id', '')}",
            f"cs1Label=TenantID",
            f"cs2={event.get('cve_id', '')}",
            f"cs2Label=CVE",
            f"cs3={event.get('ce_control', '')}",
            f"cs3Label=CEControl",
            f"cs4={event.get('remediation_class', '')}",
            f"cs4Label=RemediationClass",
            f"cfp1={event.get('secret_score', '')}",
            f"cfp1Label=SecretScore",
            f"src={event.get('asset_ip', '')}",
            f"dhost={asset}",
            f"msg={desc[:512]}",
        ]
        ext = " ".join(p for p in ext_parts if "=" in p and p.split("=", 1)[1])
        return (
            f"CEF:0|TotalIT Solutions|CyberAssetIQ|2.4|{name}|{name}|{sev}|{ext}"
        )
