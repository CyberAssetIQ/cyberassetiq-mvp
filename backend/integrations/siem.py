"""
SIEM Connectors
---------------
Sentinel     — Azure Monitor Log Analytics HTTP Data Collector API
Splunk HEC   — Splunk HTTP Event Collector
QRadar       — IBM QRadar REST Syslog/API
Elastic      — Elasticsearch / Elastic SIEM ingest endpoint

Config keys documented per class.
"""

from __future__ import annotations
import hashlib
import hmac
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from integrations.base import BaseConnector, ConnectorError

logger = logging.getLogger(__name__)


# ======================================================================= #
# Microsoft Sentinel (Azure Monitor Log Analytics)                         #
# ======================================================================= #

class SentinelConnector(BaseConnector):
    """
    Pushes enriched events to a custom Log Analytics table.

    Config keys:
      workspace_id   — Log Analytics workspace GUID
      workspace_key  — Primary or secondary shared key (base64)
      log_type       — Custom table name, e.g. CyberAssetIQ (default)
    """

    category = "siem"
    connector_type = "sentinel"

    def _build_signature(self, date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        key = base64.b64decode(self.config["workspace_key"])
        encoded = string_to_hash.encode("utf-8")
        sha256 = hmac.new(key, encoded, digestmod=hashlib.sha256)
        return f"SharedKey {self.config['workspace_id']}:{base64.b64encode(sha256.digest()).decode()}"

    def _url(self) -> str:
        wid = self.config["workspace_id"]
        return f"https://{wid}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("workspace_id", "workspace_key")
        log_type = self.config.get("log_type", "CyberAssetIQ")

        body = json.dumps([event])
        body_bytes = body.encode("utf-8")
        rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        sig = self._build_signature(
            rfc1123_date, len(body_bytes), "POST", "application/json", "/api/logs"
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": sig,
            "Log-Type": log_type,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "timestamp",
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self._url(), content=body_bytes, headers=headers)
            if resp.status_code == 200:
                return True
            raise ConnectorError(f"Sentinel HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.RequestError as exc:
            raise ConnectorError(f"Sentinel request error: {exc}") from exc

    async def test(self) -> tuple[bool, str]:
        self._require("workspace_id", "workspace_key")
        try:
            result = await self.send_event({
                "event_type": "CyberAssetIQ_ConnectionTest",
                "severity": 0,
                "timestamp": datetime.utcnow().isoformat(),
                "description": "Connectivity test from CyberAssetIQ",
            })
            return (True, "Sentinel workspace accepted test event")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Splunk HTTP Event Collector (HEC)                                        #
# ======================================================================= #

class SplunkConnector(BaseConnector):
    """
    Pushes events via Splunk HEC.

    Config keys:
      hec_url    — e.g. https://splunk.example.com:8088/services/collector
      hec_token  — HEC token (no "Splunk " prefix needed here)
      index      — Optional Splunk index (default: main)
      source     — Optional source field (default: cyberassetiq)
    """

    category = "siem"
    connector_type = "splunk"

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("hec_url", "hec_token")
        payload = {
            "time": datetime.utcnow().timestamp(),
            "host": "cyberassetiq",
            "source": self.config.get("source", "cyberassetiq"),
            "sourcetype": "_json",
            "index": self.config.get("index", "main"),
            "event": event,
        }
        headers = {
            "Authorization": f"Splunk {self.config['hec_token']}",
            "Content-Type": "application/json",
        }
        await self._post(self.config["hec_url"], payload, headers=headers)
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("hec_url", "hec_token")
        try:
            await self.send_event({
                "event_type": "CyberAssetIQ_ConnectionTest",
                "description": "Connectivity test from CyberAssetIQ",
            })
            return (True, "Splunk HEC accepted test event")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# IBM QRadar                                                               #
# ======================================================================= #

class QRadarConnector(BaseConnector):
    """
    Pushes events to QRadar via its REST API (Log Source Management).
    Uses the /api/siem/offenses endpoint for event injection.

    Config keys:
      base_url      — e.g. https://qradar.example.com
      api_token     — QRadar SEC token (Settings > Authorized Services)
      log_source_id — Optional: existing log source ID to associate events
    """

    category = "siem"
    connector_type = "qradar"

    def _headers(self) -> dict:
        return {
            "SEC": self.config["api_token"],
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Version": "16.0",
        }

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("base_url", "api_token")
        # QRadar accepts custom events via the Ariel API or via syslog.
        # We use the Custom Properties / offense notes endpoint for enrichment,
        # and POST a structured log entry via the /api/data_classification endpoint.
        # For direct event injection we POST to the log source REST ingest endpoint.
        url = f"{self.config['base_url'].rstrip('/')}/api/staged_config/notification_channels"
        # Practical approach: POST to QRadar's REST offense search as a custom event
        # using the authorized syslog ingestion endpoint.
        event_payload = {
            "log_source_id": self.config.get("log_source_id"),
            "payload": self.build_cef_event(event),
        }
        # QRadar REST — POST to the syslog collector port (514 UDP) is unreliable
        # from a SaaS platform. Instead we use the offense annotation API to attach
        # CyberAssetIQ context to matching offenses.
        # POST /api/siem/offenses/{id}/notes is the enrichment path.
        # For new event injection: POST /api/data_classification/dsm_event_mappings
        ingest_url = f"{self.config['base_url'].rstrip('/')}/console/do/qradar/api/v1/events"
        await self._post(ingest_url, event_payload, headers=self._headers())
        return True

    async def send_offense_note(self, offense_id: int, note: str) -> bool:
        """Attach a CyberAssetIQ finding as a note on an existing QRadar offense."""
        self._require("base_url", "api_token")
        url = f"{self.config['base_url'].rstrip('/')}/api/siem/offenses/{offense_id}/notes"
        await self._post(url, {"note_text": note}, headers=self._headers())
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("base_url", "api_token")
        try:
            url = f"{self.config['base_url'].rstrip('/')}/api/system/about"
            resp = await self._get(url, headers=self._headers())
            data = resp.json()
            return (True, f"QRadar connected — version {data.get('external_version', 'unknown')}")
        except ConnectorError as exc:
            return (False, str(exc))


# ======================================================================= #
# Elastic / Elastic SIEM                                                   #
# ======================================================================= #

class ElasticConnector(BaseConnector):
    """
    Pushes ECS-normalised events to Elasticsearch.

    Config keys:
      es_url    — e.g. https://my-cluster.es.io:9200
      api_key   — base64 API key (id:api_key format encoded)
      index     — target index, e.g. cyberassetiq-events (default)
    """

    category = "siem"
    connector_type = "elastic"

    def _headers(self) -> dict:
        return {
            "Authorization": f"ApiKey {self.config['api_key']}",
            "Content-Type": "application/json",
        }

    def _ecs_envelope(self, event: dict[str, Any]) -> dict:
        """Wrap a CyberAssetIQ event in an ECS (Elastic Common Schema) envelope."""
        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event": {
                "provider": "CyberAssetIQ",
                "dataset": event.get("event_type", "generic"),
                "severity": event.get("severity", 5),
                "kind": "event",
                "category": ["host"] if event.get("asset_name") else ["network"],
                "type": ["info"],
            },
            "host": {
                "name": event.get("asset_name"),
                "ip": [event.get("asset_ip")] if event.get("asset_ip") else [],
            },
            "message": event.get("description", ""),
            "labels": {
                "tenant_id": event.get("tenant_id"),
                "cve_id": event.get("cve_id"),
                "ce_control": event.get("ce_control"),
                "remediation_class": event.get("remediation_class"),
                "secret_score": str(event.get("secret_score", "")),
                "ce_compliant": str(event.get("ce_compliant", "")),
            },
            "vulnerability": {
                "id": event.get("cve_id"),
                "severity": event.get("cvss_severity"),
                "score": {"base": event.get("cvss_score")},
            },
            "cyberassetiq": event,  # raw payload passthrough
        }

    async def send_event(self, event: dict[str, Any]) -> bool:
        self._require("es_url", "api_key")
        index = self.config.get("index", "cyberassetiq-events")
        url = f"{self.config['es_url'].rstrip('/')}/{index}/_doc"
        await self._post(url, self._ecs_envelope(event), headers=self._headers())
        return True

    async def test(self) -> tuple[bool, str]:
        self._require("es_url", "api_key")
        try:
            url = f"{self.config['es_url'].rstrip('/')}/"
            resp = await self._get(url, headers=self._headers())
            data = resp.json()
            version = data.get("version", {}).get("number", "unknown")
            return (True, f"Elasticsearch connected — version {version}")
        except ConnectorError as exc:
            return (False, str(exc))
