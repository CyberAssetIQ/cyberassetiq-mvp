"""
Windows Security Event Log Collector
Reads recent Windows Security events using wevtutil (built-in, no extra deps).
Focuses on security-relevant Event IDs that feed the AI detection engine.

Supported events:
  4624  Successful logon
  4625  Failed logon
  4720  New user account created
  4728  Member added to global security group
  4732  Member added to local security group
  4740  Account locked out
  4648  Logon with explicit credentials
  4672  Special privileges assigned (admin logon)
  4697  Service installed
  4698  Scheduled task created
  4702  Scheduled task updated
  4719  System audit policy changed
  4738  User account changed
  1102  Audit log cleared
  7045  New service installed (System log)
"""
from __future__ import annotations

import logging
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Security-relevant Event IDs to collect
_SECURITY_EVENT_IDS = {
    "4624", "4625", "4720", "4728", "4732", "4740",
    "4648", "4672", "4697", "4698", "4702", "4719",
    "4738", "1102",
}
_SYSTEM_EVENT_IDS = {"7045"}

# Namespace used in Windows event XML
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _run_wevtutil(log_name: str, count: int, xpath_filter: str | None = None) -> str:
    """Run wevtutil to query event log. Returns raw XML string."""
    cmd = [
        "wevtutil", "qe", log_name,
        f"/c:{count}",
        "/rd:true",   # newest first
        "/f:XML",
    ]
    if xpath_filter:
        cmd += [f"/q:{xpath_filter}"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except FileNotFoundError:
        logger.debug("wevtutil not found — not running on Windows")
        return ""
    except subprocess.TimeoutExpired:
        logger.warning("wevtutil timed out reading %s", log_name)
        return ""
    except Exception as exc:
        logger.warning("wevtutil error on %s: %s", log_name, exc)
        return ""


def _parse_event_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse wevtutil XML output into list of event dicts."""
    events = []

    # wevtutil returns multiple <Event> elements — wrap in a root
    try:
        wrapped = f"<Events>{xml_text}</Events>"
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        logger.warning("Event XML parse error: %s", exc)
        return []

    for event_elem in root.findall("e:Event", _NS):
        try:
            ev = _extract_event(event_elem)
            if ev:
                events.append(ev)
        except Exception as exc:
            logger.debug("Failed to extract event: %s", exc)

    return events


def _extract_event(event_elem: ET.Element) -> dict[str, Any] | None:
    """Extract a clean event dict from an <Event> XML element."""
    sys_elem = event_elem.find("e:System", _NS)
    if sys_elem is None:
        return None

    event_id_elem = sys_elem.find("e:EventID", _NS)
    if event_id_elem is None:
        return None
    event_id = event_id_elem.text or ""

    computer_elem = sys_elem.find("e:Computer", _NS)
    computer = computer_elem.text if computer_elem is not None else ""

    time_elem = sys_elem.find("e:TimeCreated", _NS)
    time_str = time_elem.attrib.get("SystemTime", "") if time_elem is not None else ""

    channel_elem = sys_elem.find("e:Channel", _NS)
    channel = channel_elem.text if channel_elem is not None else "Security"

    # Extract EventData fields into a flat dict
    event_data: dict[str, str] = {}
    data_elem = event_elem.find("e:EventData", _NS)
    if data_elem is not None:
        for item in data_elem.findall("e:Data", _NS):
            name = item.attrib.get("Name", "")
            value = item.text or ""
            if name:
                event_data[name] = value

    # Pull out common fields with sensible defaults
    subject_user = event_data.get("SubjectUserName", "")
    target_user  = event_data.get("TargetUserName", "")
    ip_address   = event_data.get("IpAddress", event_data.get("WorkstationName", ""))
    logon_type   = event_data.get("LogonType", "")
    service_name = event_data.get("ServiceName", event_data.get("TaskName", ""))
    process_name = event_data.get("ProcessName", event_data.get("NewProcessName", ""))

    # Clean up placeholder values Windows uses for N/A
    ip_address = "" if ip_address in ("-", "::1", "127.0.0.1", "LOCAL", "") else ip_address
    subject_user = "" if subject_user in ("-", "SYSTEM", "") else subject_user
    target_user  = "" if target_user  in ("-", "") else target_user

    return {
        "EventID":         event_id,
        "Computer":        computer,
        "TimeCreated":     time_str,
        "Channel":         channel,
        "SubjectUserName": subject_user,
        "TargetUserName":  target_user,
        "IpAddress":       ip_address,
        "LogonType":       logon_type,
        "ServiceName":     service_name,
        "ProcessName":     process_name,
        "RawEventData":    event_data,
        "source_type":     "windows",
    }


def collect_security_events(max_events: int = 100) -> list[dict[str, Any]]:
    """
    Collect recent Windows Security and System events.
    Returns list of raw event dicts ready for the AI ingest endpoint.
    Only runs on Windows — returns [] on other platforms.
    """
    if sys.platform != "win32":
        logger.debug("Event log collection skipped — not Windows")
        return []

    # Build XPath filter for relevant Event IDs
    security_ids = " or ".join(
        f"EventID={eid}" for eid in sorted(_SECURITY_EVENT_IDS)
    )
    xpath_security = f"*[System[({security_ids})]]"

    system_ids = " or ".join(
        f"EventID={eid}" for eid in sorted(_SYSTEM_EVENT_IDS)
    )
    xpath_system = f"*[System[({system_ids})]]"

    events: list[dict[str, Any]] = []

    # Read Security log
    xml_sec = _run_wevtutil("Security", max_events, xpath_security)
    if xml_sec.strip():
        parsed = _parse_event_xml(xml_sec)
        events.extend(parsed)
        logger.info("Event log: collected %d Security events", len(parsed))

    # Read System log for service installs (EventID 7045)
    xml_sys = _run_wevtutil("System", 20, xpath_system)
    if xml_sys.strip():
        parsed_sys = _parse_event_xml(xml_sys)
        events.extend(parsed_sys)
        logger.info("Event log: collected %d System events", len(parsed_sys))

    return events


def filter_new_events(
    events: list[dict[str, Any]],
    since_epoch: int,
) -> list[dict[str, Any]]:
    """
    Filter events to only those newer than since_epoch.
    Handles Windows event timestamp format: 2026-01-15T10:30:00.000000000Z
    """
    if not since_epoch:
        return events

    new_events = []
    for ev in events:
        ts_str = ev.get("TimeCreated", "")
        if not ts_str:
            new_events.append(ev)
            continue
        try:
            # Truncate nanoseconds to microseconds (Python supports up to 6 digits)
            ts_clean = ts_str[:26].rstrip("0").rstrip(".")
            if "Z" in ts_str:
                ts_clean += "+00:00"
            dt = datetime.fromisoformat(ts_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if int(dt.timestamp()) > since_epoch:
                new_events.append(ev)
        except Exception:
            new_events.append(ev)  # include if can't parse timestamp

    return new_events
