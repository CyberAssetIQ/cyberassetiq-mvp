from __future__ import annotations

"""
CyberAssetIQ Agent — service/main.py

Fixes in this version vs original:
  - periodic_loop now starts at startup (was missing — caused last_run to stay empty)
  - ARP ping sweep is cross-platform (Windows: ping -n, macOS/Linux: ping -c)
  - Subnet auto-detected from active interface (not hardcoded to 192.168.0.x)
  - OUI vendor table expanded
  - macOS ARP format parsed correctly (different from Windows)
"""

import concurrent.futures
import logging
import platform
import re
import socket
import subprocess
import threading
import time

from fastapi import FastAPI

from core.cache import LocalQueue
from core.config import load_config
from core.logging import configure_logging
from core.scheduler import flush_queue, run_cycle
from core.transport import BackendClient

logger = logging.getLogger(__name__)

app = FastAPI(title="CyberAssetIQ Agent")

config = load_config()
configure_logging(config.log_level)

queue   = LocalQueue(config.queue_db_path)
backend = BackendClient(config.backend_url, verify_tls=config.verify_tls, api_key=config.api_key or "")

_cycle_lock = threading.Lock()
_SYSTEM = platform.system()  # "Windows" | "Darwin" | "Linux"

agent_state = {
    "registered":          False,
    "agent_id":            config.agent_id,
    "last_policy":         {},
    "last_run":            None,
    "last_error":          None,
    "last_command_poll":   None,
    "last_command_result": None,
    "last_arp_run":        None,
    "last_arp_count":      0,
    "last_log_ingest_epoch": None,
    "last_log_ingest_count": 0,
}

# ── OUI vendor table ──────────────────────────────────────────────────────

OUI_TABLE = {
    "00:50:56": "VMware",        "00:0c:29": "VMware",
    "00:1a:11": "Google",        "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",  "e4:5f:01": "Raspberry Pi",
    "00:1b:21": "Intel",         "3c:97:0e": "HP",
    "b4:b5:2f": "Apple",         "f8:ff:c2": "Apple",
    "3c:22:fb": "Apple",         "28:cf:e9": "Apple",
    "a8:66:7f": "Apple",         "00:17:f2": "Apple",
    "3c:15:c2": "Apple",         "70:56:81": "Apple",
    "f0:18:98": "Apple",         "38:f9:d3": "Apple",
    "7c:6d:62": "Apple",         "d8:1d:72": "Apple",
    "00:23:12": "Apple",         "34:36:3b": "Apple",
    "ac:bc:32": "Apple",         "00:50:ba": "D-Link",
    "00:26:b9": "Dell",          "f8:bc:12": "Dell",
    "40:74:e0": "Dell",          "00:21:70": "Cisco",
    "00:0a:41": "Cisco",         "00:1d:7e": "Cisco-Linksys",
    "00:25:9c": "Cisco",         "a4:c3:f0": "Google",
    "00:e0:4c": "Realtek",       "fc:ec:da": "Ubiquiti",
    "24:a4:3c": "Ubiquiti",      "dc:9f:db": "TP-Link",
    "50:c7:bf": "TP-Link",       "14:eb:b6": "TP-Link",
    "c4:e9:84": "TP-Link",       "30:de:4b": "TP-Link",
    "ac:f8:cc": "TP-Link",       "ac:84:c6": "Samsung",
    "f4:7b:09": "Samsung",       "04:52:c7": "Samsung",
    "8c:77:12": "Samsung",       "cc:07:ab": "Samsung",
    "78:59:5e": "Samsung",       "5c:49:7d": "Huawei",
    "00:e0:fc": "Huawei",        "28:31:52": "Huawei",
    "04:f9:38": "Xiaomi",        "64:09:80": "Xiaomi",
    "f8:a4:5f": "Xiaomi",        "28:73:f6": "Intel",
    "d4:d8:53": "Gigabyte",      "c4:a5:59": "Murata (IoT)",
    "54:df:1b": "Murata (IoT)",  "74:58:f3": "Liteon (Laptop)",
    "10:bf:67": "Intel",         "00:11:32": "Synology",
    "00:90:a9": "Synology",      "00:15:5d": "Microsoft (Hyper-V)",
    "52:54:00": "QEMU/KVM",      "08:00:27": "VirtualBox",
    "00:1c:42": "Parallels",     "30:9c:23": "Hewlett Packard",
    "e8:39:35": "Hewlett Packard","b8:ca:3a": "Hewlett Packard",
    "00:e0:4b": "Netgear",       "a0:40:a0": "Netgear",
    "20:e5:2a": "Netgear",       "c4:04:15": "Netgear",
    "00:1f:90": "Netgear",       "44:94:fc": "Belkin",
    "94:10:3e": "Belkin",        "ec:1a:59": "Belkin",
    "00:30:bd": "Belkin",
}


def _vendor_from_mac(mac: str) -> str | None:
    if not mac:
        return None
    prefix = mac.lower()[:8]
    for oui, vendor in OUI_TABLE.items():
        if prefix.startswith(oui.lower()):
            return vendor
    return None


# ── Subnet auto-detection ─────────────────────────────────────────────────

def _detect_lan_subnet() -> str:
    """
    Detect the active LAN subnet (e.g. '192.168.1') from this machine's
    non-loopback IPv4 address. Falls back to '192.168.0'.
    """
    try:
        for _iface, addrs in __import__("psutil").net_if_addrs().items():
            for addr in addrs:
                if getattr(addr, "family", None) == socket.AF_INET:
                    ip = addr.address
                    if (ip.startswith("192.168.") or ip.startswith("10.")
                            or ip.startswith("172.")):
                        parts = ip.rsplit(".", 1)
                        return parts[0]
    except Exception:
        pass
    return "192.168.0"


# ── Cross-platform ping sweep ─────────────────────────────────────────────

def _ping(ip: str) -> None:
    try:
        if _SYSTEM == "Windows":
            subprocess.run(["ping", "-n", "1", "-w", "200", ip],
                           capture_output=True, timeout=2)
        else:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True, timeout=2)
    except Exception:
        pass


def _ping_sweep(subnet: str) -> None:
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        ex.map(_ping, ips)


# ── ARP table parsing ─────────────────────────────────────────────────────

_IP_RE  = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})")


def _parse_arp_windows(stdout: str, subnet: str) -> list[dict]:
    entries = []
    current_iface_ip = None
    for line in stdout.splitlines():
        iface = re.match(r"Interface:\s+([\d\.]+)", line)
        if iface:
            current_iface_ip = iface.group(1)
            continue
        if not current_iface_ip or not current_iface_ip.startswith(subnet.rsplit(".", 1)[0]):
            continue
        ip_m  = _IP_RE.search(line)
        mac_m = _MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        ip  = ip_m.group(1)
        mac = mac_m.group(1).replace("-", ":").lower()
        if (ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239.")
                or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
                or mac.startswith("01:00:5e")):
            continue
        entries.append({"ip": ip, "mac": mac, "vendor": _vendor_from_mac(mac)})
    return entries


def _parse_arp_unix(stdout: str) -> list[dict]:
    """
    Parse macOS/Linux `arp -a` output.
    macOS format:  hostname (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    Linux format:  hostname (192.168.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
    """
    entries = []
    for line in stdout.splitlines():
        ip_m  = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
        mac_m = _MAC_RE.search(line)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
            continue
        if not mac_m or mac_m.group(1).lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        mac = mac_m.group(1).lower()
        entries.append({"ip": ip, "mac": mac, "vendor": _vendor_from_mac(mac)})
    return entries


def _run_arp_scan() -> list[dict]:
    subnet = _detect_lan_subnet()
    logger.info("Running ping sweep to populate ARP cache (subnet %s.x)...", subnet)
    _ping_sweep(subnet)
    logger.info("Ping sweep done, reading ARP table...")
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=15)
        if _SYSTEM == "Windows":
            entries = _parse_arp_windows(r.stdout, subnet)
        else:
            entries = _parse_arp_unix(r.stdout)
        # Deduplicate by IP
        seen: dict[str, dict] = {}
        for e in entries:
            seen[e["ip"]] = e
        return list(seen.values())
    except Exception as exc:
        logger.warning("ARP scan failed: %s", exc)
        return []


def _post_arp_enrichment(arp_table: list[dict]) -> None:
    if not config.agent_id or not arp_table:
        return
    try:
        import json as _json
        import urllib.request
        url     = f"{config.backend_url}/api/network-scan/arp-enrich"
        payload = _json.dumps({
            "tenant_id": config.tenant_id,
            "agent_id":  config.agent_id,
            "arp_table": arp_table,
        }).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key":    config.api_key or "",
                "X-Tenant-Id":  config.tenant_id,
                "X-Agent-Id":   config.agent_id,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = _json.loads(resp.read())
            logger.info("ARP enrichment: sent %d entries, backend updated %d assets",
                        len(arp_table), result.get("updated", 0))
            agent_state["last_arp_run"]   = int(time.time())
            agent_state["last_arp_count"] = result.get("updated", 0)
    except Exception as exc:
        logger.warning("ARP enrichment POST failed: %s", exc)


def arp_loop() -> None:
    """Run ARP scan every 5 minutes and send MAC table to backend."""
    time.sleep(30)
    while True:
        try:
            if config.agent_id:
                logger.info("Running ARP scan on LAN...")
                arp_table = _run_arp_scan()
                if arp_table:
                    logger.info("ARP found %d real LAN devices", len(arp_table))
                    _post_arp_enrichment(arp_table)
                else:
                    logger.warning("ARP scan returned no entries")
        except Exception as exc:
            logger.exception("ARP loop error: %s", exc)
        time.sleep(300)


# ── Enrollment ────────────────────────────────────────────────────────────

def enroll_if_needed() -> None:
    if config.agent_id:
        agent_state["registered"] = True
        return
    if not config.enrollment_token:
        logger.warning("No agent_id and no enrollment token — local-only mode.")
        return
    try:
        result = backend.enroll(
            tenant_id=config.tenant_id,
            enrollment_token=config.enrollment_token,
            hostname=config.hostname_override or socket.gethostname(),
        )
        config.agent_id             = result.get("agent_id")
        agent_state["agent_id"]     = config.agent_id
        agent_state["registered"]   = True
        agent_state["last_policy"]  = result.get("policy", {})
        logger.info("Enrollment successful: agent_id=%s", config.agent_id)
    except Exception as exc:
        logger.exception("Enrollment failed: %s", exc)
        agent_state["last_error"] = str(exc)


# ── Command loop ──────────────────────────────────────────────────────────

def command_loop() -> None:
    while True:
        try:
            if config.agent_id:
                pol = backend.fetch_policy(config.tenant_id, config.agent_id)
                agent_state["last_policy"] = pol
                polled = backend.fetch_commands(config.tenant_id, config.agent_id)
                agent_state["last_command_poll"] = int(time.time())
                poll_interval = polled.get(
                    "suggested_poll_interval_seconds",
                    config.command_poll_interval_seconds,
                )
                for command in polled.get("commands", []):
                    command_id = command["command_id"]
                    mode = command.get("arguments", {}).get(
                        "scan_mode", command.get("command_type", "full")
                    )
                    started = int(time.time())
                    backend.ack_command(config.tenant_id, config.agent_id, command_id, started)
                    try:
                        with _cycle_lock:
                            result = run_cycle(config, backend, queue, mode=mode)
                        finished = int(time.time())
                        backend.complete_command(
                            config.tenant_id, config.agent_id, command_id,
                            status="completed", started_epoch=started,
                            completed_epoch=finished, result=result,
                        )
                        agent_state["last_command_result"] = {"command_id": command_id, "result": result}
                        agent_state["last_run"]   = finished
                        agent_state["last_error"] = None
                    except Exception as cmd_exc:
                        finished = int(time.time())
                        backend.complete_command(
                            config.tenant_id, config.agent_id, command_id,
                            status="failed", started_epoch=started,
                            completed_epoch=finished, result={"error": str(cmd_exc)},
                        )
                        agent_state["last_error"] = str(cmd_exc)
                time.sleep(poll_interval)
            else:
                time.sleep(config.command_poll_interval_seconds)
        except Exception as exc:
            logger.exception("Command loop failed: %s", exc)
            agent_state["last_error"] = str(exc)
            time.sleep(config.command_poll_interval_seconds)


# ── Periodic loop ─────────────────────────────────────────────────────────

def periodic_loop() -> None:
    """
    Runs the full collection cycle every poll_interval_seconds.
    This was missing from the original startup — caused last_run to never populate.
    """
    # Stagger first run by 60 s to allow enrollment to complete
    time.sleep(60)
    while True:
        try:
            enroll_if_needed()
            if config.agent_id:
                agent_state["last_policy"] = backend.fetch_policy(
                    config.tenant_id, config.agent_id
                )
            acquired = _cycle_lock.acquire(blocking=False)
            if acquired:
                try:
                    summary = run_cycle(config, backend, queue, mode="full")
                    agent_state["last_run"]            = int(time.time())
                    agent_state["last_error"]          = None
                    agent_state["last_command_result"] = {"command_id": None, "result": summary}
                finally:
                    _cycle_lock.release()
            else:
                logger.debug("Periodic scan skipped — command scan in progress.")
        except Exception as exc:
            logger.exception("Agent cycle failed: %s", exc)
            agent_state["last_error"] = str(exc)
        time.sleep(config.poll_interval_seconds)


# ── Event Log Ingestion ───────────────────────────────────────────────────

def event_log_loop() -> None:
    """
    Reads Windows Security Event Log every 5 minutes and POSTs events
    to /api/ai/ingest/windows. Only active on Windows.
    Tracks last_ingest_epoch so only new events are sent each cycle.
    """
    import json as _json
    import urllib.request

    if _SYSTEM != "Windows":
        logger.info("Event log ingestion skipped — not Windows (platform=%s)", _SYSTEM)
        return

    try:
        from collectors.windows.event_log import collect_security_events, filter_new_events
    except ImportError as exc:
        logger.warning("Event log collector unavailable: %s", exc)
        return

    log_interval = int(__import__("os").getenv("CYBERASSETIQ_LOG_INGEST_INTERVAL", "300"))
    max_events   = int(__import__("os").getenv("CYBERASSETIQ_LOG_INGEST_MAX_EVENTS", "100"))
    enabled      = __import__("os").getenv("CYBERASSETIQ_LOG_INGEST_ENABLED", "true").lower() == "true"

    if not enabled:
        logger.info("Event log ingestion disabled via CYBERASSETIQ_LOG_INGEST_ENABLED=false")
        return

    time.sleep(60)  # wait for enrollment to complete first
    last_ingest_epoch = int(time.time()) - log_interval

    logger.info("Event log ingestion loop started — interval=%ds max_events=%d", log_interval, max_events)

    while True:
        try:
            if not config.agent_id:
                time.sleep(30)
                continue

            all_events = collect_security_events(max_events=max_events)
            new_events  = filter_new_events(all_events, since_epoch=last_ingest_epoch)

            if new_events:
                logger.info("Event log: sending %d new event(s) to AI ingest", len(new_events))
                url     = f"{config.backend_url}/api/ai/ingest/windows"
                payload = _json.dumps({"events": new_events}).encode()
                req = urllib.request.Request(
                    url, data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-API-Key":    config.api_key or "",
                        "X-Tenant-Id":  config.tenant_id,
                        "X-Agent-Id":   config.agent_id,
                    },
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        result = _json.loads(resp.read())
                        agent_state["last_log_ingest_count"] = result.get("events_ingested", 0)
                        agent_state["last_log_ingest_epoch"] = int(time.time())
                        logger.info(
                            "Event log ingest: %d ingested, %d alert(s) created",
                            result.get("events_ingested", 0),
                            result.get("alerts_created", 0),
                        )
                except Exception as post_exc:
                    logger.warning("Event log POST failed: %s", post_exc)
            else:
                logger.debug("Event log: no new events since last cycle")

            last_ingest_epoch = int(time.time())

        except Exception as exc:
            logger.exception("Event log loop error: %s", exc)

        time.sleep(log_interval)


# ── Startup ───────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup_event() -> None:
    enroll_if_needed()
    threading.Thread(target=command_loop,   daemon=True, name="command-loop").start()
    threading.Thread(target=arp_loop,       daemon=True, name="arp-loop").start()
    threading.Thread(target=periodic_loop,  daemon=True, name="periodic-loop").start()
    threading.Thread(target=event_log_loop, daemon=True, name="event-log-loop").start()


# ── Endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":              "ok",
        "agent_id":            agent_state["agent_id"],
        "registered":          agent_state["registered"],
        "last_run":            agent_state["last_run"],
        "last_error":          agent_state["last_error"],
        "last_command_poll":   agent_state["last_command_poll"],
        "last_command_result": agent_state["last_command_result"],
        "last_arp_run":          agent_state["last_arp_run"],
        "last_arp_count":        agent_state["last_arp_count"],
        "last_log_ingest_epoch": agent_state["last_log_ingest_epoch"],
        "last_log_ingest_count": agent_state["last_log_ingest_count"],
        "platform":              _SYSTEM,
    }


@app.post("/flush")
def manual_flush():
    try:
        flush_queue(queue, backend)
        return {"status": "flushed"}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@app.post("/run-scan")
def local_run_scan(mode: str = "full"):
    with _cycle_lock:
        result = run_cycle(config, backend, queue, mode=mode)
    agent_state["last_run"]            = int(time.time())
    agent_state["last_command_result"] = {"command_id": "manual", "result": result}
    return {"status": "ok", "result": result}


@app.post("/run-arp")
def manual_arp_scan():
    try:
        arp_table = _run_arp_scan()
        if arp_table:
            _post_arp_enrichment(arp_table)
        return {"status": "ok", "entries": len(arp_table), "sample": arp_table[:10]}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
