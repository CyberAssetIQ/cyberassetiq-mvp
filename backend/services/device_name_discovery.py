from __future__ import annotations

"""
CyberAssetIQ — Device Name Discovery Engine
============================================
Implements the same device name resolution techniques used by
Qualys, Rapid7 Nexpose, and Tenable Nessus — all without credentials.

Techniques (in priority order):
  1. NetBIOS NBNS (UDP 137)  — Windows/Samba computer names + workgroup
  2. LLMNR (UDP 5355)        — Windows Vista+ link-local name resolution
  3. mDNS/Bonjour (UDP 5353) — Apple, Linux, Android, IoT friendly names
  4. UPnP friendlyName       — Smart TVs, routers, printers, IoT
  5. SNMP sysName            — Network devices, routers, switches
  6. SSH banner              — Linux/macOS hostname in banner
  7. HTTP device name        — Routers/NAS web interfaces
  8. Reverse DNS             — PTR record fallback

Each function returns a dict:
  {
    "name":       str | None,   # device friendly name
    "source":     str,          # which technique found it
    "confidence": int,          # 0-100 (higher = more reliable)
    "extra":      dict,         # additional metadata (workgroup, model, etc.)
  }
"""

import re
import socket
import struct
import logging
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────

TIMEOUT = 2.0      # seconds per probe
MAX_WORKERS = 32   # concurrent probes


# ═════════════════════════════════════════════════════════════════════════
# 1. NetBIOS NBNS — UDP 137
#    Same as Qualys plugin / Nessus plugin 10150
#    Returns computer name + workgroup/domain
# ═════════════════════════════════════════════════════════════════════════

def _nbns_query(ip: str) -> dict | None:
    """
    Send a NetBIOS Name Service status request (NBSTAT) to UDP 137.
    Works on Windows, Samba, NAS devices, some printers.
    Returns computer name + workgroup if found.
    """
    # NBSTAT request packet — same format Nessus/Rapid7 use
    NBSTAT_REQUEST = (
        b"\x82\x28"   # Transaction ID
        b"\x00\x00"   # Flags: query
        b"\x00\x01"   # Questions: 1
        b"\x00\x00"   # Answers: 0
        b"\x00\x00"   # Authority: 0
        b"\x00\x00"   # Additional: 0
        b"\x20"       # Name length
        # Encoded "*" (wildcard) in NetBIOS format
        b"\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x00"       # Null terminator
        b"\x00\x21"   # Type: NBSTAT
        b"\x00\x01"   # Class: IN
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(NBSTAT_REQUEST, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
    except Exception:
        return None

    if len(data) < 57:
        return None

    try:
        # Parse NetBIOS response
        num_names = data[56]
        names = []
        offset = 57
        computer_name = None
        workgroup = None

        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset:offset+15].decode("ascii", errors="replace").rstrip()
            name_type = data[offset+15]
            flags = struct.unpack(">H", data[offset+16:offset+18])[0]
            offset += 18

            # Name type 0x00 = workstation name (computer name)
            # Name type 0x20 = server service
            # Name type 0x00 with GROUP flag = workgroup/domain
            is_group = bool(flags & 0x8000)
            clean_name = re.sub(r"[^\x20-\x7e]", "", raw_name).strip()

            if not clean_name:
                continue

            if not is_group and name_type in (0x00, 0x20):
                if not computer_name:
                    computer_name = clean_name
            elif is_group and name_type == 0x00:
                workgroup = clean_name

            names.append({
                "name": clean_name,
                "type": name_type,
                "is_group": is_group,
            })

        if computer_name:
            return {
                "name":       computer_name,
                "source":     "NetBIOS/NBNS",
                "confidence": 92,
                "extra":      {
                    "workgroup": workgroup,
                    "all_names": names,
                    "protocol":  "NBNS UDP/137",
                },
            }
    except Exception as exc:
        logger.debug("NBNS parse error for %s: %s", ip, exc)

    return None


# ═════════════════════════════════════════════════════════════════════════
# 2. LLMNR — UDP 5355
#    Link-Local Multicast Name Resolution — Windows Vista+
#    Send multicast query to get name of device
# ═════════════════════════════════════════════════════════════════════════

def _llmnr_query(ip: str) -> dict | None:
    """
    Send an LLMNR query to UDP 5355 (unicast to the specific IP).
    Windows Vista+ responds with its hostname.
    Same technique used by Rapid7 Nexpose plugin 11011.
    """
    # Build LLMNR query for the reverse PTR name
    # e.g. 192.168.0.100 → 100.0.168.192.in-addr.arpa
    parts = ip.split(".")
    rev = ".".join(reversed(parts)) + ".in-addr.arpa"

    # LLMNR packet structure
    transaction_id = b"\x00\x01"
    flags          = b"\x00\x00"   # Standard query
    qdcount        = b"\x00\x01"   # 1 question
    ancount        = b"\x00\x00"
    nscount        = b"\x00\x00"
    arcount        = b"\x00\x00"

    # Encode query name
    qname = b""
    for part in rev.split("."):
        encoded = part.encode("ascii")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"
    qtype  = b"\x00\x0c"   # PTR
    qclass = b"\x00\x01"   # IN

    packet = transaction_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (ip, 5355))
        data, _ = sock.recvfrom(512)
        sock.close()

        if len(data) > 12 and data[6:8] != b"\x00\x00":
            # Has answers — try to parse the name
            # Simple heuristic: look for printable ASCII hostname after answer section
            payload = data[12:].decode("ascii", errors="replace")
            m = re.search(r"([A-Za-z0-9][-A-Za-z0-9]{2,30})", payload)
            if m:
                return {
                    "name":       m.group(1).strip(),
                    "source":     "LLMNR",
                    "confidence": 75,
                    "extra":      {"protocol": "LLMNR UDP/5355"},
                }
    except Exception:
        pass

    return None


# ═════════════════════════════════════════════════════════════════════════
# 3. mDNS / Bonjour — UDP 5353
#    Apple, Linux (Avahi), Android, Chromecast, smart speakers, IoT
#    Each device announces its .local name + service type
# ═════════════════════════════════════════════════════════════════════════

def _mdns_unicast_query(ip: str) -> dict | None:
    """
    Send a unicast mDNS PTR query to UDP 5353 on the target IP.
    Qualys and Nessus both use this to discover Bonjour/Avahi names.
    Works on: Macs, iPhones, Raspberry Pi, Chromecasts, smart TVs,
              Google Home, Amazon Echo (some), Linux with Avahi.
    """
    parts = ip.split(".")
    rev   = ".".join(reversed(parts)) + ".in-addr.arpa"

    # mDNS PTR query packet
    header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname  = b""
    for part in rev.split("."):
        enc = part.encode("ascii")
        qname += bytes([len(enc)]) + enc
    qname += b"\x00\x00\x0c\x00\x01"  # PTR, class IN

    packet = header + qname

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 12:
            # Parse answer section for PTR record (device .local name)
            raw = data[12:].decode("latin-1", errors="replace")
            # Look for .local names
            m = re.search(r"([A-Za-z0-9][-A-Za-z0-9_ ]{2,40})\.local", raw)
            if m:
                device_name = m.group(1).replace("\\x00", "").strip()
                if device_name:
                    return {
                        "name":       device_name,
                        "source":     "mDNS/Bonjour",
                        "confidence": 85,
                        "extra":      {
                            "fqdn":     f"{device_name}.local",
                            "protocol": "mDNS UDP/5353",
                        },
                    }
    except Exception:
        pass

    return None


# ═════════════════════════════════════════════════════════════════════════
# 4. UPnP / SSDP — HTTP on port 1900 / device description XML
#    Smart TVs, routers, NAS, printers, media players, IP cameras
#    Returns friendlyName, manufacturer, modelName from device XML
# ═════════════════════════════════════════════════════════════════════════

def _upnp_device_name(ip: str) -> dict | None:
    """
    Query UPnP device description XML to get friendly name and model.
    Qualys uses this for IoT and smart device identification.
    Works on: routers, NAS, smart TVs, printers, IP cameras, media servers.
    """
    # Try common UPnP description URLs
    urls = [
        f"http://{ip}:1900/",
        f"http://{ip}:49152/description.xml",
        f"http://{ip}:49153/description.xml",
        f"http://{ip}:5000/description.xml",
        f"http://{ip}/description.xml",
        f"http://{ip}/upnp/description.xml",
        f"http://{ip}:8080/description.xml",
    ]

    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberAssetIQ/2.4"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                xml_data = resp.read(8192).decode("utf-8", errors="replace")

            # Parse UPnP device XML
            root = ET.fromstring(xml_data)
            ns   = {"upnp": "urn:schemas-upnp-org:device-1-0"}

            # Try with namespace first, then without
            friendly_name = (
                root.findtext(".//upnp:friendlyName", namespaces=ns) or
                root.findtext(".//{urn:schemas-upnp-org:device-1-0}friendlyName") or
                root.findtext(".//friendlyName")
            )
            manufacturer = (
                root.findtext(".//upnp:manufacturer", namespaces=ns) or
                root.findtext(".//manufacturer")
            )
            model = (
                root.findtext(".//upnp:modelName", namespaces=ns) or
                root.findtext(".//modelName")
            )
            model_number = (
                root.findtext(".//upnp:modelNumber", namespaces=ns) or
                root.findtext(".//modelNumber")
            )

            if friendly_name:
                return {
                    "name":       friendly_name.strip(),
                    "source":     "UPnP/SSDP",
                    "confidence": 88,
                    "extra":      {
                        "manufacturer": manufacturer,
                        "model":        model,
                        "model_number": model_number,
                        "url":          url,
                        "protocol":     "UPnP HTTP",
                    },
                }
        except Exception:
            continue

    return None


# ═════════════════════════════════════════════════════════════════════════
# 5. SNMP sysName — UDP 161
#    Network devices, routers, switches, printers, some servers
# ═════════════════════════════════════════════════════════════════════════

def _snmp_sysname(ip: str) -> dict | None:
    """
    Query SNMP sysName (OID 1.3.6.1.2.1.1.5.0) via SNMPv1 GET.
    Same OID used by Qualys, Nessus, and Rapid7 for device identification.
    Works with community string "public" (most network devices default).
    """
    # SNMPv1 GET request for sysName OID
    # Built manually to avoid requiring pysnmp dependency
    def encode_oid(oid_str: str) -> bytes:
        parts = [int(x) for x in oid_str.split(".")]
        # First two components encoded as 40*x + y
        encoded = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p < 128:
                encoded += bytes([p])
            else:
                # Multi-byte encoding
                result = []
                while p:
                    result.append(p & 0x7f)
                    p >>= 7
                result.reverse()
                for i, b in enumerate(result):
                    if i < len(result) - 1:
                        encoded += bytes([b | 0x80])
                    else:
                        encoded += bytes([b])
        return encoded

    def tlv(tag: int, value: bytes) -> bytes:
        length = len(value)
        if length < 128:
            return bytes([tag, length]) + value
        elif length < 256:
            return bytes([tag, 0x81, length]) + value
        else:
            return bytes([tag, 0x82, (length >> 8) & 0xff, length & 0xff]) + value

    try:
        # OID: sysName = 1.3.6.1.2.1.1.5.0
        oid_bytes  = encode_oid("1.3.6.1.2.1.1.5.0")
        oid_tlv    = tlv(0x06, oid_bytes)
        null_tlv   = b"\x05\x00"
        varbind    = tlv(0x30, oid_tlv + null_tlv)
        varbindlist= tlv(0x30, varbind)

        community  = tlv(0x04, b"public")
        version    = tlv(0x02, b"\x00")     # SNMPv1
        request_id = tlv(0x02, b"\x00\x01")
        error_status    = tlv(0x02, b"\x00")
        error_index     = tlv(0x02, b"\x00")

        get_request = tlv(0xa0,
            request_id + error_status + error_index + varbindlist)

        packet = tlv(0x30, version + community + get_request)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(packet, (ip, 161))
        data, _ = sock.recvfrom(1024)
        sock.close()

        # Extract string value from response — find OctetString after the OID
        # Simple approach: find the sysName OID bytes and read what follows
        if b"\x04" in data[30:]:
            # Look for OctetString tag after response section
            idx = data.find(b"\x04", 40)
            while idx != -1 and idx + 2 < len(data):
                length = data[idx + 1]
                if 2 <= length <= 64:
                    value = data[idx + 2: idx + 2 + length].decode("ascii", errors="replace")
                    if re.match(r"^[A-Za-z0-9][-A-Za-z0-9_.]{1,63}$", value):
                        return {
                            "name":       value,
                            "source":     "SNMP sysName",
                            "confidence": 90,
                            "extra":      {
                                "community": "public",
                                "oid":       "1.3.6.1.2.1.1.5.0",
                                "protocol":  "SNMP UDP/161",
                            },
                        }
                idx = data.find(b"\x04", idx + 1)
    except Exception:
        pass

    return None


# ═════════════════════════════════════════════════════════════════════════
# 6. SSH Banner — TCP 22
#    Linux/macOS/network device hostname often in SSH banner
# ═════════════════════════════════════════════════════════════════════════

def _ssh_banner_name(ip: str) -> dict | None:
    """
    Connect to SSH port and parse the banner for hostname hints.
    Rapid7 uses this to supplement NetBIOS/mDNS discovery.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, 22))
        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        sock.close()

        # SSH banners like: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        # or: SSH-2.0-OpenSSH_8.4 raspberrypi
        # Look for hostname pattern after OS/version info
        m = re.search(
            r"SSH-\d\.\d-\S+\s+(.{3,32})",
            banner
        )
        if m:
            extra_info = m.group(1).strip()
            # Filter out generic strings like "Ubuntu", "Debian" etc
            if not re.match(r"^(Ubuntu|Debian|CentOS|RHEL|Fedora|Alpine)[\s-]", extra_info):
                return {
                    "name":       extra_info,
                    "source":     "SSH Banner",
                    "confidence": 55,
                    "extra":      {
                        "banner":   banner[:120],
                        "protocol": "SSH TCP/22",
                    },
                }

        # Even if no extra name, extract OS from banner
        if "Ubuntu" in banner or "Debian" in banner or "Linux" in banner:
            return None   # OS info only — not a name

    except Exception:
        pass

    return None


# ═════════════════════════════════════════════════════════════════════════
# 7. HTTP Device Name — Port 80/443/8080
#    Routers, NAS, printers, cameras often expose device name in HTTP
# ═════════════════════════════════════════════════════════════════════════

def _http_device_name(ip: str) -> dict | None:
    """
    Parse HTTP response for device name hints.
    Checks: page title, Server header, X-Device-Name header,
    common router/NAS admin page patterns.
    """
    for port, use_ssl in [(80, False), (8080, False), (443, True), (8443, True)]:
        scheme = "https" if use_ssl else "http"
        try:
            req = urllib.request.Request(
                f"{scheme}://{ip}:{port}/",
                headers={
                    "User-Agent":    "CyberAssetIQ/2.4",
                    "Accept":        "text/html,application/xhtml+xml",
                    "Cache-Control": "no-cache",
                },
            )
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=2, context=ctx if use_ssl else None) as resp:
                headers = dict(resp.headers)
                html = resp.read(4096).decode("utf-8", errors="replace")

            # Check Server header for device model
            server = headers.get("Server", "")
            x_device = headers.get("X-Device-Name", "") or headers.get("X-Model", "")

            if x_device:
                return {
                    "name":       x_device.strip(),
                    "source":     "HTTP Header",
                    "confidence": 80,
                    "extra":      {"server": server, "protocol": f"HTTP {port}"},
                }

            # Parse page title
            m = re.search(r"<title[^>]*>([^<]{3,60})</title>", html, re.I)
            if m:
                title = m.group(1).strip()
                # Filter out generic titles
                generic = {"login","home","welcome","index","admin","dashboard",
                           "router","gateway","status","web interface","management"}
                title_lower = title.lower()
                if not any(g == title_lower for g in generic) and len(title) > 3:
                    # Check for device-specific patterns
                    device_patterns = [
                        r"(TP-Link\s+\S+)",
                        r"(Netgear\s+\S+)",
                        r"(ASUS\s+\S+)",
                        r"(Synology\s+\S+)",
                        r"(QNAP\s+\S+)",
                        r"(Ubiquiti\s+\S+)",
                        r"(UniFi\s+\S+)",
                        r"(Hikvision\s+\S+)",
                        r"(Dahua\s+\S+)",
                        r"(Canon\s+\S+)",
                        r"(HP\s+\S+)",
                        r"(Epson\s+\S+)",
                        r"(Brother\s+\S+)",
                        r"(FRITZ!Box\s+\S+)",
                        r"(Raspberry\s+Pi)",
                        r"([A-Z][a-z]+[A-Z][a-zA-Z]+)",  # CamelCase device names
                    ]
                    for pat in device_patterns:
                        dm = re.search(pat, title, re.I)
                        if dm:
                            return {
                                "name":       dm.group(1),
                                "source":     "HTTP Title",
                                "confidence": 72,
                                "extra":      {
                                    "full_title": title,
                                    "server":     server,
                                    "protocol":   f"HTTP {port}",
                                },
                            }

                    # Check if title looks like a hostname/device name
                    if re.match(r"^[A-Za-z0-9][-A-Za-z0-9_.]{3,30}$", title):
                        return {
                            "name":       title,
                            "source":     "HTTP Title",
                            "confidence": 60,
                            "extra":      {
                                "server":   server,
                                "protocol": f"HTTP {port}",
                            },
                        }

        except Exception:
            continue

    return None


# ═════════════════════════════════════════════════════════════════════════
# 8. Reverse DNS PTR
#    Last resort — often set by DHCP server or admin
# ═════════════════════════════════════════════════════════════════════════

def _reverse_dns_name(ip: str) -> dict | None:
    """
    Reverse DNS PTR lookup — last resort, same as all scanners use.
    Confidence is lower because PTR records can be stale.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            # Strip .local suffix for cleaner display
            name = hostname.replace(".local", "").split(".")[0]
            if len(name) > 2:
                return {
                    "name":       name,
                    "source":     "Reverse DNS",
                    "confidence": 50,
                    "extra":      {
                        "fqdn":     hostname,
                        "protocol": "DNS PTR",
                    },
                }
    except Exception:
        pass
    return None


# ═════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR — runs all probes concurrently, picks best result
# ═════════════════════════════════════════════════════════════════════════

def discover_device_name(ip: str) -> dict[str, Any]:
    """
    Run all device name discovery probes concurrently for a single IP.
    Returns the highest-confidence result plus all others as fallbacks.

    This mirrors the Qualys/Rapid7/Nessus approach:
    - NetBIOS first (most reliable for Windows)
    - mDNS/Bonjour for Apple/Linux/IoT
    - LLMNR for Windows Vista+
    - UPnP for smart devices
    - SNMP for network gear
    - HTTP/SSH as fallbacks

    Returns:
        {
            "ip":          str,
            "name":        str | None,     # best name found
            "source":      str | None,     # which protocol found it
            "confidence":  int,            # 0-100
            "all_results": list[dict],     # all probes that returned data
            "extra":       dict,           # extra data from winning probe
        }
    """
    probes = [
        ("nbns",     _nbns_query),
        ("mdns",     _mdns_unicast_query),
        ("llmnr",    _llmnr_query),
        ("upnp",     _upnp_device_name),
        ("snmp",     _snmp_sysname),
        ("ssh",      _ssh_banner_name),
        ("http",     _http_device_name),
        ("rdns",     _reverse_dns_name),
    ]

    results = []

    with ThreadPoolExecutor(max_workers=len(probes)) as ex:
        futures = {ex.submit(fn, ip): name for name, fn in probes}
        for future in as_completed(futures, timeout=TIMEOUT + 1):
            try:
                result = future.result(timeout=0.1)
                if result:
                    results.append(result)
            except Exception:
                pass

    if not results:
        return {
            "ip":         ip,
            "name":       None,
            "source":     None,
            "confidence": 0,
            "all_results": [],
            "extra":      {},
        }

    # Pick highest confidence result
    best = max(results, key=lambda r: r["confidence"])

    return {
        "ip":          ip,
        "name":        best["name"],
        "source":      best["source"],
        "confidence":  best["confidence"],
        "all_results": sorted(results, key=lambda r: -r["confidence"]),
        "extra":       best.get("extra", {}),
    }


def batch_discover_device_names(
    ips: list[str],
    max_workers: int = MAX_WORKERS,
) -> dict[str, dict]:
    """
    Discover device names for a list of IPs concurrently.
    Returns dict: {ip: discovery_result}

    This is called by the network scan service after the nmap phase
    to enrich any devices with blank hostnames.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(discover_device_name, ip): ip for ip in ips}
        for future in as_completed(futures, timeout=30):
            ip = futures[future]
            try:
                results[ip] = future.result(timeout=1)
            except Exception as exc:
                logger.debug("Device name discovery failed for %s: %s", ip, exc)
                results[ip] = {
                    "ip": ip, "name": None, "source": None,
                    "confidence": 0, "all_results": [], "extra": {}
                }
    return results
