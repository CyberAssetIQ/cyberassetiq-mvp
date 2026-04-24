from __future__ import annotations
import re, sys
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        print(f"[WARN] Pattern not found for {label}")
        return text
    return text.replace(old, new, 1)


def replace_regex(text: str, pattern: str, repl: str, label: str, flags=re.DOTALL) -> str:
    new_text, n = re.subn(pattern, repl, text, count=1, flags=flags)
    if n == 0:
        print(f"[WARN] Regex not found for {label}")
        return text
    return new_text


def patch_index(root: Path):
    path = root / "backend" / "static" / "index.html"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}")
    text = path.read_text(encoding="utf-8")

    pattern_launch = r'<div style="display:flex;gap:10px;align-items:flex-end[^\"]*">[\s\S]*?<button class="btn(?: primary)?" onclick="(?:reclassifyNetworkAssets|reclassifyAssets)\(\)"[^>]*>[\s\S]*?</button>\s*</div>\s*</div>\s*</div>'
    replacement_launch = '''<div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
            <div style="flex:1;min-width:260px">
              <label class="form-label">Target Subnet</label>
              <input class="form-input" id="netSubnet" value="192.168.0.0/24" placeholder="e.g. 192.168.0.0/24">
            </div>
            <button class="btn primary" onclick="startNetworkScan()" style="height:36px;flex-shrink:0">▶ Start Scan</button>
            <button class="btn" onclick="resolveNetworkHostnames()" style="height:36px;flex-shrink:0">🧭 Resolve Hostnames</button>
            <button class="btn" onclick="reclassifyNetworkAssets()" style="height:36px;flex-shrink:0">⚡ Reclassify Assets</button>
          </div>
        </div>
      </div>'''
    text = replace_regex(text, pattern_launch, replacement_launch, "network launch dedupe")

    if "function cleanupNetworkUiState()" not in text:
        old = "let _netPollTimer = null;\n\nfunction loadNetworkPage() {\n  loadNetworkJobs();\n  loadNetworkAssets();\n}\n"
        new = """let _netPollTimer = null;\n\nfunction cleanupNetworkUiState() {\n  if (_netPollTimer) {\n    clearInterval(_netPollTimer);\n    _netPollTimer = null;\n  }\n  const box = document.getElementById('netProgressBox');\n  if (box) box.style.display = 'none';\n}\n\nfunction loadNetworkPage() {\n  loadNetworkJobs();\n  loadNetworkAssets();\n}\n"""
        text = replace_once(text, old, new, "cleanup helper")

    old_nav = "function navigate(page) {\n  if (!page) page = 'dashboard';\n  currentPage = page;\n"
    new_nav = "function navigate(page) {\n  if (!page) page = 'dashboard';\n  if (page !== 'network') cleanupNetworkUiState();\n  currentPage = page;\n"
    text = replace_once(text, old_nav, new_nav, "navigate cleanup")

    pattern_summary = r'function summariseNetworkAssets\(items\) \{[\s\S]*?return summary;\n\}'
    replacement_summary = """function summariseNetworkAssets(items) {\n  const summary = {\n    total: items.length,\n    rogue: 0,\n    managed: 0,\n    critical: 0,\n    high: 0,\n    medium: 0,\n    low: 0,\n    openPorts: 0,\n    services: 0,\n    confirmed: 0,\n    likely: 0,\n    observed: 0,\n    mobile_iot: 0,\n  };\n  items.forEach(a => {\n    if (a.is_rogue) summary.rogue += 1;\n    if (a.managed || a.agent_installed) summary.managed += 1;\n    const level = String(a.risk_level || a.risk_hint || '').toLowerCase();\n    if (level === 'critical') summary.critical += 1;\n    else if (level === 'high') summary.high += 1;\n    else if (level === 'medium') summary.medium += 1;\n    else if (level === 'low') summary.low += 1;\n    summary.openPorts += normaliseOpenPorts(a.open_ports).length;\n    summary.services += Array.isArray(a.services) ? a.services.length : 0;\n\n    const conf = String(a.asset_confidence || '').toLowerCase();\n    if (conf === 'confirmed_asset') summary.confirmed += 1;\n    else if (conf === 'likely_asset') summary.likely += 1;\n    else if (conf === 'observed_host') summary.observed += 1;\n\n    const family = String(a.device_family || a.device_type || '').toLowerCase();\n    const vendor = String(a.vendor || '').toLowerCase();\n    if (\n      family.includes('mobile') || family.includes('iot') || family.includes('tv') ||\n      family.includes('smart') || family.includes('wearable') || family.includes('consumer') ||\n      vendor.includes('murata') || vendor.includes('roku') || vendor.includes('sonos') ||\n      vendor.includes('apple') || vendor.includes('samsung') || vendor.includes('google') ||\n      vendor.includes('amazon')\n    ) {\n      summary.mobile_iot += 1;\n    }\n  });\n  return summary;\n}"""
    text = replace_regex(text, pattern_summary, replacement_summary, "network summary counts")

    pattern_summary_html = r'const summaryHtml = `[\s\S]*?</div>`;'
    replacement_summary_html = """const summaryHtml = `<div style=\"display:grid;grid-template-columns:repeat(9,minmax(110px,1fr));gap:10px;padding:14px 16px;border-bottom:1px solid var(--border);background:rgba(255,255,255,0.02)\">\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Assets</div><div style=\"font-size:22px;font-weight:700;color:var(--white)\">${summary.total ?? d.length}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Managed</div><div style=\"font-size:22px;font-weight:700;color:var(--green)\">${summary.managed ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Rogue</div><div style=\"font-size:22px;font-weight:700;color:var(--red)\">${summary.rogue ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Critical</div><div style=\"font-size:22px;font-weight:700;color:var(--red)\">${summary.critical ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">High</div><div style=\"font-size:22px;font-weight:700;color:var(--orange)\">${summary.high ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Open Ports</div><div style=\"font-size:22px;font-weight:700;color:var(--teal)\">${summary.open_ports ?? summary.openPorts ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Confirmed</div><div style=\"font-size:22px;font-weight:700;color:var(--white)\">${summary.confirmed ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Likely</div><div style=\"font-size:22px;font-weight:700;color:var(--yellow)\">${summary.likely ?? 0}</div></div>\n      <div><div style=\"font-size:10px;color:var(--text-dim);text-transform:uppercase\">Mobile / IoT</div><div style=\"font-size:22px;font-weight:700;color:var(--teal)\">${summary.mobile_iot ?? 0}</div></div>\n    </div>`;"""
    text = replace_regex(text, pattern_summary_html, replacement_summary_html, "summary html")

    pattern_scan = r'async function startNetworkScan\(\) \{[\s\S]*?\n\}'
    replacement_scan = """async function startNetworkScan() {\n  const subnet = document.getElementById('netSubnet').value.trim() || '192.168.0.0/24';\n  toast('Starting network scan on ' + subnet + '…', 'info');\n  const r = await api('POST', '/api/network-scan/jobs', { tenant_id: TENANT||'tenant-001', target: subnet, requested_by: 'dashboard' });\n  if (!r) { toast('Failed to start scan — check backend is running', 'error'); return; }\n  const jobId = r.job_id || r.id;\n  toast('Scan started · job_id: ' + jobId, 'success');\n  const box = document.getElementById('netProgressBox');\n  if (currentPage === 'network' && box) box.style.display = 'block';\n  clearInterval(_netPollTimer);\n  _netPollTimer = setInterval(async () => {\n    const prog = await api('GET', '/api/network-scan/jobs/' + jobId + '/progress');\n    if (!prog) return;\n    const pct = prog.progress_pct ?? prog.pct ?? prog.progress ?? 0;\n    const hostsFound = prog.hosts_found ?? prog.discovered_count ?? 0;\n    const phase = prog.phase || 'Running';\n    const msg = prog.msg ? ' · ' + prog.msg : '';\n\n    if (currentPage === 'network') {\n      document.getElementById('netProgressBar').style.width = pct + '%';\n      document.getElementById('netProgressText').textContent = pct + '% · ' + hostsFound + ' hosts · ' + phase + msg;\n    }\n\n    if (prog.status === 'completed' || pct >= 100) {\n      cleanupNetworkUiState();\n      toast('Scan complete · ' + hostsFound + ' hosts discovered', 'success');\n      if (currentPage === 'network') {\n        loadNetworkJobs();\n        loadNetworkAssets();\n      }\n    }\n    if (prog.status === 'failed' || prog.status === 'cancelled') {\n      cleanupNetworkUiState();\n      toast('Scan stopped · ' + (prog.msg || prog.status), 'error');\n      if (currentPage === 'network') loadNetworkJobs();\n    }\n  }, 2000);\n  loadNetworkJobs();\n}"""
    text = replace_regex(text, pattern_scan, replacement_scan, "startNetworkScan replace")

    if 'async function resolveNetworkHostnames()' not in text:
        marker = "async function loadNetworkAssets() {\n"
        addition = """async function resolveNetworkHostnames() {\n  toast('Resolving hostnames…', 'info');\n  const r = await api('POST', '/api/network-scan/resolve-hostnames');\n  if (r) {\n    toast('Hostname resolution complete', 'success');\n    loadNetworkAssets();\n  } else {\n    toast('Hostname resolution failed', 'error');\n  }\n}\n\nasync function reclassifyNetworkAssets() {\n  toast('Reclassifying assets…', 'info');\n  const r = await api('POST', '/api/network-scan/reclassify-assets');\n  if (r) {\n    toast('Asset reclassification complete', 'success');\n    loadNetworkAssets();\n  } else {\n    toast('Asset reclassification failed', 'error');\n  }\n}\n\n"""
        text = replace_once(text, marker, addition + marker, "network action functions")

    path.write_text(text, encoding='utf-8')
    print('[OK] Patched index.html')


def patch_network_route(root: Path):
    path = root / 'backend' / 'api' / 'routes' / 'network.py'
    if not path.exists():
        print('[WARN] backend/api/routes/network.py missing')
        return
    text = path.read_text(encoding='utf-8')

    if '"asset_confidence":' not in text:
        target = '"scan_job_id":     r.scan_job_id,'
        repl = '''"scan_job_id":     r.scan_job_id,
            "asset_confidence": getattr(r, "asset_confidence", "observed_host"),'''
        text = replace_once(text, target, repl, 'asset_confidence list field')

    if 'def _regrade_asset_confidence' not in text:
        helper = '''

def _regrade_asset_confidence(asset) -> tuple[str, bool]:
    mac = bool(getattr(asset, "mac_address", None))
    hostname = bool(getattr(asset, "hostname", None) or getattr(asset, "netbios_name", None) or getattr(asset, "mdns_name", None) or getattr(asset, "fqdn", None))
    open_ports = getattr(asset, "open_ports", None) or []
    services = getattr(asset, "services", None) or []
    vendor = (getattr(asset, "vendor", None) or "").lower()
    family = (getattr(asset, "device_family", None) or getattr(asset, "device_type", None) or "").lower()
    has_identity = mac or hostname or bool(open_ports) or bool(services)

    if has_identity:
        confidence = "confirmed_asset"
    elif vendor or family:
        confidence = "likely_asset"
    else:
        confidence = "observed_host"

    is_consumer_iot = (
        "mobile" in family or "iot" in family or "tv" in family or "smart" in family or "consumer" in family or
        any(w in vendor for w in ["murata","liteon","roku","sonos","apple","samsung","google","amazon"])
    )
    return confidence, is_consumer_iot


@router.post("/reclassify-assets")
def reclassify_assets(
    auth: AuthenticatedRequest = Depends(require_admin),
    db: Session = Depends(get_db),
) -> dict:
    rows = db.query(NetworkDiscoveredAsset).filter(
        NetworkDiscoveredAsset.tenant_id == auth.tenant_id
    ).all()

    updated = 0
    consumer_iot = 0
    observed = 0
    likely = 0
    confirmed = 0

    for asset in rows:
        confidence, is_consumer_iot = _regrade_asset_confidence(asset)
        asset.asset_confidence = confidence

        if confidence == "observed_host":
            observed += 1
        elif confidence == "likely_asset":
            likely += 1
        else:
            confirmed += 1

        if is_consumer_iot:
            consumer_iot += 1

        updated += 1

    db.commit()
    return {
        "status": "ok",
        "updated": updated,
        "confirmed": confirmed,
        "likely": likely,
        "observed": observed,
        "mobile_iot": consumer_iot,
    }
'''
        marker = '\n\n@router.get("/jobs")\ndef list_network_jobs('
        if marker in text:
            text = text.replace(marker, helper + marker, 1)
        else:
            print('[WARN] could not place reclassify endpoint')

    path.write_text(text, encoding='utf-8')
    print('[OK] Patched network.py route')


def patch_model(root: Path):
    path = root / 'backend' / 'models' / 'network.py'
    if not path.exists():
        print('[WARN] backend/models/network.py missing')
        return
    text = path.read_text(encoding='utf-8')
    old = 'asset_confidence: Mapped[str | None] = mapped_column(String(32), nullable=True, default="confirmed_asset")'
    new = 'asset_confidence: Mapped[str | None] = mapped_column(String(32), nullable=True, default="observed_host")'
    text = replace_once(text, old, new, 'model confidence default')
    path.write_text(text, encoding='utf-8')
    print('[OK] Patched model confidence default')


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
    patch_index(root)
    patch_network_route(root)
    patch_model(root)
    print('[DONE] UI cleanup + confidence patch applied')


if __name__ == '__main__':
    main()
