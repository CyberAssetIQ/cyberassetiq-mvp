from pathlib import Path
import re
import sys

ROOT = Path.cwd()
network_py = ROOT / 'backend' / 'api' / 'routes' / 'network.py'
index_html = ROOT / 'backend' / 'static' / 'index.html'

if not network_py.exists() or not index_html.exists():
    print('Run this from the CyberAssetIQ project root containing backend/.')
    sys.exit(1)

network_text = network_py.read_text(encoding='utf-8')
index_text = index_html.read_text(encoding='utf-8')

# --- Patch backend/api/routes/network.py ---
helper_block = '''def _hostname_sources(asset: NetworkDiscoveredAsset) -> list[str]:
    sources: list[str] = []
    if getattr(asset, "hostname", None):
        sources.append("reverse_dns")
    if getattr(asset, "netbios_name", None):
        sources.append("netbios")
    if getattr(asset, "mdns_name", None):
        sources.append("mdns")
    if getattr(asset, "fqdn", None):
        sources.append("fqdn")
    return sources


def _discovery_quality(asset: NetworkDiscoveredAsset, port_numbers: list[int | str]) -> str:
    score = 0
    if getattr(asset, "mac_address", None):
        score += 1
    if _hostname_sources(asset):
        score += 1
    if port_numbers:
        score += 1
    if getattr(asset, "vendor", None):
        score += 1
    if getattr(asset, "os_guess", None):
        score += 1
    return {
        0: "Observed only",
        1: "Low confidence",
        2: "Basic fingerprint",
        3: "Good fingerprint",
        4: "Rich fingerprint",
        5: "High fidelity",
    }.get(score, "Rich fingerprint")


def _asset_confidence_score(asset: NetworkDiscoveredAsset, port_numbers: list[int | str]) -> int:
    score = 20
    if getattr(asset, "mac_address", None):
        score += 20
    if _hostname_sources(asset):
        score += 20
    if port_numbers:
        score += 20
    if getattr(asset, "vendor", None):
        score += 10
    if getattr(asset, "os_guess", None):
        score += 10
    if getattr(asset, "agent_installed", False) or getattr(asset, "managed", False):
        score += 20
    return min(score, 100)


def _recommended_action(asset: NetworkDiscoveredAsset, port_numbers: list[int | str]) -> str:
    risk = str(_risk_level_text(asset) or "INFO").upper()
    if getattr(asset, "is_rogue", False):
        return "investigate_and_isolate"
    if getattr(asset, "agent_installed", False) or getattr(asset, "managed", False):
        if risk in {"CRITICAL", "HIGH"}:
            return "patch_and_harden"
        return "monitor_managed_asset"
    if 445 in port_numbers or 3389 in port_numbers:
        return "enrol_or_harden_host"
    if risk == "CRITICAL":
        return "contain_and_triage"
    if risk == "HIGH":
        return "investigate_and_reduce_exposure"
    if risk == "MEDIUM":
        return "review_and_harden"
    return "monitor_only"


def _classification_reasons(asset: NetworkDiscoveredAsset, port_numbers: list[int | str], service_names: list[str]) -> list[str]:
    reasons: list[str] = []
    vendor = getattr(asset, "vendor", None)
    if vendor:
        reasons.append(f"MAC vendor identified as {vendor}.")
    if getattr(asset, "os_guess", None):
        reasons.append(f"OS fingerprint suggests {asset.os_guess}.")
    device_family = getattr(asset, "device_family", None) or getattr(asset, "device_type", None)
    if device_family:
        reasons.append(f"Classified as {device_family} from ports, banners, and vendor signals.")
    if port_numbers:
        reasons.append(f"Open ports observed: {', '.join(str(p) for p in port_numbers[:8])}{'…' if len(port_numbers) > 8 else ''}.")
    if service_names:
        reasons.append(f"Services identified: {', '.join(service_names[:5])}{'…' if len(service_names) > 5 else ''}.")
    for factor in (getattr(asset, "risk_factors", None) or [])[:5]:
        reasons.append(f"Risk factor detected: {factor}.")
    return reasons

'''

if '_hostname_sources(asset: NetworkDiscoveredAsset)' not in network_text:
    network_text = network_text.replace('def _risk_level_text(asset: NetworkDiscoveredAsset) -> str:\n    return getattr(asset, "risk_level", None) or getattr(asset, "risk_hint", None) or "INFO"\n\n', 'def _risk_level_text(asset: NetworkDiscoveredAsset) -> str:\n    return getattr(asset, "risk_level", None) or getattr(asset, "risk_hint", None) or "INFO"\n\n' + helper_block)

new_summary = '''def _network_asset_summary_row(asset: NetworkDiscoveredAsset) -> dict[str, Any]:
    hostname = asset.hostname or getattr(asset, "netbios_name", None) or getattr(asset, "mdns_name", None)
    open_ports = asset.open_ports or []
    services = getattr(asset, "services", []) or []
    port_numbers = _port_numbers(open_ports)
    service_names = _service_names(services)
    hostname_sources = _hostname_sources(asset)
    confidence_score = _asset_confidence_score(asset, port_numbers)
    vulnerabilities = getattr(asset, "vulnerabilities", None) or []
    return {
        "id": asset.id,
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "netbios_name": getattr(asset, "netbios_name", None),
        "mdns_name": getattr(asset, "mdns_name", None),
        "fqdn": getattr(asset, "fqdn", None),
        "display_name": hostname or asset.ip_address,
        "mac_address": asset.mac_address,
        "vendor": asset.vendor,
        "device_model": getattr(asset, "device_model", None),
        "device_type": asset.device_type,
        "device_family": getattr(asset, "device_family", None),
        "os_guess": asset.os_guess,
        "os": asset.os_guess,
        "os_family": asset.os_guess,
        "os_version": getattr(asset, "os_version", None),
        "os_confidence": getattr(asset, "os_confidence", None),
        "network_segment": getattr(asset, "network_segment", None),
        "vlan": getattr(asset, "vlan", None),
        "gateway": getattr(asset, "gateway", None),
        "risk_score": getattr(asset, "risk_score", None),
        "risk_level": _risk_level_text(asset),
        "risk_hint": getattr(asset, "risk_hint", None),
        "risk_factors": getattr(asset, "risk_factors", []) or [],
        "recommended_action": _recommended_action(asset, port_numbers),
        "open_ports": open_ports,
        "ports_display": port_numbers,
        "open_port_count": len(port_numbers),
        "services": services,
        "services_display": service_names,
        "service_count": len(service_names),
        "http_headers": getattr(asset, "http_headers", None),
        "tls_info": getattr(asset, "tls_info", None),
        "smb_info": getattr(asset, "smb_info", None),
        "snmp_data": getattr(asset, "snmp_data", None),
        "banner_data": getattr(asset, "banner_data", None),
        "ce_issues": getattr(asset, "ce_issues", []) or [],
        "managed": getattr(asset, "managed", False),
        "is_managed": getattr(asset, "managed", False),
        "agent_installed": getattr(asset, "agent_installed", False),
        "is_rogue": getattr(asset, "is_rogue", False),
        "is_internet_facing": getattr(asset, "is_internet_facing", False),
        "asset_confidence": getattr(asset, "asset_confidence", None),
        "confidence_score": confidence_score,
        "discovery_quality": _discovery_quality(asset, port_numbers),
        "classification_reasons": _classification_reasons(asset, port_numbers, service_names),
        "hostname_sources": hostname_sources,
        "vulnerabilities": vulnerabilities[:20],
        "cve_count": getattr(asset, "cve_count", 0),
        "critical_cve_count": getattr(asset, "critical_cve_count", 0),
        "high_cve_count": getattr(asset, "high_cve_count", 0),
        "medium_cve_count": getattr(asset, "medium_cve_count", 0),
        "first_seen": getattr(asset, "first_seen", None),
        "last_seen": getattr(asset, "last_seen", None),
        "scan_job_id": asset.scan_job_id,
        "raw_metadata_json": getattr(asset, "raw_metadata_json", None),
    }
'''

network_text2, count = re.subn(r'def _network_asset_summary_row\(asset: NetworkDiscoveredAsset\) -> dict\[str, Any\]:\n(?:    .*\n)+?\n\ndef _network_assets_rollup', new_summary + '\n\ndef _network_assets_rollup', network_text, count=1)
if count != 1:
    print('Failed to patch _network_asset_summary_row in network.py')
    sys.exit(1)
network_text = network_text2
network_py.write_text(network_text, encoding='utf-8')

# --- Patch backend/static/index.html ---
new_show = '''async function showAssetDetail(assetIdOrIp) {
  if (!assetIdOrIp) return;
  const a = (_netAllAssets || []).find(x =>
    String(x.id) === String(assetIdOrIp) || x.ip_address === assetIdOrIp
  );
  if (!a) {
    toast('Asset not found in current scan data', 'error');
    return;
  }

  const risk = (a.risk_level || 'info').toUpperCase();
  const riskColorMap = { CRITICAL:'var(--red)', HIGH:'var(--orange)', MEDIUM:'var(--yellow)', LOW:'var(--green)', INFO:'var(--teal)' };
  const riskColor = riskColorMap[risk] || 'var(--teal)';
  const ports = Array.isArray(a.open_ports) ? a.open_ports : [];
  const services = Array.isArray(a.services) ? a.services : [];
  const hostnameList = [a.hostname, a.netbios_name, a.mdns_name, a.fqdn].filter(Boolean);
  const vulnList = Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [];
  const reasons = Array.isArray(a.classification_reasons) ? a.classification_reasons : [];
  const hostnameSources = Array.isArray(a.hostname_sources) ? a.hostname_sources : [];
  const riskFactors = Array.isArray(a.risk_factors) ? a.risk_factors : [];
  const ceIssues = Array.isArray(a.ce_issues) ? a.ce_issues : [];
  const sourceBadges = [
    (a.managed || a.agent_installed) ? '<span class="badge success">Managed</span>' : '<span class="badge warn">Unmanaged</span>',
    a.is_rogue ? '<span class="badge danger">Rogue</span>' : '',
    a.is_internet_facing ? '<span class="badge warn">Internet-facing</span>' : '',
    a.asset_confidence ? `<span class="badge info">${escapeHtml(String(a.asset_confidence).replaceAll('_',' '))}</span>` : ''
  ].filter(Boolean).join(' ');

  const kv = (label, value) => `<div style="display:flex;justify-content:space-between;gap:16px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05)"><span style="color:var(--text-dim)">${label}</span><span style="color:var(--white);text-align:right;max-width:60%">${value}</span></div>`;
  const chip = (text, tone='info') => `<span class="badge ${tone}" style="margin-right:6px;margin-bottom:6px;display:inline-block">${escapeHtml(text)}</span>`;

  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.82);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:28px;max-width:1080px;width:100%;max-height:90vh;overflow-y:auto">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:18px">
        <div>
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <div style="font-size:26px;font-weight:800;color:var(--white)">${escapeHtml(a.display_name || a.ip_address || 'Asset')}</div>
            <span style="background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor}44;border-radius:999px;padding:5px 12px;font-size:11px;font-weight:800;letter-spacing:.4px">${risk}</span>
          </div>
          <div style="font-size:13px;color:var(--text-dim);margin-top:6px">
            ${escapeHtml(a.ip_address || '—')} ${hostnameList.length ? '&middot; ' + hostnameList.map(escapeHtml).join(' &middot; ') : ''}
          </div>
          <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">${sourceBadges}</div>
        </div>
        <button onclick="this.closest('.cy-temp-overlay').remove()" style="background:transparent;border:none;color:var(--text-dim);cursor:pointer;font-size:26px;line-height:1">&#x2715;</button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px">
        <div class="card"><div class="card-body"><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase">Device Type</div><div style="font-size:18px;font-weight:700;color:var(--white);margin-top:6px">${escapeHtml(a.device_family || a.device_type || 'Unknown')}</div><div style="font-size:12px;color:var(--text-dim);margin-top:4px">${escapeHtml(a.vendor || a.device_model || 'Unknown vendor')}</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase">Exposure</div><div style="font-size:18px;font-weight:700;color:var(--white);margin-top:6px">${escapeHtml(String(a.open_port_count ?? ports.length ?? 0))} ports</div><div style="font-size:12px;color:var(--text-dim);margin-top:4px">${escapeHtml(String(a.service_count ?? services.length ?? 0))} services</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase">Confidence</div><div style="font-size:18px;font-weight:700;color:var(--white);margin-top:6px">${escapeHtml(String(a.confidence_score ?? 0))}/100</div><div style="font-size:12px;color:var(--text-dim);margin-top:4px">${escapeHtml(a.discovery_quality || '—')}</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:10px;color:var(--text-dim);text-transform:uppercase">Vulnerabilities</div><div style="font-size:18px;font-weight:700;color:var(--white);margin-top:6px">${escapeHtml(String(a.cve_count ?? 0))}</div><div style="font-size:12px;color:var(--text-dim);margin-top:4px">Critical ${escapeHtml(String(a.critical_cve_count ?? 0))} · High ${escapeHtml(String(a.high_cve_count ?? 0))}</div></div></div>
      </div>

      <div style="display:grid;grid-template-columns:1.1fr 1fr;gap:16px;margin-bottom:18px">
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:10px">Identity & Discovery</div>
          ${kv('IP Address', escapeHtml(a.ip_address || '—'))}
          ${kv('MAC Address', escapeHtml(a.mac_address || '—'))}
          ${kv('Vendor / Model', escapeHtml([a.vendor, a.device_model].filter(Boolean).join(' / ') || 'Unknown'))}
          ${kv('Hostnames', hostnameList.length ? hostnameList.map(escapeHtml).join('<br>') : 'None resolved')}
          ${kv('Hostname Sources', hostnameSources.length ? hostnameSources.map(escapeHtml).join(', ') : 'None')}
          ${kv('Network Segment', escapeHtml(a.network_segment || '—'))}
          ${kv('Gateway / VLAN', escapeHtml([a.gateway, a.vlan].filter(Boolean).join(' / ') || '—'))}
          ${kv('First Seen', escapeHtml(a.first_seen || '—'))}
          ${kv('Last Seen', escapeHtml(a.last_seen || '—'))}
          ${kv('Last Scan Job', escapeHtml(a.scan_job_id != null ? String(a.scan_job_id) : '—'))}
        </div></div>

        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:10px">OS & Risk</div>
          ${kv('OS Fingerprint', escapeHtml(a.os_guess || a.os_family || a.os || 'Unknown OS'))}
          ${kv('OS Version', escapeHtml(a.os_version || '—'))}
          ${kv('OS Confidence', escapeHtml(a.os_confidence != null ? String(a.os_confidence) : '—'))}
          ${kv('Risk Level', `<span style="color:${riskColor};font-weight:700">${escapeHtml(risk)}</span>`)}
          ${kv('Risk Score', escapeHtml(a.risk_score != null ? String(a.risk_score) : '0'))}
          ${kv('Recommended Action', escapeHtml(a.recommended_action || 'monitor_only'))}
          ${kv('Managed', a.managed || a.agent_installed ? 'Yes' : 'No')}
          ${kv('Rogue', a.is_rogue ? 'Yes' : 'No')}
          ${kv('Internet-facing', a.is_internet_facing ? 'Yes' : 'No')}
          ${kv('Asset Confidence', escapeHtml(a.asset_confidence || '—'))}
        </div></div>
      </div>

      <div class="card" style="margin-bottom:14px"><div class="card-body">
        <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Classification Reasons</div>
        <div style="font-size:12px;color:var(--text)">
          ${reasons.length ? `<ul style="padding-left:18px;line-height:1.8;margin:0">${reasons.map(x => `<li>${escapeHtml(x)}</li>`).join('')}</ul>` : '<span style="color:var(--text-dim)">No detailed reasons stored yet.</span>'}
        </div>
      </div></div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px">
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Risk Factors</div>
          <div>${riskFactors.length ? riskFactors.map(f => chip(String(f), 'warn')).join('') : '<span style="color:var(--text-dim)">No explicit risk factors recorded.</span>'}</div>
        </div></div>
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Compliance / CE Issues</div>
          <div>${ceIssues.length ? ceIssues.map(f => chip(String(f), 'danger')).join('') : '<span style="color:var(--text-dim)">No CE issues recorded.</span>'}</div>
        </div></div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px">
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Open Ports</div>
          <div>${ports.length ? formatPortList(ports) : '<span style="color:var(--text-dim)">No open ports recorded.</span>'}</div>
        </div></div>
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Services</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">${services.length ? services.map(s => chip(`${s.port ? s.port + '/' : ''}${s.service || s.name || s.product || 'service'}`)).join('') : '<span style="color:var(--text-dim)">No service banners recorded.</span>'}</div>
        </div></div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px">
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Protocols & Banners</div>
          <div style="font-size:12px;color:var(--text);line-height:1.8">
            ${kv('SMB', escapeHtml(a.smb_info ? JSON.stringify(a.smb_info).slice(0, 180) : '—'))}
            ${kv('TLS', escapeHtml(a.tls_info ? JSON.stringify(a.tls_info).slice(0, 180) : '—'))}
            ${kv('HTTP Headers', escapeHtml(a.http_headers ? JSON.stringify(a.http_headers).slice(0, 180) : '—'))}
            ${kv('Banner Data', escapeHtml(a.banner_data ? JSON.stringify(a.banner_data).slice(0, 180) : '—'))}
          </div>
        </div></div>
        <div class="card"><div class="card-body">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px">Vulnerabilities</div>
          <div style="max-height:220px;overflow:auto;padding-right:6px">
            ${vulnList.length ? vulnList.map(v => `<div style="border-bottom:1px solid rgba(255,255,255,.05);padding:8px 0"><div style="display:flex;justify-content:space-between;gap:12px"><strong style="color:var(--white)">${escapeHtml(v.cve_id || v.id || 'Finding')}</strong><span style="color:var(--text-dim)">${escapeHtml(v.severity || '—')}</span></div><div style="font-size:12px;color:var(--text-dim);margin-top:4px">${escapeHtml(v.title || v.description || 'No vulnerability summary stored.')}</div></div>`).join('') : '<span style="color:var(--text-dim)">No vulnerability records attached to this asset.</span>'}
          </div>
        </div></div>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
}
'''

index_text2, count = re.subn(r'async function showAssetDetail\(assetIdOrIp\) \{[\s\S]*?\n\}\n\n\n// ── CSV EXPORT', new_show + '\n\n// ── CSV EXPORT', index_text, count=1)
if count != 1:
    print('Failed to patch showAssetDetail in index.html')
    sys.exit(1)
index_text = index_text2
index_html.write_text(index_text, encoding='utf-8')

print('Patched: backend/api/routes/network.py')
print('Patched: backend/static/index.html')
print('Restart backend after applying.')
