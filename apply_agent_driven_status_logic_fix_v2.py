from pathlib import Path
import shutil

root = Path(__file__).resolve().parent
network_py = root / 'backend' / 'api' / 'routes' / 'network.py'
index_html = root / 'backend' / 'static' / 'index.html'

if not network_py.exists():
    raise SystemExit(f'network.py not found: {network_py}')
if not index_html.exists():
    raise SystemExit(f'index.html not found: {index_html}')

for p in [network_py, index_html]:
    backup = p.with_suffix(p.suffix + '.agent_status_v2.bak')
    if not backup.exists():
        shutil.copy2(p, backup)

text = network_py.read_text(encoding='utf-8')

if 'from models.agent import Agent' not in text:
    text = text.replace(
        'from models.network import NetworkDiscoveredAsset, NetworkScanJob
',
        'from models.network import NetworkDiscoveredAsset, NetworkScanJob
from models.agent import Agent
from models.asset import CanonicalAsset
',
        1,
    )
if 'import re
' not in text:
    text = text.replace('import logging
', 'import logging
import re
import time
', 1)
elif 'import time
' not in text:
    text = text.replace('import re
', 'import re
import time
', 1)

helper_marker = 'def _network_asset_summary_row(asset: NetworkDiscoveredAsset) -> dict[str, Any]:
'
helper_block = '''def _norm_identity(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower()
    return value or None


def _norm_mac(value: Any) -> str | None:
    item = _norm_identity(value)
    if not item:
        return None
    item = re.sub(r"[^0-9a-f]", "", item)
    return item or None


def _build_management_index(db: Session, tenant_id: str) -> dict[str, dict[str, Any]]:
    now = int(time.time())
    heartbeat_live_window = 15 * 60

    by_ip: dict[str, dict[str, Any]] = {}
    by_mac: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}

    canonical_rows = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    agents = {
        row.agent_id: row
        for row in db.query(Agent).filter(Agent.tenant_id == tenant_id).all()
    }

    for asset in canonical_rows:
        agent = agents.get(asset.agent_id)
        last_seen_epoch = None
        if agent and agent.last_seen_epoch is not None:
            last_seen_epoch = agent.last_seen_epoch
        elif asset.last_snapshot_epoch is not None:
            last_seen_epoch = asset.last_snapshot_epoch

        agent_live = bool(last_seen_epoch and (now - int(last_seen_epoch) <= heartbeat_live_window))
        agent_status = (agent.status if agent and getattr(agent, 'status', None) else None) or ('active' if agent_live else 'offline')

        payload = {
            'agent_id': asset.agent_id,
            'agent_status': agent_status,
            'agent_live': agent_live,
            'last_seen_epoch': last_seen_epoch,
            'managed': True,
            'agent_installed': True,
            'management_status': 'managed',
            'management_source': 'agent',
            'canonical_asset_id': asset.id,
        }

        for ip in asset.ips or []:
            key = _norm_identity(ip)
            if key and key not in by_ip:
                by_ip[key] = payload
        for mac in asset.macs or []:
            key = _norm_mac(mac)
            if key and key not in by_mac:
                by_mac[key] = payload
        for name in [asset.hostname, asset.fqdn]:
            key = _norm_identity(name)
            if key and key not in by_name:
                by_name[key] = payload
            if key and '.' in key:
                short_key = key.split('.', 1)[0]
                if short_key and short_key not in by_name:
                    by_name[short_key] = payload

    return {'by_ip': by_ip, 'by_mac': by_mac, 'by_name': by_name}


def _overlay_management_truth(db: Session, tenant_id: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    idx = _build_management_index(db, tenant_id)
    out: list[dict[str, Any]] = []

    for item in items:
        match = None
        ip_key = _norm_identity(item.get('ip_address'))
        mac_key = _norm_mac(item.get('mac_address'))
        names = [
            item.get('hostname'),
            item.get('fqdn'),
            item.get('netbios_name'),
            item.get('mdns_name'),
            item.get('display_name'),
        ]

        if ip_key:
            match = idx['by_ip'].get(ip_key)
        if not match and mac_key:
            match = idx['by_mac'].get(mac_key)
        if not match:
            for candidate in names:
                key = _norm_identity(candidate)
                if not key:
                    continue
                match = idx['by_name'].get(key)
                if match:
                    break
                if '.' in key:
                    match = idx['by_name'].get(key.split('.', 1)[0])
                    if match:
                        break

        current_agent = bool(item.get('agent_installed'))

        if match:
            item['matched_agent_id'] = match.get('agent_id')
            item['matched_canonical_asset_id'] = match.get('canonical_asset_id')
            item['agent_status'] = match.get('agent_status')
            item['agent_live'] = bool(match.get('agent_live'))
            item['agent_last_seen_epoch'] = match.get('last_seen_epoch')
            item['management_source'] = 'agent'
            item['agent_installed'] = True
            item['managed'] = True
            item['is_managed'] = True
            item['management_status'] = 'managed'
            item['status'] = 'managed'
        else:
            item['matched_agent_id'] = item.get('matched_agent_id')
            item['matched_canonical_asset_id'] = item.get('matched_canonical_asset_id')
            item['agent_status'] = item.get('agent_status') or ('installed' if current_agent else 'not_installed')
            item['agent_live'] = bool(item.get('agent_live'))
            item['agent_last_seen_epoch'] = item.get('agent_last_seen_epoch')
            item['management_source'] = item.get('management_source') or ('agent' if current_agent else 'network_scan')
            item['agent_installed'] = current_agent
            item['managed'] = current_agent
            item['is_managed'] = current_agent
            item['management_status'] = 'managed' if current_agent else 'unmanaged'
            item['status'] = 'managed' if current_agent else 'unmanaged'

        out.append(item)

    return out


'''
if '_overlay_management_truth' not in text:
    text = text.replace(helper_marker, helper_block + helper_marker, 1)

old = '    items = [_network_asset_summary_row(r) for r in rows]

    if include_summary:
'
new = '    items = [_network_asset_summary_row(r) for r in rows]
    items = _overlay_management_truth(db, auth.tenant_id, items)

    if include_summary:
'
if old in text and 'items = _overlay_management_truth(db, auth.tenant_id, items)' not in text:
    text = text.replace(old, new, 1)

network_py.write_text(text, encoding='utf-8')

html = index_html.read_text(encoding='utf-8')
for old, new in [
    ("const isManaged = a.managed || a.agent_installed;", "const isManaged = !!a.agent_installed;"),
    ("if (managed === 'managed') filtered = filtered.filter(a => a.managed || a.agent_installed);", "if (managed === 'managed') filtered = filtered.filter(a => !!a.agent_installed);"),
    ("else if (managed === 'unmanaged') filtered = filtered.filter(a => !a.managed && !a.agent_installed && !a.is_rogue);", "else if (managed === 'unmanaged') filtered = filtered.filter(a => !a.agent_installed && !a.is_rogue);"),
    ("a.cve_count??0, a.managed||a.agent_installed?'Yes':'No',", "a.cve_count??0, a.agent_installed?'Yes':'No',"),
    ("const rogues = _netAllAssets.filter(a => a.is_rogue || (!a.managed && !a.agent_installed));", "const rogues = _netAllAssets.filter(a => a.is_rogue || !a.agent_installed);"),
    ("<div><strong style="color:var(--white)">Managed:</strong> ${a.is_managed || a.managed ? 'Yes' : 'No'}</div>", "<div><strong style="color:var(--white)">Managed:</strong> ${a.agent_installed ? 'Yes' : 'No'}</div>"),
]:
    html = html.replace(old, new)

anchor = "<div><strong style="color:var(--white)">Managed:</strong> ${a.agent_installed ? 'Yes' : 'No'}</div>
            <div><strong style="color:var(--white)">Rogue:</strong> ${a.is_rogue ? 'Yes' : 'No'}</div>"
replacement = "<div><strong style="color:var(--white)">Managed:</strong> ${a.agent_installed ? 'Yes' : 'No'}</div>
            <div><strong style="color:var(--white)">Agent State:</strong> ${escapeHtml(a.agent_status || (a.agent_installed ? 'installed' : 'not_installed'))}${a.agent_live ? ' · live' : ''}</div>
            <div><strong style="color:var(--white)">Rogue:</strong> ${a.is_rogue ? 'Yes' : 'No'}</div>"
if anchor in html and 'Agent State:' not in html:
    html = html.replace(anchor, replacement, 1)

index_html.write_text(html, encoding='utf-8')
print('Applied agent-driven status logic fix v2 successfully.')
print('Backups created with suffix .agent_status_v2.bak')
