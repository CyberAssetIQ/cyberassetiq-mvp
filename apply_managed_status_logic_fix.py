from pathlib import Path

project_root = Path.cwd()
network_py = project_root / 'backend' / 'api' / 'routes' / 'network.py'
frontend = project_root / 'backend' / 'static' / 'index.html'

if not network_py.exists():
    raise SystemExit(f'Could not find {network_py}')

text = network_py.read_text(encoding='utf-8')
original = text

import_anchor = 'from models.network import NetworkDiscoveredAsset, NetworkScanJob\n'
extra_imports = 'from models.agent import Agent\nfrom models.asset import CanonicalAsset\n'
if 'from models.agent import Agent' not in text:
    text = text.replace(import_anchor, import_anchor + extra_imports)

helper_block = """

def _norm_ip_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return str(ip_address(value))
    except Exception:
        return value.lower()


def _norm_mac_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower().replace('-', ':')
    if not value:
        return None
    value = ''.join(ch for ch in value if ch in '0123456789abcdef:')
    parts = [p.zfill(2) for p in value.split(':') if p]
    return ':'.join(parts) if parts else None


def _norm_name_text(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower()
    return value or None


def _is_agent_live(agent: Agent | None, stale_after_seconds: int = 1800) -> bool:
    if not agent or getattr(agent, 'status', None) not in {None, '', 'active'}:
        return False
    last_seen_epoch = getattr(agent, 'last_seen_epoch', None)
    if not last_seen_epoch:
        return False
    try:
        import time
        return (int(time.time()) - int(last_seen_epoch)) <= stale_after_seconds
    except Exception:
        return False


def _annotate_network_rows_with_managed_state(db: Session, tenant_id: str, rows: list[NetworkDiscoveredAsset]) -> None:
    canonical_assets = db.query(CanonicalAsset).filter(CanonicalAsset.tenant_id == tenant_id).all()
    agents = db.query(Agent).filter(Agent.tenant_id == tenant_id).all()

    canonical_by_ip: dict[str, CanonicalAsset] = {}
    canonical_by_mac: dict[str, CanonicalAsset] = {}
    canonical_by_name: dict[str, CanonicalAsset] = {}
    for asset in canonical_assets:
        for ip in (asset.ips or []):
            norm = _norm_ip_text(ip)
            if norm:
                canonical_by_ip.setdefault(norm, asset)
        for mac in (asset.macs or []):
            norm = _norm_mac_text(mac)
            if norm:
                canonical_by_mac.setdefault(norm, asset)
        for name in [asset.hostname, asset.fqdn]:
            norm = _norm_name_text(name)
            if norm:
                canonical_by_name.setdefault(norm, asset)

    agents_by_id = {a.agent_id: a for a in agents}
    live_agents_by_ip: dict[str, Agent] = {}
    live_agents_by_mac: dict[str, Agent] = {}
    live_agents_by_name: dict[str, Agent] = {}
    for asset in canonical_assets:
        agent = agents_by_id.get(asset.agent_id)
        if not _is_agent_live(agent):
            continue
        for ip in (asset.ips or []):
            norm = _norm_ip_text(ip)
            if norm:
                live_agents_by_ip.setdefault(norm, agent)
        for mac in (asset.macs or []):
            norm = _norm_mac_text(mac)
            if norm:
                live_agents_by_mac.setdefault(norm, agent)
        for name in [asset.hostname, asset.fqdn, getattr(agent, 'hostname', None)]:
            norm = _norm_name_text(name)
            if norm:
                live_agents_by_name.setdefault(norm, agent)

    for row in rows:
        row_ip = _norm_ip_text(getattr(row, 'ip_address', None))
        row_mac = _norm_mac_text(getattr(row, 'mac_address', None))
        row_names = [
            _norm_name_text(getattr(row, 'hostname', None)),
            _norm_name_text(getattr(row, 'netbios_name', None)),
            _norm_name_text(getattr(row, 'mdns_name', None)),
            _norm_name_text(getattr(row, 'fqdn', None)),
        ]
        row_names = [x for x in row_names if x]

        matched_asset = None
        matched_agent = None

        if row_ip and row_ip in canonical_by_ip:
            matched_asset = canonical_by_ip[row_ip]
        if row_mac and row_mac in canonical_by_mac and matched_asset is None:
            matched_asset = canonical_by_mac[row_mac]
        if matched_asset is None:
            for name in row_names:
                if name in canonical_by_name:
                    matched_asset = canonical_by_name[name]
                    break

        if row_ip and row_ip in live_agents_by_ip:
            matched_agent = live_agents_by_ip[row_ip]
        if row_mac and row_mac in live_agents_by_mac and matched_agent is None:
            matched_agent = live_agents_by_mac[row_mac]
        if matched_agent is None:
            for name in row_names:
                if name in live_agents_by_name:
                    matched_agent = live_agents_by_name[name]
                    break

        if matched_asset is not None:
            row.managed = True
            meta = getattr(row, 'raw_metadata_json', None) or {}
            if isinstance(meta, dict):
                meta['matched_agent_id'] = matched_asset.agent_id
                meta['managed_source'] = 'canonical_asset_match'
                if matched_agent is not None:
                    meta['live_agent_status'] = 'live'
                    meta['live_agent_hostname'] = getattr(matched_agent, 'hostname', None)
                row.raw_metadata_json = meta

        if matched_agent is not None:
            row.agent_installed = True
            if not getattr(row, 'managed', False):
                row.managed = True
"""

if '_annotate_network_rows_with_managed_state' not in text:
    text = text.replace('def _network_asset_summary_row(asset: NetworkDiscoveredAsset) -> dict[str, Any]:\n', helper_block + '\ndef _network_asset_summary_row(asset: NetworkDiscoveredAsset) -> dict[str, Any]:\n')

old = '    rows = query.all()\n    rows = sorted(rows, key=lambda r: _sort_ip_text(r.ip_address))\n    items = [_network_asset_summary_row(r) for r in rows]\n'
new = '    rows = query.all()\n    _annotate_network_rows_with_managed_state(db, auth.tenant_id, rows)\n    rows = sorted(rows, key=lambda r: _sort_ip_text(r.ip_address))\n    items = [_network_asset_summary_row(r) for r in rows]\n'
if old not in text:
    raise SystemExit('Could not find list_network_assets block to patch.')
text = text.replace(old, new)

network_py.write_text(text, encoding='utf-8')

if frontend.exists():
    ftxt = frontend.read_text(encoding='utf-8')
    old_js = """<div><strong style="color:var(--white)">Managed:</strong> ${a.is_managed || a.managed ? 'Yes' : 'No'}</div>"""
    new_js = """<div><strong style="color:var(--white)">Managed:</strong> ${a.is_managed || a.managed || a.agent_installed ? 'Yes' : 'No'}</div>"""
    if old_js in ftxt:
        ftxt = ftxt.replace(old_js, new_js)
        frontend.write_text(ftxt, encoding='utf-8')

if text == original:
    raise SystemExit('No backend changes were applied; patch may already be present.')

print('Managed status logic fix applied successfully.')
