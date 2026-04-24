from pathlib import Path
from datetime import datetime

path = Path("backend/static/index.html")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".html.bak_asset_inventory_filter_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

old1 = """  allAssets = [...agentItems, ...manualItems];

  renderAssetsTable(allAssets, tenantRisk);"""

new1 = """  // Separate true agent-managed assets from network/manual assets.
  // Agent Assets tab must only show enrolled agent devices.
  allAssets = [...agentItems, ...manualItems].map(a => {
    const realSource = a.source || a.asset_source || a.source_of_truth || '';
    const realAgentId = String(a.agent_id || '');
    const isTrueAgent =
      realSource === 'agent' ||
      realSource === 'asset_snapshot' ||
      realSource === 'security_posture' ||
      realAgentId.startsWith('agent-') ||
      a.management_state === 'managed' ||
      a.agent_installed === true;

    return {
      ...a,
      source: isTrueAgent ? 'agent' : (realSource || 'network'),
      _is_true_agent_asset: isTrueAgent
    };
  });

  const agentOnlyAssets = allAssets.filter(a => a._is_true_agent_asset);
  renderAssetsTable(agentOnlyAssets, tenantRisk);"""

old2 = """    if (view === 'agent') {
    btnAgent.style.background   = 'var(--teal)';
    btnAgent.style.color        = '#02111d';
    btnUnified.style.background = 'transparent';
    btnUnified.style.color      = 'var(--text-dim)';
    if (sub) sub.textContent    = 'Enrolled agent-managed assets';
    renderAssetsTable(allAssets, tenantRisk);"""

new2 = """    if (view === 'agent') {
    btnAgent.style.background   = 'var(--teal)';
    btnAgent.style.color        = '#02111d';
    btnUnified.style.background = 'transparent';
    btnUnified.style.color      = 'var(--text-dim)';
    if (sub) sub.textContent    = 'Enrolled agent-managed assets only';
    renderAssetsTable(allAssets.filter(a => a._is_true_agent_asset), tenantRisk);"""

old3 = """          <td><span class="badge info">${a.source || a.asset_source || 'agent'}</span></td>"""

new3 = """          <td><span class="badge ${a._is_true_agent_asset ? 'active' : 'info'}">${escapeHtml(a.source || a.asset_source || 'unknown')}</span></td>"""

for old, new in [(old1, new1), (old2, new2), (old3, new3)]:
    if old not in text:
        print("WARNING: block not found:", old[:80])
    text = text.replace(old, new)

path.write_text(text, encoding="utf-8")
print(f"Patched Asset Inventory Agent tab filtering. Backup: {backup}")