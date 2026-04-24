export default function AppLayout({ children }) {
  return (
    <div className="app-shell">
      <aside className="sidebar pro-sidebar">
        <div className="brand pro-brand">
          <div className="brand-mark">✓</div>
          <div>
            <strong>CyberAssetIQ</strong>
            <span>CYBER ASSET INTELLIGENCE</span>
          </div>
        </div>

        <nav className="pro-nav">
          <MenuGroup title="PLATFORM">
            <MenuItem active icon="▦" label="Overview" />
            <MenuItem icon="▰" label="Assets" badge="81" />
            <MenuItem icon="⬢" label="Vulnerabilities" badge="50" danger />
            <MenuItem icon="✣" label="Network Scanning" />
            <MenuItem icon="▣" label="Agent Telemetry" />
          </MenuGroup>

          <MenuGroup title="COMPLIANCE">
            <MenuItem icon="⬢" label="CE v3.2 Willow" />
            <MenuItem icon="◈" label="CE v4 Danzell" badge="NEW" />
            <MenuItem icon="☑" label="NCSC CAF" />
            <MenuItem icon="■" label="CS&R Bill" badge="NEW" />
            <MenuItem icon="◷" label="Posture Record" />
          </MenuGroup>

          <MenuGroup title="AI & INTELLIGENCE">
            <MenuItem icon="☻" label="AI Security Intel" />
            <MenuItem icon="⬡" label="Agentic AI Loop" />
            <MenuItem icon="★" label="Risk Engine" />
          </MenuGroup>

          <MenuGroup title="ECOSYSTEM">
            <MenuItem icon="◆" label="Broker API" />
            <MenuItem icon="▤" label="Supplier Portal" />
            <MenuItem icon="▧" label="MSP Console" />
            <MenuItem icon="▣" label="Reports" />
          </MenuGroup>
        </nav>

        <div className="user-card">
          <div className="avatar">WA</div>
          <div>
            <strong>Wole Adekola</strong>
            <span>Founder & CEO · Admin</span>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar v9-topbar">
          <div>
            <h1>CyberAssetIQ Command Centre</h1>
            <p>
              Live cyber posture, trust records, broker APIs, supply-chain
              assurance and AI risk intelligence
            </p>
          </div>

          <div className="v9-tenant-switcher">
            <span>Active Tenant</span>
            <strong>tenant-001</strong>
            <button type="button">Switch</button>
          </div>
        </header>

        {children}
      </main>
    </div>
  );
}

function MenuGroup({ title, children }) {
  return (
    <div className="menu-group">
      <div className="menu-title">
        <span>{title}</span>
        <div></div>
      </div>
      {children}
    </div>
  );
}

function MenuItem({ icon, label, badge, active, danger }) {
  return (
    <a className={`menu-item ${active ? "active" : ""}`}>
      <span className="menu-icon">{icon}</span>
      <span>{label}</span>
      {badge && <em className={danger ? "badge-danger" : ""}>{badge}</em>}
    </a>
  );
}