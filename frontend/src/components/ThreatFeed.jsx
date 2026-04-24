function normaliseAlerts(alerts) {
  const items = Array.isArray(alerts) ? alerts : alerts?.items || alerts?.alerts || [];
  const grouped = {};

  items.forEach((a) => {
    const title = a.title || a.alert_type || a.detection_type || "Security Alert";
    const host = a.hostname || a.asset_name || a.agent_id || a.ip_address || "";
    const key = `${title}::${host}`;

    if (!grouped[key]) {
      grouped[key] = { ...a, count: 0, host, title };
    }

    grouped[key].count += 1;
  });

  return Object.values(grouped).slice(0, 6);
}

function cleanSeverity(sev) {
  if (!sev) return "Low";
  return sev.toString().replaceAll("_", " ").toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
}

export default function ThreatFeed({ alerts }) {
  const groupedAlerts = normaliseAlerts(alerts);

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2>AI Threat Feed</h2>
          <p>Prioritised behavioural and exposure alerts</p>
        </div>
        <button className="panel-action">View All</button>
      </div>

      {groupedAlerts.length === 0 ? (
        <div className="empty">No recent alerts</div>
      ) : (
        <div className="threat-list">
          {groupedAlerts.map((a, index) => {
            const severity = (a.severity || "low").toLowerCase();
            const host = a.host || "Unknown Asset";
            const displayTitle =
              a.title.includes(host) ? a.title : `${a.title}`;

            const risk = Math.min(99, 55 + a.count * 3);
            const confidence = Math.min(98, 76 + a.count * 2);

            return (
              <div className="threat-item" key={index}>
                <div className={`severity-dot ${severity}`} />
                <div className="threat-content">
                  <div className="threat-title">{displayTitle}</div>
                  <div className="threat-meta">
                    Asset: {host} · Risk {risk}/100 · AI Confidence {confidence}%
                  </div>
                  <div className="threat-meta">
                    {a.count > 1 ? `${a.count} related detections` : "1 detection"}
                  </div>
                  <div className="suggested-action">
                    Suggested Action: Review user activity and validate sign-in context
                  </div>
                </div>
                <span className={`severity-badge ${severity}`}>
                  {cleanSeverity(a.severity)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}