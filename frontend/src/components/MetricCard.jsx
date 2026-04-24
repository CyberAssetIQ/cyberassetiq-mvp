export default function MetricCard({ title, value, subtitle, tone = "blue" }) {
  const colours = {
    blue: "#38bdf8",
    red: "#fb7185",
    amber: "#facc15",
    green: "#34d399",
    purple: "#818cf8"
  };

  return (
    <div className="metric-card">
      <div className="metric-header">
        <span>{title}</span>
        <span className="metric-dot" style={{ background: colours[tone] }} />
      </div>
      <div className="metric-value" style={{ color: colours[tone] }}>
        {value ?? 0}
      </div>
      <div className="metric-subtitle">{subtitle}</div>
    </div>
  );
}