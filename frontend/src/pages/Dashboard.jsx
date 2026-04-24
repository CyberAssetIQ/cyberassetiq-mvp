import { useEffect, useMemo, useState } from "react";
import { getDashboardSummary, getAlerts } from "../api/client";

const API_BASE = "http://192.168.0.179:8000";
const API_KEY = import.meta.env.VITE_API_KEY || "";
const TENANT_ID = import.meta.env.VITE_TENANT_ID || "tenant-001";

function go(route) {
  window.location.hash = route;
}

async function api(path, method = "GET") {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "X-API-Key": API_KEY,
      "X-Tenant-ID": TENANT_ID,
    },
  });

  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
}

const commercialModules = [
  {
    title: "Neutral Posture Record",
    tag: "Core IP",
    route: "posture",
    desc: "Single reusable cyber posture record for brokers, buyers, insurers and MSPs.",
  },
  {
    title: "Trust Passport",
    tag: "Verifiable Credential",
    route: "verification",
    desc: "Time-stamped credential with public verification token and expiry.",
  },
  {
    title: "Insurance Broker API",
    tag: "Revenue Channel",
    route: "broker",
    desc: "Broker-neutral posture data for quotation, renewal and risk advice.",
  },
  {
    title: "Supply Chain Assurance",
    tag: "Enterprise Buyers",
    route: "supplychain",
    desc: "Reusable supplier assurance aligned to procurement and CS&R expectations.",
  },
  {
    title: "Cyber Essentials v4",
    tag: "Danzell 2026",
    route: "ce4",
    desc: "Continuous mapping against CE v4 Danzell and UK SME readiness.",
  },
  {
    title: "NCSC CAF + CS&R Bill",
    tag: "UK Regulation",
    route: "csr",
    desc: "Supply-chain obligation mapping for the new UK cyber compliance landscape.",
  },
  {
    title: "MSP White Label",
    tag: "Scale Channel",
    route: "msp",
    desc: "Enable MSPs to manage multiple SME posture records under their own brand.",
  },
  {
    title: "AI Risk Engine",
    tag: "Automation",
    route: "ai",
    desc: "AI-guided risk prioritisation, recommendations and executive summaries.",
  },
];

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [posture, setPosture] = useState(null);
  const [history, setHistory] = useState([]);
  const [sharing, setSharing] = useState([]);
  const [brokerClients, setBrokerClients] = useState([]);
  const [supplyStatus, setSupplyStatus] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const [
          summaryData,
          alertData,
          postureData,
          historyData,
          sharingData,
          brokerData,
          supplyData,
        ] = await Promise.all([
          getDashboardSummary(),
          getAlerts(),
          api("/api/posture/current"),
          api("/api/posture/history"),
          api("/api/posture-sharing/grants"),
          api("/api/brokers/clients"),
          api("/api/supply-chain/my-status"),
        ]);

        setSummary(summaryData);
        setAlerts(Array.isArray(alertData) ? alertData : alertData?.items || alertData?.alerts || []);
        setPosture(postureData);
        setHistory(Array.isArray(historyData) ? historyData : []);
        setSharing(Array.isArray(sharingData) ? sharingData : []);
        setBrokerClients(Array.isArray(brokerData) ? brokerData : []);
        setSupplyStatus(supplyData);
      } catch (err) {
        setError(err.message || "Unable to load CyberAssetIQ commercial dashboard");
      }
    }

    load();
  }, []);

  const kpis = useMemo(() => {
    if (!summary || !posture) return [];

    return [
      ["Assets", summary.total_assets, "Live estate intelligence"],
      ["Risk Score", posture.overall_score ?? summary.risk_score, posture.risk_band || "Live risk"],
      ["Insurance", posture.insurance_readiness_score, "Broker readiness"],
      ["Supply Chain", posture.supply_chain_score, "Buyer assurance"],
      ["Compliance", posture.compliance_score, "CE · CAF · CS&R"],
      ["Versions", history.length, "Posture record history"],
      ["Broker Clients", brokerClients.length, "Commercial channel"],
      ["Sharing Grants", sharing.length, "Authorised access"],
    ];
  }, [summary, posture, history, brokerClients, sharing]);

  const credential = supplyStatus?.credential || null;
  const topRisks = posture?.top_risks || [];
  const controls = posture?.controls || {};

  if (error) return <div className="error-box">API Error: {error}</div>;
  if (!summary || !posture) return <div className="loading">Loading CyberAssetIQ V8 Commercial Command Centre...</div>;

  return (
    <div className="v8-dashboard">
      <section className="v8-hero">
        <div className="v8-motion-grid"></div>

        <div className="v8-hero-left">
          <span className="v8-eyebrow">Commercial Cyber Trust Infrastructure</span>
          <h2>CyberAssetIQ V8 Command Centre</h2>
          <p>
            The reusable cyber posture record platform for SMEs, brokers, enterprise buyers,
            insurers and MSPs — continuously updated, machine-readable and externally verifiable.
          </p>

          <div className="v8-hero-pills">
            <span>Neutral Posture Record</span>
            <span>Broker API</span>
            <span>Supplier Assurance</span>
            <span>Trust Passport</span>
            <span>CE v4 · CAF · CS&R</span>
          </div>
        </div>

        <div className="v8-score-sphere">
          <small>Live Posture</small>
          <strong>{posture.overall_score}</strong>
          <span>{posture.risk_band}</span>
        </div>
      </section>

      <section className="v8-kpi-grid">
        {kpis.map(([title, value, desc]) => (
          <div className="v8-kpi" key={title}>
            <span>{title}</span>
            <strong>{value ?? 0}</strong>
            <small>{desc}</small>
          </div>
        ))}
      </section>

      <section className="v8-commercial-grid">
        <div className="v8-panel v8-trust-engine">
          <div className="v8-panel-head">
            <div>
              <h3>Reusable Trust Record Engine</h3>
              <p>Cyber posture as infrastructure — not a one-off PDF report.</p>
            </div>
            <button onClick={() => go("posture")}>Open Record</button>
          </div>

          <div className="v8-orbit">
            <button onClick={() => go("broker")}>Broker</button>
            <button onClick={() => go("supplychain")}>Buyer</button>
            <button onClick={() => go("insurance")}>Insurer</button>
            <button onClick={() => go("msp")}>MSP</button>
            <button onClick={() => go("verification")}>Verify</button>

            <div className="v8-core">
              <strong>CyberAssetIQ</strong>
              <span>Neutral Posture Record</span>
            </div>
          </div>
        </div>

        <div className="v8-panel">
          <div className="v8-panel-head">
            <div>
              <h3>Trust Passport</h3>
              <p>Reusable supplier credential generated from the posture record.</p>
            </div>
            <button onClick={() => go("verification")}>Verify</button>
          </div>

          <div className="v8-passport">
            <span>Credential</span>
            <strong>{credential?.status || "Not issued"}</strong>
            <p>{credential?.credential_uuid || "No credential UUID available"}</p>
            <div>
              <small>Expires</small>
              <b>{credential?.expires_at ? new Date(credential.expires_at).toLocaleDateString() : "N/A"}</b>
            </div>
          </div>
        </div>
      </section>

      <section className="v8-market-row">
        <div>
          <span>Market Category</span>
          <strong>Cyber Posture Infrastructure</strong>
        </div>
        <div>
          <span>Use Case</span>
          <strong>Insurance + Supply Chain + Compliance</strong>
        </div>
        <div>
          <span>Frameworks</span>
          <strong>CE v4 · CAF · CS&R Bill</strong>
        </div>
        <div>
          <span>Commercial Channels</span>
          <strong>SME · Broker · Enterprise · MSP</strong>
        </div>
      </section>

      <section className="v8-operating-grid">
        <div className="v8-panel">
          <div className="v8-panel-head">
            <div>
              <h3>Framework Alignment</h3>
              <p>Evidence mapped to UK cyber assurance expectations.</p>
            </div>
          </div>

          <div className="v8-framework-list">
            <div>
              <span>Cyber Essentials v4</span>
              <strong>{controls?.ce_danzell?.score ?? 0}%</strong>
              <small>{controls?.ce_danzell?.status || "Unknown"}</small>
            </div>
            <div>
              <span>NCSC CAF</span>
              <strong>{controls?.ncsc_caf?.score ?? 0}%</strong>
              <small>{controls?.ncsc_caf?.status || "Unknown"}</small>
            </div>
            <div>
              <span>CS&R Bill</span>
              <strong>{controls?.csr_bill?.score ?? 0}%</strong>
              <small>{controls?.csr_bill?.status || "Unknown"}</small>
            </div>
          </div>
        </div>

        <div className="v8-panel">
          <div className="v8-panel-head">
            <div>
              <h3>Commercial Readiness</h3>
              <p>Signals that matter to external relying parties.</p>
            </div>
          </div>

          <div className="v8-readiness">
            <div>
              <span>Insurance Readiness</span>
              <b>{posture.insurance_readiness_score}%</b>
              <i style={{ width: `${posture.insurance_readiness_score}%` }}></i>
            </div>
            <div>
              <span>Supply Chain Score</span>
              <b>{posture.supply_chain_score}%</b>
              <i style={{ width: `${posture.supply_chain_score}%` }}></i>
            </div>
            <div>
              <span>Compliance Score</span>
              <b>{posture.compliance_score}%</b>
              <i style={{ width: `${posture.compliance_score}%` }}></i>
            </div>
          </div>
        </div>

        <div className="v8-panel">
          <div className="v8-panel-head">
            <div>
              <h3>Live Platform Activity</h3>
              <p>Commercial proof that the platform is working continuously.</p>
            </div>
          </div>

          <div className="v8-activity">
            <div><b>RECORD</b><span>Posture version {posture.version_no} active with signed hash.</span></div>
            <div><b>BROKER</b><span>{brokerClients.length} broker client relationship available.</span></div>
            <div><b>SHARE</b><span>{sharing.length} authorised posture sharing grant found.</span></div>
            <div><b>SUPPLY</b><span>Supplier credential status: {credential?.status || "not issued"}.</span></div>
            <div><b>AI</b><span>{alerts.length} security signal(s) available for AI triage.</span></div>
          </div>
        </div>
      </section>

      <section className="v8-risk-grid">
        <div className="v8-panel">
          <div className="v8-panel-head">
            <div>
              <h3>Top Risk Drivers</h3>
              <p>What brokers, buyers and SMEs need to act on first.</p>
            </div>
          </div>

          <div className="v8-risk-list">
            {topRisks.slice(0, 6).map((risk, index) => (
              <div key={risk}>
                <b>{index + 1}</b>
                <span>{risk}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="v8-panel">
          <div className="v8-panel-head">
            <div>
              <h3>Posture Version History</h3>
              <p>Continuous monitoring evidence for audits and renewals.</p>
            </div>
          </div>

          <div className="v8-history">
            {history.slice(0, 5).map((item) => (
              <div key={item.version_id}>
                <span>v{item.version_no}</span>
                <b>{item.overall_score}</b>
                <small>{item.risk_band}</small>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="v8-feature-grid">
        {commercialModules.map((item) => (
          <button className="v8-feature" key={item.title} onClick={() => go(item.route)}>
            <span>{item.tag}</span>
            <h3>{item.title}</h3>
            <p>{item.desc}</p>
          </button>
        ))}
      </section>
    </div>
  );
}