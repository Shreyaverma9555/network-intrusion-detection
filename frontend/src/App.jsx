import React, { useCallback, useEffect, useMemo, useState } from "react";

const API_URL = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

async function api(path, token, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response;
}

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const submit = async (event) => {
    event.preventDefault();
    setError("");
    try {
      const body = new URLSearchParams({ username, password });
      const response = await api("/auth/login", "", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });
      onLogin((await response.json()).access_token);
    } catch (reason) {
      setError(reason.message);
    }
  };
  return <section className="login-shell">
    <div className="login-copy"><span className="brand-mark">S</span><p className="eyebrow">SENTINEL INTELLIGENCE</p>
      <h2>See the threat.<br/><span>Control the response.</span></h2>
      <p>A production-ready command center for network telemetry, enriched intelligence, and incident response.</p>
      <div className="login-features"><span>Live telemetry</span><span>AI explanations</span><span>Automated response</span></div>
    </div>
    <div className="login panel"><p className="eyebrow">AUTHENTICATED ACCESS</p><h2>Enter the SOC</h2><p className="muted">Sign in with your analyst or administrator account.</p>
      <form onSubmit={submit}>
        <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        <button>Open command center <span>-&gt;</span></button>{error && <p className="error">{error}</p>}
      </form>
    </div>
  </section>;
}

function CategoryChart({ events }) {
  const counts = useMemo(() => events.reduce((result, event) => {
    const name = event.category || "Normal";
    result[name] = (result[name] || 0) + 1;
    return result;
  }, {}), [events]);
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = Math.max(1, ...rows.map(([, count]) => count));
  return <section className="panel chart">
    <div><p className="eyebrow">LIVE ANALYTICS</p><h2>Detection categories</h2></div>
    <div className="bars">{rows.length ? rows.map(([name, count]) =>
      <div className="bar-row" key={name}><span>{name}</span><i style={{ width: `${(count / max) * 100}%` }} /><strong>{count}</strong></div>
    ) : <p className="muted">Waiting for detector events.</p>}</div>
  </section>;
}

function SeverityChart({ events }) {
  const counts = useMemo(() => events.reduce((out, event) => {
    const level = event.severity || "Low";
    out[level] = (out[level] || 0) + 1;
    return out;
  }, {}), [events]);
  const total = Math.max(events.length, 1);
  const critical = (counts.Critical || 0) / total * 100;
  const high = critical + (counts.High || 0) / total * 100;
  const medium = high + (counts.Medium || 0) / total * 100;
  const gradient = `conic-gradient(#ff4d82 0 ${critical}%, #ff9f43 ${critical}% ${high}%, #a66cff ${high}% ${medium}%, #2dd4bf ${medium}% 100%)`;
  return <section className="panel severity-card">
    <div><p className="eyebrow">RISK DISTRIBUTION</p><h2>Severity posture</h2></div>
    <div className="donut-wrap"><div className="donut" style={{ background: gradient }}><div><strong>{events.length}</strong><span>events</span></div></div>
      <div className="legend">{["Critical", "High", "Medium", "Low"].map(level => <span key={level}><i className={`dot ${level}`} />{level}<b>{counts[level] || 0}</b></span>)}</div>
    </div>
  </section>;
}

function IncidentPanel({ event, token, onClose }) {
  const [output, setOutput] = useState("");
  const [status, setStatus] = useState("");
  if (!event) return null;
  const eventStats = typeof event.statistics === "string" ? JSON.parse(event.statistics || "{}") : (event.statistics || {});
  const action = async (kind) => {
    setStatus("Working...");
    try {
      if (kind === "pdf") {
        const response = await api(`/events/${event.id}/report.pdf`, token);
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement("a");
        link.href = url; link.download = `soc-incident-${event.id}.pdf`; link.click();
        URL.revokeObjectURL(url); setStatus("PDF downloaded"); return;
      }
      const path = kind === "intel" ? `/threat-intel/${encodeURIComponent(event.source_ip)}?external=true` : kind === "explain" ? `/events/${event.id}/explain` : `/events/${event.id}/notify`;
      const response = await api(path, token, kind === "alert" ? { method: "POST" } : {});
      const data = await response.json();
      setOutput(kind === "explain" ? (data.report || data.explanation || JSON.stringify(data, null, 2)) : JSON.stringify(data, null, 2));
      setStatus("Complete");
    } catch (reason) { setStatus(reason.message); }
  };
  return <aside className="incident">
    <button className="icon-button" onClick={onClose}>x</button><p className="eyebrow">INCIDENT WORKBENCH</p><h2>{event.category || "Security event"}</h2>
    <span className={`severity ${event.severity || "Low"}`}>{event.severity || "Low"} priority</span>
    <div className="incident-grid"><div><span>Source</span><strong>{event.source_ip || "Not captured"}</strong></div><div><span>Destination</span><strong>{event.destination_ip || "Not captured"}</strong></div><div><span>Confidence</span><strong>{Math.round(Number(event.confidence || 0) * 100)}%</strong></div><div><span>MITRE</span><strong>{eventStats.mitre_technique_ids || "Unmapped"}</strong></div></div>
    <div className="intel-box"><span>Threat intelligence</span><strong>{eventStats.threat_intel_provider || event.reputation || "Lookup available"}</strong><p>{event.source_country || "Unknown region"} - {eventStats.threat_intel_organization || eventStats.threat_intel_asn || "Unknown network"}</p></div>
    <div className="actions"><button onClick={() => action("intel")} disabled={!event.source_ip}>Enrich IP</button><button onClick={() => action("explain")}>AI explain</button><button onClick={() => action("alert")}>Notify team</button><button className="secondary" onClick={() => action("pdf")}>PDF report</button></div>
    {status && <p className="action-status">{status}</p>}{output && <pre className="report">{output}</pre>}
  </aside>;
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem("nid_token") || "");
  const [dashboard, setDashboard] = useState({ summary: {}, recent_events: [], active_alerts: [] });
  const [live, setLive] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const load = useCallback(async () => {
    if (!token) return;
    try {
      const response = await api("/api/dashboard", token);
      setDashboard(await response.json());
      setError("");
    } catch (reason) {
      setError(reason.message);
      if (/401|expired|token/i.test(reason.message)) setToken("");
    }
  }, [token]);

  useEffect(() => {
    if (!token) return;
    sessionStorage.setItem("nid_token", token);
    load();
    const timer = setInterval(load, 20000);
    const socket = new WebSocket(API_URL.replace(/^http/, "ws") + "/ws/events");
    socket.onopen = () => socket.send(JSON.stringify({ token }));
    socket.onmessage = ({ data }) => {
      const message = JSON.parse(data);
      if (message.type === "ready") setLive(true);
      if (message.type === "detection") {
        setDashboard((current) => ({
          ...current,
          recent_events: [message.event, ...current.recent_events].slice(0, 100)
        }));
      }
    };
    socket.onclose = () => setLive(false);
    return () => { clearInterval(timer); socket.close(); };
  }, [token, load]);

  const login = (value) => { sessionStorage.setItem("nid_token", value); setToken(value); };
  const logout = () => { sessionStorage.removeItem("nid_token"); setToken(""); setSelected(null); };
  const summary = dashboard.summary || {};
  const events = dashboard.recent_events || [];

  return <main className="shell">
    <header>
      <div className="brand"><span className="brand-mark">S</span><div><p className="eyebrow">SENTINEL // NETWORK DEFENSE</p><h1>Security Operations Center</h1></div></div>
      <span className={live ? "status live" : "status"}>{live ? "Live telemetry" : "Stream offline"}</span>
    </header>
    {!token ? <Login onLogin={login} /> : <>
      <div className="toolbar"><span>Production API: {API_URL || "not configured"}</span><div><button className="secondary" onClick={load}>Refresh</button><button className="secondary" onClick={logout}>Log out</button></div></div>
      {error && <p className="error banner">{error}</p>}
      <section className="metrics">
        <article className="metric-cyan"><span>Total events</span><strong>{summary.total_events ?? 0}</strong><small>Network observations</small></article>
        <article className="metric-violet"><span>Detected attacks</span><strong>{summary.total_attacks ?? 0}</strong><small>Actionable signals</small></article>
        <article className="metric-red"><span>High severity</span><strong>{summary.high_severity ?? 0}</strong><small>Require investigation</small></article>
        <article className="metric-green"><span>Top source</span><strong>{summary.top_source_ip || "No traffic"}</strong><small>Most active origin</small></article>
      </section>
      <section className="visual-grid"><CategoryChart events={events} /><SeverityChart events={events} /></section>
      <section className="panel events">
        <div><p className="eyebrow">REAL-TIME SIEM</p><h2>Recent security events</h2></div>
        <div className="table-wrap"><table>
          <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Category</th><th>Severity</th><th>Confidence</th></tr></thead>
          <tbody>{events.map((event, index) => <tr key={event.id || index} onClick={() => setSelected(event)}>
            <td>{event.created_at ? new Date(event.created_at).toLocaleString() : "-"}</td>
            <td>{event.source_ip || "Unknown"}</td><td>{event.destination_ip || "Unknown"}</td>
            <td>{event.category || "Normal"}</td><td><span className={`severity ${event.severity || "Low"}`}>{event.severity || "Low"}</span></td>
            <td>{Math.round(Number(event.confidence || 0) * 100)}%</td>
          </tr>)}</tbody>
        </table></div>
        {!events.length && <p className="empty">No packets captured yet. Start the detector to stream network events.</p>}
      </section>
    </>}
    {selected && <IncidentPanel event={selected} token={token} onClose={() => setSelected(null)} />}
  </main>;
}

export default App;
