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
  return <section className="login panel">
    <p className="eyebrow">AUTHENTICATED ACCESS</p>
    <h2>Enter the SOC</h2>
    <p className="muted">Sign in with your analyst or administrator account.</p>
    <form onSubmit={submit}>
      <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
      <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
      <button>Open dashboard</button>
      {error && <p className="error">{error}</p>}
    </form>
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

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem("nid_token") || "");
  const [dashboard, setDashboard] = useState({ summary: {}, recent_events: [], active_alerts: [] });
  const [live, setLive] = useState(false);
  const [error, setError] = useState("");
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
  const logout = () => { sessionStorage.removeItem("nid_token"); setToken(""); };
  const summary = dashboard.summary || {};
  const events = dashboard.recent_events || [];

  return <main className="shell">
    <header>
      <div><p className="eyebrow">SENTINEL // NETWORK DEFENSE</p><h1>Security Operations Center</h1></div>
      <span className={live ? "status live" : "status"}>{live ? "WebSocket live" : "Stream offline"}</span>
    </header>
    {!token ? <Login onLogin={login} /> : <>
      <div className="toolbar"><span>Production API: {API_URL || "not configured"}</span><div><button className="secondary" onClick={load}>Refresh</button><button className="secondary" onClick={logout}>Log out</button></div></div>
      {error && <p className="error banner">{error}</p>}
      <section className="metrics">
        <article><span>Total events</span><strong>{summary.total_events ?? 0}</strong></article>
        <article><span>Detected attacks</span><strong>{summary.total_attacks ?? 0}</strong></article>
        <article><span>High severity</span><strong>{summary.high_severity ?? 0}</strong></article>
        <article><span>Top source</span><strong>{summary.top_source_ip || "None"}</strong></article>
      </section>
      <CategoryChart events={events} />
      <section className="panel events">
        <div><p className="eyebrow">REAL-TIME SIEM</p><h2>Recent security events</h2></div>
        <div className="table-wrap"><table>
          <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Category</th><th>Severity</th><th>Confidence</th></tr></thead>
          <tbody>{events.map((event, index) => <tr key={event.id || index}>
            <td>{event.created_at ? new Date(event.created_at).toLocaleString() : "-"}</td>
            <td>{event.source_ip || "Unknown"}</td><td>{event.destination_ip || "Unknown"}</td>
            <td>{event.category || "Normal"}</td><td><span className={`severity ${event.severity || "Low"}`}>{event.severity || "Low"}</span></td>
            <td>{Math.round(Number(event.confidence || 0) * 100)}%</td>
          </tr>)}</tbody>
        </table></div>
        {!events.length && <p className="empty">No detector events have arrived yet.</p>}
      </section>
    </>}
  </main>;
}

export default App;
