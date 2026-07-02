from __future__ import annotations

import json
import os
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.nid.blocking import block_ip
from src.nid.auth import dashboard_auth_enabled, dashboard_credentials, dashboard_role, password_matches
from src.nid.explain import explain_event
from src.nid.incident_report import incident_report
from src.nid.processor import ProcessingPolicy, RealTimeProcessor
from src.nid.postgres import PostgresRepository
from src.nid.realtime import DetectionEvent
from src.nid.scapy_capture import list_interfaces
from src.nid.security_analyst import security_analyst_report
from src.nid.visualization import attack_map_figure, geo_attack_table, network_figure
from src.nid.xai import xai_markdown


st.set_page_config(page_title="AI Network Security Operations Center", layout="wide")
st.markdown(
    """
    <style>
    .block-container {padding-top: 1.2rem; padding-bottom: 2rem;}
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #111827, #1f2937);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 12px;
    }
    div[data-testid="stMetric"] label, div[data-testid="stMetric"] div {color: #f9fafb;}
    </style>
    """,
    unsafe_allow_html=True,
)
st.title("AI Network Security Operations Center")
st.caption("Live monitoring, threat intelligence, XAI, SIEM analytics, attack maps, response, and alerts")

if dashboard_auth_enabled() and not st.session_state.get("authenticated"):
    configured_user, configured_password, configured_hash = dashboard_credentials()
    st.subheader("SOC Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login", type="primary"):
        if username == configured_user and password_matches(password, configured_password, configured_hash):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.role = dashboard_role()
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.stop()
elif dashboard_auth_enabled():
    st.caption(
        f"Authenticated as {st.session_state.get('username', 'analyst')} "
        f"({st.session_state.get('role', dashboard_role())})"
    )

dashboard_user_role = st.session_state.get("role", dashboard_role())
dashboard_can_respond = dashboard_user_role in {"admin", "analyst"}

@st.cache_resource
def processor(postgres_dsn: str, postgres_ready: bool) -> RealTimeProcessor:
    repository = PostgresRepository(postgres_dsn) if postgres_ready else None
    return RealTimeProcessor(
        "models/sample_ensemble.joblib",
        min_packets=int(os.getenv("NID_MIN_PACKETS", "10")),
        policy=ProcessingPolicy(save_events=postgres_ready),
        store=repository,
    )


@st.cache_resource
def store(postgres_dsn: str) -> PostgresRepository:
    repository = PostgresRepository(postgres_dsn)
    repository.initialize()
    return repository


postgres_dsn = os.getenv("NID_POSTGRES_DSN", "")
postgres_repository: PostgresRepository | None = None
postgres_connection_error: str | None = None
if postgres_dsn:
    try:
        postgres_repository = store(postgres_dsn)
    except Exception as error:
        postgres_connection_error = str(error)
else:
    postgres_connection_error = (
        "PostgreSQL server credentials are not configured. Run `python soc.py setup-postgres` "
        "to create the NID database, save the DSN, and enable analytics and automatic response."
    )
postgres_ready = postgres_repository is not None


@st.cache_data(ttl=30)
def database_summary(postgres_dsn: str, postgres_ready: bool) -> tuple[dict[str, object], str | None]:
    empty = {
        "total_attacks": 0,
        "attacks_today": 0,
        "high_severity": 0,
        "top_attack_type": "Unavailable",
        "most_dangerous_ip": "Unavailable",
        "top_source_ip": "Unavailable",
        "most_targeted_host": "Unavailable",
    }
    if not postgres_ready:
        return empty, postgres_connection_error
    try:
        return store(postgres_dsn).summary(), None
    except Exception as error:
        return empty, str(error)


def analyze_window(
    source: str,
    interface: str | None,
    seconds: float,
    external_intel: bool,
    notify: bool,
    auto_block: bool,
    auto_response: bool = False,
    alert_min_severity: str = "High",
    save_events: bool = True,
    block_confidence: float = 0.90,
    block_threat_score: float = 75.0,
    alert_cooldown: int = 300,
    full_shap_live: bool = False,
    packet_limit: int = 500,
    alert_threshold: float = 0.75,
):
    engine = processor(postgres_dsn, postgres_ready)
    engine.detector.threshold = alert_threshold
    engine.live_xai_mode = "shap" if full_shap_live else "adaptive"
    engine.policy = ProcessingPolicy(
        use_external_threat_intel=external_intel,
        save_events=save_events,
        send_notifications=notify,
        alert_min_severity=alert_min_severity,
        auto_block=auto_block,
        auto_response=auto_response,
        alert_cooldown_seconds=alert_cooldown,
        block_min_confidence=block_confidence,
        block_min_threat_score=block_threat_score,
    )
    return (
        engine.process_file("data/live_packets.csv")
        if source == "Demo capture"
        else engine.process_live_window(interface, seconds, packet_limit)
    )


with st.sidebar:
    st.header("Monitoring Controls")
    source = st.radio("Packet source", ["Demo capture", "Live Scapy capture"])
    try:
        interfaces = list_interfaces()
    except FileNotFoundError:
        interfaces = []
    interface = st.selectbox("WiFi / Ethernet interface", interfaces) if interfaces else None
    seconds = st.slider(
        "Capture window (seconds)",
        0.25,
        10.0,
        float(os.getenv("NID_WINDOW_SECONDS", "0.5")),
        0.25,
    )
    full_shap_live = st.checkbox(
        "Full SHAP on every live window (slower)",
        value=os.getenv("NID_FULL_SHAP_LIVE", "0") == "1",
    )
    st.caption("Adaptive mode uses fast window attribution for Normal traffic and full SHAP for detected threats.")
    alert_threshold = st.slider(
        "Model threat-score threshold",
        0.50,
        0.99,
        float(os.getenv("NID_ALERT_THRESHOLD", "0.75")),
        0.01,
        help="An alert requires both this model score and sufficient behavioral evidence.",
    )
    packet_limit = st.slider(
        "Maximum packets per window",
        50,
        5000,
        int(os.getenv("NID_PACKET_LIMIT", "500")),
        50,
    )
    external_intel = st.checkbox("External IP reputation and GeoIP")
    notify = st.checkbox("Send configured alerts")
    alert_min_severity = st.selectbox(
        "Minimum alert severity",
        ["Medium", "High", "Critical"],
        index=["Medium", "High", "Critical"].index(os.getenv("NID_ALERT_MIN_SEVERITY", "High")),
    )
    alert_cooldown = st.slider(
        "Duplicate alert cooldown (seconds)",
        0,
        3600,
        int(os.getenv("NID_ALERT_COOLDOWN_SECONDS", "300")),
        30,
    )
    auto_block = st.checkbox("Automatically block confirmed public threats", disabled=not postgres_ready or not dashboard_can_respond)
    auto_response = st.checkbox(
        "High severity auto-response: log, alert, block",
        value=postgres_ready and os.getenv("NID_AUTO_RESPONSE", "0") == "1",
        disabled=not postgres_ready or not dashboard_can_respond,
    )
    st.caption("Auto-blocking is public-IP-only and requires Administrator privileges plus admin/analyst dashboard role.")
    block_confidence = st.slider(
        "Auto-block minimum decision support",
        0.75,
        1.0,
        float(os.getenv("NID_BLOCK_MIN_CONFIDENCE", "0.90")),
        0.01,
    )
    block_threat_score = st.slider(
        "Auto-block minimum reputation score",
        50,
        100,
        int(float(os.getenv("NID_BLOCK_MIN_THREAT_SCORE", "75"))),
    )
    st.caption("PostgreSQL analytics: " + ("connected" if postgres_ready else "setup needed"))
    use_llm = st.checkbox("Use AI security assistant", value=True)
    auto_monitor = st.checkbox("Continuous live monitoring")
    run = st.button("Analyze Packet Window", type="primary", width="stretch")

if "event" not in st.session_state:
    initial = analyze_window(
        "Demo capture",
        None,
        seconds,
        False,
        False,
        False,
        False,
        save_events=postgres_ready,
        alert_threshold=alert_threshold,
    )
    st.session_state.event = initial.event
    st.session_state.actions = initial.actions
    st.session_state.errors = initial.errors
    st.session_state.window_counts = {initial.event.category: 1}
    st.session_state.scope_counts = {initial.event.traffic_scope: 1}
if run or (auto_monitor and source == "Live Scapy capture"):
    try:
        result = analyze_window(
            source,
            interface,
            seconds,
            external_intel,
            notify,
            auto_block,
            auto_response,
            alert_min_severity,
            postgres_ready,
            block_confidence,
            float(block_threat_score),
            alert_cooldown,
            full_shap_live,
            packet_limit,
            alert_threshold,
        )
        st.session_state.event = result.event
        st.session_state.actions = result.actions
        st.session_state.errors = result.errors
        counts = st.session_state.get("window_counts", {})
        counts[result.event.category] = counts.get(result.event.category, 0) + 1
        st.session_state.window_counts = counts
        scope_counts = st.session_state.get("scope_counts", {})
        scope_counts[result.event.traffic_scope] = scope_counts.get(result.event.traffic_scope, 0) + 1
        st.session_state.scope_counts = scope_counts
    except Exception as error:
        st.error(str(error))
        auto_monitor = False

event: DetectionEvent = st.session_state.event
if postgres_ready:
    try:
        history = pd.DataFrame(store(postgres_dsn).recent(500))
    except Exception as error:
        st.error(f"PostgreSQL history unavailable: {error}")
        history = pd.DataFrame()
else:
    history = pd.DataFrame()
if not history.empty:
    history["statistics_parsed"] = history["statistics"].map(json.loads)
summary, postgres_error = database_summary(postgres_dsn, postgres_ready)

capabilities = st.columns(4)
capabilities[0].metric("Streamlit Dashboard", "ACTIVE")
capabilities[1].metric("SHAP Explainability", "FULL" if full_shap_live else "ADAPTIVE")
capabilities[2].metric("PostgreSQL Analytics", "CONNECTED" if postgres_ready else "SETUP NEEDED")
capabilities[3].metric("Automatic Response", "ARMED" if auto_response else "DISARMED")


def top_threats_table(events: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    columns = [
        "Rank",
        "Source IP",
        "Destination IP",
        "Attack Type",
        "Severity",
        "Decision Support",
        "Threat Score",
        "Risk Score",
        "Occurrences",
        "Latest Detection",
        "Blocked",
    ]
    if events.empty:
        return pd.DataFrame(columns=columns)
    threats = events[events["predicted_attack"].eq(1)].copy()
    if threats.empty:
        return pd.DataFrame(columns=columns)
    severity_score = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    threats["severity_rank"] = threats["severity"].map(severity_score).fillna(0)
    threats["risk_score"] = (
        threats["severity_rank"] * 25
        + threats["confidence"].astype(float) * 50
        + threats["threat_score"].astype(float) * 0.25
    )
    grouped = (
        threats.groupby(["source_ip", "destination_ip", "category"], dropna=False)
        .agg(
            severity=("severity", lambda values: max(values, key=lambda value: severity_score.get(value, 0))),
            confidence=("confidence", "max"),
            threat_score=("threat_score", "max"),
            occurrences=("category", "size"),
            latest=("created_at", "max"),
            blocked=("blocked", "max"),
            risk_score=("risk_score", "max"),
        )
        .sort_values(["risk_score", "occurrences"], ascending=False)
        .head(limit)
        .reset_index()
    )
    grouped.insert(0, "Rank", range(1, len(grouped) + 1))
    grouped["confidence"] = grouped["confidence"].map(lambda value: f"{float(value):.1%}")
    grouped["threat_score"] = grouped["threat_score"].map(lambda value: f"{float(value):.0f}%")
    grouped["risk_score"] = grouped["risk_score"].map(lambda value: f"{float(value):.1f}")
    grouped["blocked"] = grouped["blocked"].map({0: "No", 1: "Yes", False: "No", True: "Yes"})
    grouped["latest"] = grouped["latest"].map(
        lambda value: datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M:%S")
    )
    grouped = grouped.rename(
        columns={
            "source_ip": "Source IP",
            "destination_ip": "Destination IP",
            "category": "Attack Type",
            "severity": "Severity",
            "confidence": "Decision Support",
            "threat_score": "Threat Score",
            "risk_score": "Risk Score",
            "occurrences": "Occurrences",
            "latest": "Latest Detection",
            "blocked": "Blocked",
        }
    )
    return grouped[columns]


def threat_timeline_figure(events: pd.DataFrame) -> go.Figure:
    frame = events.sort_values("created_at").copy()
    return px.line(
        frame,
        x="created_at",
        y=["attack_probability", "confidence"],
        title="Model Threat Score and Decision Support",
        labels={"value": "Score", "created_at": "Time", "variable": "Signal"},
        color_discrete_map={"attack_probability": "#ef4444", "confidence": "#38bdf8"},
    ).update_layout(
        legend_title_text="",
        hovermode="x unified",
    ).for_each_trace(
        lambda trace: trace.update(
            name={"attack_probability": "Model Threat Score", "confidence": "Decision Support"}.get(
                trace.name, trace.name
            )
        )
    )


def category_figure(events: pd.DataFrame) -> go.Figure:
    counts = events["category"].value_counts().rename_axis("Attack Type").reset_index(name="Count")
    return px.bar(
        counts,
        x="Attack Type",
        y="Count",
        color="Count",
        color_continuous_scale="Reds",
        title="Attack Category Distribution",
    ).update_layout(coloraxis_showscale=False)


def host_figure(events: pd.DataFrame, column: str, title: str) -> go.Figure:
    counts = events[column].replace("", "Unknown").value_counts().head(10).rename_axis("Host").reset_index(name="Count")
    return px.bar(counts, x="Count", y="Host", orientation="h", title=title, color="Count", color_continuous_scale="Blues")


analysis_latency_ms = float((event.statistics or {}).get("analysis_latency_ms", 0))
analysis_health = "Fast" if analysis_latency_ms < 100 else "Moderate" if analysis_latency_ms < 250 else "High"
cards = st.columns(17)
cards[0].metric("Packets/sec", (event.statistics or {}).get("packets_per_second", 0))
cards[1].metric("Active Connections", (event.statistics or {}).get("active_connections", 0))
cards[2].metric("Source IP", event.source_display)
cards[3].metric("Destination IP", event.destination_display)
cards[4].metric("Primary Flow Scope", event.traffic_scope)
cards[5].metric("Threat Count", summary["total_attacks"])
cards[6].metric("Attacks Today", summary["attacks_today"])
cards[7].metric("Current Attack", event.category)
cards[8].metric(
    "Model Threat Score",
    f"{event.model_threat_score:.1%}",
    help="Robust model-only window score derived from median and P90 packet predictions; not a calibrated probability.",
)
cards[9].metric(
    "Decision Support",
    f"{event.confidence:.1%}",
    help="Support for the final class from the model score and behavioral evidence; not a calibrated probability.",
)
cards[10].metric("Threat Intel", f"{event.threat_score:.0f}%")
cards[11].metric("High Severity Today", summary["high_severity"])
cards[12].metric("Window Latency", f"{(event.statistics or {}).get('window_latency_ms', 0):.0f} ms")
cards[13].metric(
    "Decision Uncertainty",
    "Insufficient Evidence"
    if (event.statistics or {}).get("evidence_state") == "Insufficient sample"
    else f"{float((event.statistics or {}).get('decision_uncertainty', 1 - event.confidence)):.1%}",
)
cards[14].metric("Capture Latency", f"{float((event.statistics or {}).get('capture_latency_ms', 0)):.0f} ms")
cards[15].metric("Analysis Latency", f"{analysis_latency_ms:.0f} ms")
cards[16].metric(
    "Analysis Health",
    analysis_health,
    help="Rates detection analysis only; the selected Scapy capture-window duration is intentionally excluded.",
)

if event.predicted_attack:
    st.error(f"{event.severity} {event.category} threat from {event.source_ip or 'unknown source'}")
else:
    st.success(f"Current classification: {event.category}")
if st.session_state.get("actions"):
    st.caption("Real-time actions: " + ", ".join(st.session_state.actions))
for error in st.session_state.get("errors", []):
    st.warning(error)
if postgres_error:
    st.warning(f"PostgreSQL analytics unavailable: {postgres_error}")

live_tab, intel_tab, xai_tab, analyst_tab, report_tab, quality_tab, validation_tab, map_tab, network_tab, siem_tab, response_tab = st.tabs(
    [
        "Live Monitoring",
        "Threat Intelligence",
        "Explainable AI",
        "AI Security Analyst",
        "Incident Report",
        "Model Quality",
        "Attack Validation",
        "Attack Map",
        "Network Graph",
        "SIEM Logs",
        "Response",
    ]
)

with live_tab:
    st.subheader("Local Traffic Classification")
    scope_columns = st.columns(6)
    scope_columns[0].metric("Primary Flow Scope", event.traffic_scope)
    scope_columns[1].metric(
        "Dominant Window Scope",
        str((event.statistics or {}).get("dominant_traffic_scope", event.traffic_scope)),
    )
    scope_columns[2].metric("Local LAN", f"{float((event.statistics or {}).get('local_lan_traffic_rate', 0)):.1%}")
    scope_columns[3].metric("Outbound", f"{float((event.statistics or {}).get('outbound_traffic_rate', 0)):.1%}")
    scope_columns[4].metric("Inbound", f"{float((event.statistics or {}).get('inbound_traffic_rate', 0)):.1%}")
    scope_columns[5].metric(
        "Same Source/Destination",
        f"{int((event.statistics or {}).get('same_endpoint_packet_count', 0))} "
        f"({float((event.statistics or {}).get('same_endpoint_traffic_rate', 0)):.1%})",
        help=f"Observed self-addressed hosts: {(event.statistics or {}).get('same_endpoint_addresses', 'None') or 'None'}",
    )
    signature_columns = st.columns(3)
    signature_columns[0].metric("Top Rule Signature", str((event.statistics or {}).get("rule_engine_top_rule", "None")))
    signature_columns[1].metric("Rule Match Score", f"{float((event.statistics or {}).get('rule_engine_top_score', 0)):.1%}")
    signature_columns[2].metric("Rule Matches", int((event.statistics or {}).get("rule_engine_match_count", 0)))
    st.caption(f"Matched signatures: {(event.statistics or {}).get('rule_engine_matches', 'None')}")
    scope_counts = pd.DataFrame(
        [
            {"Traffic Scope": scope, "Windows": count}
            for scope, count in st.session_state.get("scope_counts", {}).items()
        ]
    )
    if not scope_counts.empty:
        st.plotly_chart(px.bar(scope_counts, x="Traffic Scope", y="Windows", color="Traffic Scope"), width="stretch")
    st.subheader("Current Session Distribution")
    session_counts = pd.DataFrame(
        [
            {"Category": category, "Windows": count}
            for category, count in st.session_state.get("window_counts", {}).items()
        ]
    )
    if not session_counts.empty:
        st.plotly_chart(px.bar(session_counts, x="Category", y="Windows", color="Category"), width="stretch")
    st.subheader("Top Threats")
    st.dataframe(top_threats_table(history), width="stretch", hide_index=True)
    left, right = st.columns(2)
    with left:
        st.subheader("Threat Graph")
        if not history.empty:
            st.plotly_chart(threat_timeline_figure(history), width="stretch")
        st.subheader("Attack Timeline")
        attacks = history[history["predicted_attack"].eq(1)] if not history.empty else history
        if not attacks.empty:
            st.dataframe(attacks[["created_at", "category", "severity", "source_ip"]], width="stretch", hide_index=True)
    with right:
        st.subheader("Normal vs Attack")
        if not history.empty:
            ratio = history["predicted_attack"].map({0: "Normal", 1: "Attack"}).value_counts().reset_index()
            st.plotly_chart(px.pie(ratio, names="predicted_attack", values="count", hole=0.45), width="stretch")
        st.subheader("Attack Statistics")
        if not history.empty:
            st.plotly_chart(category_figure(history), width="stretch")
        st.subheader("Severity Distribution")
        if not history.empty:
            severity = history["severity"].value_counts().reset_index()
            st.plotly_chart(px.bar(severity, x="severity", y="count", color="severity"), width="stretch")

with intel_tab:
    st.subheader("Source IP Reputation")
    intel_columns = st.columns(6)
    intel_columns[0].metric("Source IP", event.source_display)
    intel_columns[1].metric("Destination IP", event.destination_display)
    intel_columns[2].metric("Country", event.source_country)
    intel_columns[3].metric("Threat Score", f"{event.threat_score:.0f}%")
    intel_columns[4].metric("Intel Status", str((event.statistics or {}).get("threat_intel_status", "Not checked")))
    intel_columns[5].metric("Provider", str((event.statistics or {}).get("threat_intel_provider", "Local")))
    st.write("Reputation labels:", ", ".join(event.threat_labels or ["No known malicious reputation"]))
    st.write(
        "Port intelligence:",
        f"{(event.statistics or {}).get('top_destination_port', 0)} "
        f"{(event.statistics or {}).get('port_service', 'Unknown service')} "
        f"risk={(event.statistics or {}).get('port_risk', 'Unknown')}",
    )
    st.write(
        "Ownership:",
        f"ASN={(event.statistics or {}).get('threat_intel_asn', '') or 'Unknown'}, "
        f"ISP={(event.statistics or {}).get('threat_intel_isp', '') or 'Unknown'}, "
        f"Org={(event.statistics or {}).get('threat_intel_organization', '') or 'Unknown'}",
    )
    st.write("Protocol summary:", (event.statistics or {}).get("protocol_summary", "Unknown"))
    mitre_entries = (event.statistics or {}).get("mitre_attack", [])
    st.subheader("MITRE ATT&CK Mapping")
    mitre_columns = st.columns(3)
    mitre_columns[0].metric("Tactics", (event.statistics or {}).get("mitre_tactics", "None"))
    mitre_columns[1].metric("Technique IDs", (event.statistics or {}).get("mitre_technique_ids", "None"))
    mitre_columns[2].metric("Techniques", len(mitre_entries) if isinstance(mitre_entries, list) else 0)
    if isinstance(mitre_entries, list) and mitre_entries:
        st.dataframe(pd.DataFrame(mitre_entries), width="stretch", hide_index=True)
    st.info("Enable external reputation and GeoIP to query configured services. Private IPs remain local.")

with xai_tab:
    st.subheader(f"Why the model classified this window as {event.category}")
    st.markdown(xai_markdown(event))
    evidence = pd.DataFrame(event.top_features or [])
    if not evidence.empty:
        if "raw_feature" not in evidence:
            evidence["raw_feature"] = evidence["feature"]
        if "direction" not in evidence:
            evidence["direction"] = "Window activity"
        if "signed_contribution" not in evidence:
            evidence["signed_contribution"] = None
        method = str(evidence.iloc[0].get("method", "Feature attribution"))
        xai_metrics = st.columns(4)
        xai_metrics[0].metric("Explanation Method", method)
        xai_metrics[1].metric("Decision Support", f"{event.confidence:.1%}")
        xai_metrics[2].metric(
            "Decision Uncertainty",
            "Insufficient Evidence"
            if (event.statistics or {}).get("evidence_state") == "Insufficient sample"
            else f"{float((event.statistics or {}).get('decision_uncertainty', 1 - event.confidence)):.1%}",
        )
        xai_metrics[3].metric("Features Explained", len(evidence))

        chart_data = evidence.sort_values("importance", ascending=True)
        figure = px.bar(
            chart_data,
            x="importance",
            y="feature",
            orientation="h",
            color="direction",
            color_discrete_map={
                "Supports final class": "#22c55e",
                "Opposes final class": "#ef4444",
                "Window activity": "#38bdf8",
            },
            labels={"importance": "Relative contribution", "feature": "Traffic feature"},
            title=f"{method}: Current Window Contributions",
        )
        figure.update_layout(xaxis_tickformat=".0%", legend_title_text="Contribution direction")
        st.plotly_chart(figure, width="stretch")

        table = evidence.sort_values("importance", ascending=False).reset_index(drop=True)
        table.insert(0, "rank", table.index + 1)
        table["importance"] = table["importance"].map(lambda value: f"{float(value):.1%}")
        if "signed_contribution" in table:
            table["signed_contribution"] = table["signed_contribution"].map(
                lambda value: "" if pd.isna(value) else f"{float(value):+.4f}"
            )
        table = table.rename(
            columns={
                "rank": "Rank",
                "feature": "Explanation",
                "raw_feature": "Model Feature",
                "importance": "Contribution",
                "method": "Method",
                "direction": "Direction",
                "signed_contribution": "Signed SHAP",
            }
        )
        st.dataframe(table, width="stretch", hide_index=True)
        if "SHAP" not in method:
            st.info("Enable 'Full SHAP on every live window' in the sidebar for SHAP explanations.")
    st.subheader("AI Security Assistant")
    st.text(explain_event(event, use_llm=use_llm))

with analyst_tab:
    st.subheader("AI Security Analyst")
    analyst_report = security_analyst_report(event, use_llm=use_llm)
    st.markdown(analyst_report)
    st.download_button(
        "Download Analyst Assessment",
        analyst_report,
        file_name=f"analyst-assessment-{datetime.fromtimestamp(event.timestamp).strftime('%Y%m%d-%H%M%S')}.md",
        mime="text/markdown",
    )

with report_tab:
    st.subheader("AI Incident Report")
    report = incident_report(event, use_llm=use_llm)
    st.markdown(report)
    st.download_button(
        "Download Incident Report",
        report,
        file_name=f"incident-{datetime.fromtimestamp(event.timestamp).strftime('%Y%m%d-%H%M%S')}.md",
        mime="text/markdown",
    )

with quality_tab:
    st.subheader("Model Evaluation")
    metrics_path = "reports/sample_metrics.json"
    try:
        with open(metrics_path, encoding="utf-8") as metrics_file:
            metrics = json.load(metrics_file)
    except (OSError, json.JSONDecodeError):
        metrics = {}
    if metrics:
        quality_cards = st.columns(8)
        quality_cards[0].metric("Accuracy", f"{float(metrics.get('accuracy', 0)):.1%}")
        quality_cards[1].metric("Precision", f"{float(metrics.get('precision', 0)):.1%}")
        quality_cards[2].metric("Recall", f"{float(metrics.get('recall', 0)):.1%}")
        quality_cards[3].metric("F1 Score", f"{float(metrics.get('f1', 0)):.1%}")
        quality_cards[4].metric("ROC-AUC", f"{float(metrics.get('roc_auc', 0)):.1%}")
        quality_cards[5].metric("Calibration", str(metrics.get("calibration_method", "none")))
        quality_cards[6].metric("Brier", f"{float(metrics.get('brier_score_calibrated', 0)):.3f}")
        quality_cards[7].metric("ECE", f"{float(metrics.get('expected_calibration_error_calibrated', 0)):.3f}")
        bins = pd.DataFrame(metrics.get("calibration_bins", []))
        if not bins.empty:
            bins["bin"] = bins["bin_start"].map(lambda value: f"{float(value):.1f}") + "-" + bins["bin_end"].map(lambda value: f"{float(value):.1f}")
            st.plotly_chart(
                px.bar(
                    bins,
                    x="bin",
                    y=["mean_score", "observed_attack_rate"],
                    barmode="group",
                    title="Calibration Curve: Mean Score vs Observed Attack Rate",
                    labels={"value": "Rate", "bin": "Score Bin", "variable": "Signal"},
                ),
                width="stretch",
            )
        matrix = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
        st.plotly_chart(
            px.imshow(
                matrix,
                text_auto=True,
                x=["Predicted Normal", "Predicted Attack"],
                y=["Actual Normal", "Actual Attack"],
                title="Confusion Matrix",
                color_continuous_scale="Blues",
            ),
            width="stretch",
        )
        rows = int(metrics.get("rows", 0))
        test_rows = int(metrics.get("test_rows", 0))
        if rows < 1000 or test_rows < 200:
            st.warning(
                f"Evaluation is not deployment-grade: only {rows} total rows and {test_rows} test rows. "
                "Train on a large representative dataset before trusting the displayed scores."
            )
    else:
        st.info("Run `python train_model.py` to generate accuracy, precision, recall, F1, ROC-AUC, and confusion matrix.")

with validation_tab:
    st.subheader("Attack Validation")
    validation_path = "reports/attack_validation.json"
    try:
        with open(validation_path, encoding="utf-8") as validation_file:
            validation = json.load(validation_file)
    except (OSError, json.JSONDecodeError):
        validation = {}

    if validation:
        validation_cards = st.columns(5)
        validation_cards[0].metric("Status", "Ready" if validation.get("ready") else "Needs Work")
        validation_cards[1].metric("Passed", f"{int(validation.get('passed', 0))}/{int(validation.get('total', 0))}")
        validation_cards[2].metric("Failed", int(validation.get("failed", 0)))
        validation_cards[3].metric("PostgreSQL", "Checked" if validation.get("postgres_requested") else "Skipped")
        validation_cards[4].metric("Generated", str(validation.get("generated_at", ""))[:19])

        results = pd.DataFrame(validation.get("results", []))
        if not results.empty:
            display_columns = [
                "status",
                "scenario",
                "category",
                "severity",
                "decision_support",
                "model_threat_score",
                "behavior_score",
                "threat_score",
                "source_country",
                "source_latitude",
                "source_longitude",
                "source_ip",
                "destination_ip",
                "postgres_logged",
            ]
            st.dataframe(results[[column for column in display_columns if column in results.columns]], width="stretch", hide_index=True)
            failures = results[results["status"].ne("PASS")] if "status" in results.columns else pd.DataFrame()
            if not failures.empty:
                st.error("One or more validation scenarios failed.")
                for _, row in failures.iterrows():
                    st.write(f"{row['scenario']}: {'; '.join(row.get('details') or [])}")
            else:
                st.success("All synthetic attack and benign baseline scenarios passed.")
        st.caption("Refresh this report with `python soc.py validate-attacks` or `python validate_attacks.py --no-postgres`.")
    else:
        st.info("Run `python soc.py validate-attacks` to generate reports/attack_validation.json.")

with map_tab:
    st.subheader("Geo-IP Attack Map")
    geo_table = geo_attack_table(history)
    attack_history = history[history["predicted_attack"].eq(1)] if not history.empty else history
    mapped_events = 0
    if not attack_history.empty and "statistics_parsed" in attack_history:
        mapped_events = int(
            attack_history["statistics_parsed"].map(
                lambda stats: isinstance(stats, dict)
                and "source_latitude" in stats
                and "source_longitude" in stats
            ).sum()
        )
    geo_cards = st.columns(4)
    geo_cards[0].metric("Mapped Attacks", mapped_events)
    geo_cards[1].metric("Unmapped Attacks", max(int(len(attack_history)) - mapped_events, 0))
    geo_cards[2].metric("Countries", 0 if geo_table.empty else int(geo_table["Country"].nunique()))
    geo_cards[3].metric("Top Country", "None" if geo_table.empty else str(geo_table.iloc[0]["Country"]))
    st.plotly_chart(attack_map_figure(history), width="stretch")
    if not geo_table.empty:
        st.subheader("Attacks by Country")
        st.dataframe(geo_table, width="stretch", hide_index=True)
        st.plotly_chart(px.bar(geo_table, x="Country", y="Attacks", color="Top Attack"), width="stretch")
    st.caption(
        "Coordinates come from configs/geoip_locations.json first, then external GeoIP when "
        "`NID_ENABLE_GEOIP=1` and external reputation is enabled. Private IPs stay unmapped."
    )

with network_tab:
    st.subheader("Live Network Visualization")
    st.plotly_chart(network_figure(history), width="stretch")
    st.caption("Red links indicate malicious traffic; green links indicate normal traffic.")

with siem_tab:
    siem_cards = st.columns(5)
    siem_cards[0].metric("Top Attack Type", summary["top_attack_type"])
    siem_cards[1].metric("Most Dangerous IP", summary["most_dangerous_ip"])
    siem_cards[2].metric("Top Source IP", summary["top_source_ip"])
    siem_cards[3].metric("Most Targeted Host", summary["most_targeted_host"])
    siem_cards[4].metric("Stored Events", len(history))
    st.caption(
        "Primary analytics store: PostgreSQL"
    )
    if not history.empty:
        chart_columns = st.columns(2)
        with chart_columns[0]:
            st.subheader("Top Source IPs")
            st.plotly_chart(
                host_figure(history[history["predicted_attack"].eq(1)], "source_ip", "Top Threat Sources"),
                width="stretch",
            )
        with chart_columns[1]:
            st.subheader("Most Targeted Hosts")
            st.plotly_chart(
                host_figure(history[history["predicted_attack"].eq(1)], "destination_ip", "Most Targeted Hosts"),
                width="stretch",
            )
    if not history.empty:
        display_columns = [
            "created_at", "source_ip", "destination_ip", "category", "severity",
            "confidence", "threat_score", "source_country", "blocked",
        ]
        if "traffic_scope" in history:
            display_columns.insert(3, "traffic_scope")
        display = history[display_columns].copy()
        display = display.rename(columns={"confidence": "decision_support"})
        display["created_at"] = display["created_at"].map(
            lambda value: datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
        )
        st.dataframe(display, width="stretch", hide_index=True)

with response_tab:
    st.subheader("Automatic Blocking")
    st.warning("Blocking is public-IP-only and requires Administrator/root privileges. Preview the rule before execution.")
    if not postgres_ready:
        st.info("Connect PostgreSQL to unlock automatic response and preserve a complete response audit trail.")
    if not dashboard_can_respond:
        st.info("Your dashboard role is viewer, so response actions are read-only.")
    target_ip = st.text_input("IP address to block", value=event.source_ip)
    execute_block = st.checkbox("Execute OS firewall rule instead of dry run", disabled=not postgres_ready or not dashboard_can_respond)
    if st.button("Preview / Block IP", disabled=not dashboard_can_respond):
        try:
            result = block_ip(target_ip, execute=execute_block)
            st.code(result)
            if execute_block:
                event.blocked = True
                store(postgres_dsn).record_response(target_ip, "block", result)
        except Exception as error:
            st.error(str(error))
    st.subheader("Alert Channels")
    st.write("Configured channels can include email, Telegram, webhook, Twilio SMS, and WhatsApp.")
    responses = pd.DataFrame(store(postgres_dsn).recent_responses(50)) if postgres_ready else pd.DataFrame()
    if not responses.empty:
        st.subheader("Response Audit Log")
        st.dataframe(responses, width="stretch", hide_index=True)

if auto_monitor:
    time.sleep(float(os.getenv("NID_DASHBOARD_REFRESH_DELAY", "0.1")))
    st.rerun()
