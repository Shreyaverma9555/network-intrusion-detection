from __future__ import annotations

import math

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def network_figure(history: pd.DataFrame) -> go.Figure:
    graph = nx.Graph()
    if not history.empty:
        for _, row in history.iterrows():
            source = row.get("source_ip") or "Unknown source"
            destination = row.get("destination_ip") or "Unknown destination"
            graph.add_edge(source, destination, attack=bool(row.get("predicted_attack")))
    if not graph.nodes:
        graph.add_node("No network data")
    positions = nx.spring_layout(graph, seed=42)
    traces: list[go.Scatter] = []
    for is_attack, color, name in [(False, "#2ca02c", "Normal"), (True, "#d62728", "Attack")]:
        edge_x: list[float | None] = []
        edge_y: list[float | None] = []
        for source, destination, data in graph.edges(data=True):
            if bool(data.get("attack")) != is_attack:
                continue
            x0, y0 = positions[source]
            x1, y1 = positions[destination]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        traces.append(go.Scatter(x=edge_x, y=edge_y, mode="lines", line={"color": color, "width": 2}, name=name))
    traces.append(
        go.Scatter(
            x=[positions[node][0] for node in graph.nodes],
            y=[positions[node][1] for node in graph.nodes],
            mode="markers+text",
            text=list(graph.nodes),
            textposition="top center",
            marker={"size": 18, "color": "#1f77b4"},
            name="Hosts",
        )
    )
    return go.Figure(traces, layout=go.Layout(margin={"l": 10, "r": 10, "t": 10, "b": 10}))


def attack_map_figure(history: pd.DataFrame) -> go.Figure:
    locations: list[dict[str, object]] = []
    if not history.empty:
        for _, row in history[history["predicted_attack"].eq(1)].iterrows():
            try:
                stats = row.get("statistics_parsed", {})
                locations.append(
                    {
                        "lat": float(stats["source_latitude"]),
                        "lon": float(stats["source_longitude"]),
                        "country": row.get("source_country", "Unknown"),
                        "category": row.get("category", "Attack"),
                        "source_ip": row.get("source_ip", "Unknown"),
                        "severity": row.get("severity", "Unknown"),
                        "threat_score": float(row.get("threat_score", 0) or 0),
                    }
                )
            except (KeyError, TypeError, ValueError):
                continue
    frame = pd.DataFrame(locations)
    if frame.empty:
        figure = go.Figure(layout=go.Layout(geo={"projection_type": "natural earth"}, margin={"l": 0, "r": 0, "t": 0, "b": 0}))
        figure.add_annotation(text="No Geo-IP coordinates available yet", x=0.5, y=0.5, showarrow=False)
        return figure
    counts = (
        frame.groupby(["lat", "lon", "country", "category", "severity"], as_index=False)
        .agg(attacks=("source_ip", "size"), unique_sources=("source_ip", "nunique"), max_threat_score=("threat_score", "max"))
    )
    counts["marker_size"] = counts["attacks"].map(lambda value: 8 + math.sqrt(value) * 8)
    return px.scatter_geo(
        counts,
        lat="lat",
        lon="lon",
        color="category",
        size="marker_size",
        hover_name="country",
        hover_data={
            "category": True,
            "severity": True,
            "attacks": True,
            "unique_sources": True,
            "max_threat_score": ":.0f",
            "marker_size": False,
            "lat": False,
            "lon": False,
        },
        projection="natural earth",
    ).update_layout(margin={"l": 0, "r": 0, "t": 0, "b": 0})


def geo_attack_table(history: pd.DataFrame) -> pd.DataFrame:
    if history.empty or "source_country" not in history:
        return pd.DataFrame(columns=["Country", "Attacks", "Unique Sources", "Top Attack", "Max Threat Score", "Mapped"])
    attacks = history[history["predicted_attack"].eq(1)].copy()
    if attacks.empty:
        return pd.DataFrame(columns=["Country", "Attacks", "Unique Sources", "Top Attack", "Max Threat Score", "Mapped"])

    def mapped(row: pd.Series) -> bool:
        stats = row.get("statistics_parsed", {})
        return isinstance(stats, dict) and "source_latitude" in stats and "source_longitude" in stats

    attacks["mapped"] = attacks.apply(mapped, axis=1)
    rows: list[dict[str, object]] = []
    for country, group in attacks.groupby(attacks["source_country"].fillna("Unknown")):
        top_attack = group["category"].value_counts().index[0] if not group.empty else "Unknown"
        rows.append(
            {
                "Country": country or "Unknown",
                "Attacks": int(len(group)),
                "Unique Sources": int(group["source_ip"].nunique()),
                "Top Attack": top_attack,
                "Max Threat Score": float(group["threat_score"].max() or 0),
                "Mapped": int(group["mapped"].sum()),
            }
        )
    return pd.DataFrame(rows).sort_values(["Attacks", "Max Threat Score"], ascending=[False, False])
