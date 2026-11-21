"""Plotly charts built only from uploaded evidence (no invented values)."""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

NAVY = "#0B1F3A"
BLUE = "#1E40AF"
COLORS = {"error": "#C62828", "warn": "#E09100", "change": "#6A1B9A", "metric anomaly": "#1E40AF",
          "ERROR": "#C62828", "WARN": "#E09100", "OTHER": "#607D8B"}
LAYOUT = dict(template="plotly_white", font=dict(family="Inter, Segoe UI, sans-serif", color=NAVY, size=13),
              margin=dict(l=10, r=10, t=50, b=10), height=340,
              legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))


def _window(fig: go.Figure, result: dict) -> go.Figure:
    inc = result["incident"]
    x0, x1 = pd.Timestamp(inc["start_time"]), pd.Timestamp(inc["end_time"])
    fig.add_vrect(x0=x0, x1=x1, fillcolor="#C62828", opacity=0.07, line_width=0)
    fig.add_annotation(x=x0, y=1, xref="x", yref="paper", text="incident window", showarrow=False,
                       xanchor="left", yanchor="bottom", font=dict(size=11, color="#C62828"))
    return fig


def error_distribution(result: dict):
    errors = result.get("detection", {}).get("errors", [])
    if not errors:
        return None
    df = pd.DataFrame(errors).groupby(["service", "severity"]).size().reset_index(name="records")
    fig = px.bar(df, x="service", y="records", color="severity", color_discrete_map=COLORS,
                 title="Detected errors by service", barmode="stack")
    fig.update_layout(**LAYOUT, xaxis_title=None, yaxis_title="flagged log records")
    return fig


def error_frequency(result: dict):
    errors = result.get("detection", {}).get("errors", [])
    if not errors:
        return None
    df = pd.DataFrame(errors)
    df["time"] = pd.to_datetime(df["timestamp_iso"], utc=True).dt.floor("min")
    df = df.groupby(["time", "severity"]).size().reset_index(name="records")
    fig = px.bar(df, x="time", y="records", color="severity", color_discrete_map=COLORS,
                 title="Error frequency over time (per minute)")
    fig.update_layout(**LAYOUT, xaxis_title="time (UTC)", yaxis_title="flagged records")
    return _window(fig, result)


def _metric_line(result: dict, column: str, title: str, y_title: str, nonzero_only: bool = False):
    rows = result.get("metrics_series", [])
    if not rows:
        return None
    df = pd.DataFrame(rows)
    if column not in df.columns:
        return None
    df = df[pd.to_numeric(df[column], errors="coerce").notna()].copy()
    if nonzero_only:
        keep = df.groupby("service")[column].transform(lambda s: (s > 0).any())
        df = df[keep]
    if df.empty:
        return None
    df["time"] = pd.to_datetime(df["timestamp_iso"], utc=True)
    df = df.sort_values("time")
    fig = px.line(df, x="time", y=column, color="service", markers=True, title=title)
    fig.update_layout(**LAYOUT, xaxis_title="time (UTC)", yaxis_title=y_title)
    return _window(fig, result)


def service_latency(result: dict):
    return _metric_line(result, "latency_ms", "Service latency during the incident", "latency (ms)")


def pool_usage(result: dict):
    fig = _metric_line(result, "db_connection_pool_used_percent", "Database connection pool usage",
                       "pool used (%)", nonzero_only=True)
    if fig is not None:
        fig.add_hline(y=100, line_dash="dot", line_color="#C62828", annotation_text="100% (exhausted)")
    return fig


def incident_timeline(result: dict):
    events = result.get("correlation", {}).get("timeline", [])
    if not events:
        return None
    df = pd.DataFrame(events)
    df["time"] = pd.to_datetime(df["timestamp"], utc=True)
    df["label"] = df["evidence_id"] + ": " + df["event"].str.slice(0, 80)
    fig = px.scatter(df, x="time", y="service", color="type", color_discrete_map=COLORS, hover_name="label",
                     title="Incident timeline (observed events)", symbol="type")
    fig.update_traces(marker=dict(size=13, line=dict(width=1, color="white")))
    fig.update_layout(**LAYOUT, xaxis_title="time (UTC)", yaxis_title=None)
    return _window(fig, result)


def dashboard_services(stats: dict):
    rows = stats.get("investigations_by_service", [])
    if not rows:
        return None
    df = pd.DataFrame(rows).rename(columns={"n": "investigations"})
    fig = px.bar(df.head(10), x="investigations", y="service", orientation="h",
                 title="Most frequently affected services", color_discrete_sequence=[BLUE])
    fig.update_layout(**LAYOUT, yaxis=dict(autorange="reversed", title=None), xaxis_title="investigations with errors")
    return fig
