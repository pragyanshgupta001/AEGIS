"""Evidence correlation (workflow step 4).

For every detected error, related records are searched in the other evidence:
    * metrics of the same service inside the incident time window
    * traces sharing the same request identifier
    * deployment / configuration changes affecting the suspected service shortly before

Correlation uses only timestamps, service names and request identifiers.
It also builds the *evidence registry*: one entry per evidence identifier, used
later by the verifier to check what the LLM cites.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .error_detector import DetectionResult
from .evidence_loader import EvidenceBundle
from .incident_manager import Incident, iso

# Absolute anomaly thresholds used when no pre-incident baseline exists.
LATENCY_ABS_MS = 1000
ERROR_RATE_ABS_PCT = 5.0
POOL_SATURATION_PCT = 90.0
CPU_ABS_PCT = 90.0
MEMORY_ABS_PCT = 90.0


@dataclass
class CorrelationResult:
    suspect_services: list[str]
    metrics: list[dict] = field(default_factory=list)          # related metric rows with anomaly flags
    metric_baselines: dict = field(default_factory=dict)
    traces: list[dict] = field(default_factory=list)           # related trace summaries
    changes: list[dict] = field(default_factory=list)          # related changes
    error_links: list[dict] = field(default_factory=list)      # per detected error
    registry: dict = field(default_factory=dict)               # evidence_id -> entry
    timeline: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _metric_anomalies(row: pd.Series, baseline: dict) -> list[str]:
    found = []
    lat = row.get("latency_ms")
    if pd.notna(lat):
        base = baseline.get("latency_ms")
        if base is not None and base > 0:
            if lat >= max(3 * base, base + 500):
                found.append(f"latency {lat:.0f} ms vs baseline {base:.0f} ms")
        elif lat >= LATENCY_ABS_MS:
            found.append(f"latency {lat:.0f} ms (≥ {LATENCY_ABS_MS} ms)")
    err = row.get("error_rate_percent")
    if pd.notna(err):
        base = baseline.get("error_rate_percent")
        limit = max(ERROR_RATE_ABS_PCT, 3 * base) if base is not None else ERROR_RATE_ABS_PCT
        if err >= limit:
            found.append(f"error rate {err:.1f}%" + (f" vs baseline {base:.1f}%" if base is not None else ""))
    pool = row.get("db_connection_pool_used_percent")
    if pd.notna(pool) and pool >= POOL_SATURATION_PCT:
        found.append(f"DB connection pool {pool:.0f}% used")
    cpu = row.get("cpu_percent")
    if pd.notna(cpu) and cpu >= CPU_ABS_PCT:
        found.append(f"CPU {cpu:.0f}%")
    mem = row.get("memory_percent")
    if pd.notna(mem) and mem >= MEMORY_ABS_PCT:
        found.append(f"memory {mem:.0f}%")
    return found


def _metric_summary(row: pd.Series, numeric_cols: list[str]) -> dict:
    out = {}
    for col in numeric_cols:
        val = row.get(col)
        if pd.notna(val):
            out[col] = float(val) if not float(val).is_integer() else int(val)
    return out


def build_registry(bundle: EvidenceBundle, detection: DetectionResult, metric_rows: dict) -> dict:
    """One entry per evidence identifier in the uploaded files."""
    registry: dict[str, dict] = {}
    flagged_ids = set(detection.flagged["evidence_id"]) if detection.has_errors else set()
    for _, r in bundle.logs.iterrows():
        abnormal = r["evidence_id"] in flagged_ids
        registry[r["evidence_id"]] = {
            "type": "log", "services": [r["service"]], "timestamp": r["timestamp"],
            "abnormal": abnormal, "request_id": r["request_id"],
            "summary": f"[{r['level']}] {r['service']}: {r['message']}",
        }
    for _, r in bundle.metrics.iterrows():
        info = metric_rows.get(r["evidence_id"], {})
        anomalies = info.get("anomalies", [])
        registry[r["evidence_id"]] = {
            "type": "metric", "services": [r["service"]], "timestamp": r["timestamp"],
            "abnormal": bool(anomalies), "anomalies": anomalies,
            "summary": f"{r['service']} metrics at {r['timestamp_iso']}" + (f" ({'; '.join(anomalies)})" if anomalies else " (within normal range)"),
        }
    for t in bundle.traces:
        registry[t["evidence_id"]] = {
            "type": "trace", "services": t["services"], "timestamp": t["timestamp"],
            "abnormal": t["has_error"], "request_id": t["request_id"],
            "summary": f"trace {t['trace_id']} ({t['request_id']}): " + " → ".join(
                f"{s['service']}[{s['status']},{s['duration_ms']:.0f}ms]" if s["duration_ms"] is not None else f"{s['service']}[{s['status']}]"
                for s in t["spans"]),
        }
        for s in t["spans"]:
            registry[s["evidence_id"]] = {
                "type": "span", "services": [s["service"]], "timestamp": t["timestamp"],
                "abnormal": s["status"] == "ERROR" or bool(s["error"]), "request_id": t["request_id"],
                "summary": f"span {s['evidence_id']} {s['service']}.{s['operation']} {s['status']}"
                           + (f" - {s['error']}" if s["error"] else ""),
            }
    for _, r in bundle.changes.iterrows():
        registry[r["evidence_id"]] = {
            "type": "change", "services": [r["service"]], "timestamp": r["timestamp"],
            "abnormal": True,  # a change is a notable event, not an error
            "summary": f"{r.get('change_type', '')} on {r['service']}: {r['description']}",
        }
    return registry


def correlate(bundle: EvidenceBundle, detection: DetectionResult, incident: Incident,
              context_minutes: int = 10, change_lookback_minutes: int = 60) -> CorrelationResult:
    start, end = incident.start_time, incident.end_time
    ctx_start = start - pd.Timedelta(minutes=context_minutes)
    ctx_end = end + pd.Timedelta(minutes=context_minutes)
    notes: list[str] = []

    # --- suspect services: services with errors, then warnings, then user hint, then error spans
    suspects: list[str] = [a["service"] for a in detection.affected_services if a["errors"] > 0]
    suspects += [a["service"] for a in detection.affected_services if a["errors"] == 0]
    if incident.affected_service:
        hint = incident.affected_service.strip().lower()
        if hint not in suspects:
            suspects.insert(0, hint)
    if not bundle.spans.empty:
        err_spans = bundle.spans[(bundle.spans["status"] == "ERROR") | (bundle.spans["error"] != "")]
        for svc in err_spans["service"].unique():
            if svc not in suspects:
                suspects.append(svc)
    suspects = list(dict.fromkeys(suspects))

    # --- metrics: baseline before incident, anomaly flags inside the context window
    metric_rows: dict[str, dict] = {}
    related_metrics: list[dict] = []
    baselines: dict[str, dict] = {}
    if not bundle.metrics.empty:
        numeric_cols = [c for c in bundle.metrics.columns
                        if c not in ("evidence_id", "timestamp", "timestamp_iso", "service", "source_file")
                        and pd.api.types.is_numeric_dtype(bundle.metrics[c])]
        for service, group in bundle.metrics.groupby("service"):
            before = group[group["timestamp"] < start]
            baselines[service] = {c: float(before[c].median()) for c in numeric_cols if before[c].notna().any()}
        for _, row in bundle.metrics.iterrows():
            anomalies = _metric_anomalies(row, baselines.get(row["service"], {}))
            metric_rows[row["evidence_id"]] = {"anomalies": anomalies}
            if row["service"] in suspects and ctx_start - pd.Timedelta(minutes=context_minutes) <= row["timestamp"] <= ctx_end:
                related_metrics.append({
                    "evidence_id": row["evidence_id"], "timestamp": row["timestamp_iso"], "service": row["service"],
                    "values": _metric_summary(row, numeric_cols), "anomalies": anomalies,
                    "in_incident_window": bool(start <= row["timestamp"] <= end),
                    "phase": "before" if row["timestamp"] < start else ("during" if row["timestamp"] <= end else "after"),
                })
        for svc in suspects:
            if svc not in baselines or not baselines[svc]:
                if not bundle.metrics[bundle.metrics["service"] == svc].empty:
                    notes.append(f"No pre-incident metric baseline for {svc}; absolute thresholds were used.")
        missing_metric_services = [s for s in suspects if bundle.metrics[bundle.metrics["service"] == s].empty]
        if missing_metric_services:
            notes.append("No metrics were provided for: " + ", ".join(missing_metric_services) + ".")

    # --- traces: matched by request id, plus error traces inside the context window
    related_traces = []
    req_set = set(detection.request_ids)
    for t in bundle.traces:
        by_request = t["request_id"] in req_set
        in_ctx = t["timestamp"] is not None and ctx_start <= t["timestamp"] <= ctx_end
        if by_request or (in_ctx and t["has_error"]) or (in_ctx and set(t["services"]) & set(suspects)):
            error_spans = [s for s in t["spans"] if s["status"] == "ERROR" or s["error"]]
            durations = [s for s in t["spans"] if s["duration_ms"] is not None]
            slowest = max(durations, key=lambda s: s["duration_ms"]) if durations else None
            # deepest failing span = last error span in call order (closest to the origin of the failure)
            deepest = error_spans[-1] if error_spans else None
            related_traces.append({
                "evidence_id": t["evidence_id"], "request_id": t["request_id"], "timestamp": t["timestamp_iso"],
                "matched_by": "request_id" if by_request else "time window",
                "has_error": t["has_error"],
                "path": " → ".join(s["service"] for s in t["spans"]),
                "spans": [{"evidence_id": s["evidence_id"], "service": s["service"], "operation": s["operation"],
                           "status": s["status"], "duration_ms": s["duration_ms"], "error": s["error"]} for s in t["spans"]],
                "error_span_ids": [s["evidence_id"] for s in error_spans],
                "slowest_span": slowest["evidence_id"] if slowest else "",
                "deepest_error_span": deepest["evidence_id"] if deepest else "",
                "deepest_error_service": deepest["service"] if deepest else "",
            })
    if detection.request_ids and bundle.traces:
        traced = {t["request_id"] for t in bundle.traces}
        untraced = [r for r in detection.request_ids if r not in traced]
        if untraced:
            notes.append("No trace was provided for failed request(s): " + ", ".join(untraced) + ".")

    # --- changes: within the look-back window before the incident, up to its end
    related_changes = []
    first_error = detection.first_error_time
    lb_start = start - pd.Timedelta(minutes=change_lookback_minutes)
    for _, row in bundle.changes.iterrows():
        if not (lb_start <= row["timestamp"] <= end):
            continue
        minutes_before = None
        if first_error is not None:
            minutes_before = round((first_error - row["timestamp"]).total_seconds() / 60.0, 1)
        related_changes.append({
            "evidence_id": row["evidence_id"], "timestamp": row["timestamp_iso"], "service": row["service"],
            "change_type": row.get("change_type", ""), "description": row["description"],
            "version": row.get("version", ""),
            "affects_suspect_service": row["service"] in suspects,
            "minutes_before_first_error": minutes_before,
        })
    if bundle.changes.empty:
        notes.append("No deployment/configuration change records were provided.")
    elif not related_changes:
        notes.append(f"No changes were recorded in the {change_lookback_minutes} minutes before the incident.")

    # --- per-error links
    links = []
    if detection.has_errors:
        for _, err in detection.flagged.iterrows():
            svc = err["service"]
            m_ids = [m["evidence_id"] for m in related_metrics if m["service"] == svc]
            t_ids = [t["evidence_id"] for t in related_traces if err["request_id"] and t["request_id"] == err["request_id"]]
            c_ids = [c["evidence_id"] for c in related_changes if c["service"] == svc]
            links.append({"error_id": err["evidence_id"], "service": svc, "request_id": err["request_id"],
                          "metric_ids": m_ids, "trace_ids": t_ids, "change_ids": c_ids})

    # --- timeline (observed events only)
    timeline = []
    for c in related_changes:
        timeline.append({"timestamp": c["timestamp"], "type": "change", "service": c["service"],
                         "event": f"{c['change_type']}: {c['description']}", "evidence_id": c["evidence_id"]})
    if detection.has_errors:
        for _, e in detection.flagged.iterrows():
            timeline.append({"timestamp": e["timestamp_iso"], "type": e["severity"].lower(), "service": e["service"],
                             "event": e["message"], "evidence_id": e["evidence_id"]})
    for m in related_metrics:
        if m["anomalies"]:
            timeline.append({"timestamp": m["timestamp"], "type": "metric anomaly", "service": m["service"],
                             "event": "; ".join(m["anomalies"]), "evidence_id": m["evidence_id"]})
    timeline.sort(key=lambda x: x["timestamp"])

    registry = build_registry(bundle, detection, metric_rows)
    return CorrelationResult(
        suspect_services=suspects, metrics=related_metrics, metric_baselines=baselines,
        traces=related_traces, changes=related_changes, error_links=links,
        registry=registry, timeline=timeline, notes=notes,
    )


def evidence_summary(incident: Incident, bundle: EvidenceBundle, detection: DetectionResult,
                     corr: CorrelationResult) -> dict:
    """A compact, structured summary shown in the UI and used to build the LLM prompt."""
    return {
        "incident_window": {"start": iso(incident.start_time), "end": iso(incident.end_time)},
        "evidence_available": bundle.available_modalities,
        "evidence_missing": bundle.missing_modalities,
        "record_counts": bundle.counts(),
        "first_error": iso(detection.first_error_time) if detection.first_error_time is not None else "",
        "suspect_services": corr.suspect_services,
        "anomalous_metric_ids": [m["evidence_id"] for m in corr.metrics if m["anomalies"]],
        "error_trace_ids": [t["evidence_id"] for t in corr.traces if t["has_error"]],
        "recent_change_ids": [c["evidence_id"] for c in corr.changes],
        "notes": corr.notes,
    }
