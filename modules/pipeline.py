"""End-to-end investigation workflow: steps 2-8 run in order for one incident.

The result is a plain JSON-serialisable dictionary so it can be stored in SQLite,
re-opened from history and rendered by the UI or the report builder.
"""
from __future__ import annotations

import math
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

import pandas as pd

from . import database
from .config import AppSettings, LLMConfig, get_app_settings, get_llm_config
from .error_detector import detect_errors
from .evidence_correlator import correlate, evidence_summary
from .evidence_loader import load_bundle
from .evidence_verifier import verify_all
from .incident_manager import Incident, iso
from .llm_analyzer import BaseProvider, ContextPackage, analyze
from .report_builder import build_report

ProgressFn = Callable[[str, str], None]

LOG_FIELDS = ["evidence_id", "timestamp_iso", "level", "service", "request_id", "message", "error_code", "exception"]


def _clean(value):
    if isinstance(value, pd.Timestamp):
        return iso(value)
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if hasattr(value, "item"):  # numpy scalars
        try:
            return _clean(value.item())
        except (ValueError, AttributeError):
            pass
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def records(df: pd.DataFrame, columns: list[str] | None = None) -> list[dict]:
    if df is None or df.empty:
        return []
    if columns:
        df = df[[c for c in columns if c in df.columns]]
    return [_clean(r) for r in df.to_dict(orient="records")]


def _log_record(r: dict) -> dict:
    out = {"evidence_id": r["evidence_id"], "timestamp": r.get("timestamp_iso", ""), "level": r["level"],
           "service": r["service"], "request_id": r.get("request_id", ""), "message": r["message"]}
    for opt in ("error_code", "exception"):
        if r.get(opt):
            out[opt] = r[opt]
    return out


def new_investigation_id() -> str:
    return "INV-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4].upper()


def run_investigation(incident: Incident, files: dict, llm_cfg: LLMConfig | None = None,
                      settings: AppSettings | None = None, provider: BaseProvider | None = None,
                      progress: ProgressFn | None = None, save: bool = True) -> dict:
    llm_cfg = llm_cfg or get_llm_config()
    settings = settings or get_app_settings()
    notify = progress or (lambda stage, msg: None)
    started = time.perf_counter()
    stages: list[dict] = []
    result: dict = {
        "investigation_id": new_investigation_id(),
        "incident": incident.to_dict(),
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stages": stages,
    }

    def stage(name: str, status: str, detail: str):
        stages.append({"stage": name, "status": status, "detail": detail})
        notify(name, detail)

    # Step 2 - evidence loading
    bundle = load_bundle(files)
    counts = bundle.counts()
    stage("Evidence loading", "ok" if bundle.available_modalities else "failed",
          f"{counts['logs']} log records, {counts['metrics']} metric rows, {counts['traces']} traces "
          f"({counts['spans']} spans), {counts['changes']} change records")
    result["evidence"] = {"counts": counts, "available": bundle.available_modalities,
                          "missing": bundle.missing_modalities, "warnings": bundle.warnings,
                          "sources": bundle.sources}

    # Step 3 - rule-based error detection
    detection = detect_errors(bundle.logs, incident.start_time, incident.end_time, settings.context_minutes)
    stage("Error detection", "ok" if detection.has_errors else "warn",
          f"{detection.counts.get('flagged', 0)} suspicious records flagged "
          f"({detection.counts.get('errors', 0)} ERROR, {detection.counts.get('warnings', 0)} WARN) "
          f"across {len(detection.affected_services)} service(s)")
    flagged_records = records(detection.flagged, LOG_FIELDS + ["severity", "rules", "in_incident_window", "pattern_key"])
    result["detection"] = {
        "counts": detection.counts,
        "patterns": _clean(detection.patterns),
        "affected_services": detection.affected_services,
        "request_ids": detection.request_ids,
        "first_error": iso(detection.first_error_time) if detection.first_error_time is not None else "",
        "last_error": iso(detection.last_error_time) if detection.last_error_time is not None else "",
        "errors": flagged_records,
        "context": records(detection.context_records, LOG_FIELDS),
        "successful_reference": records(detection.successful_reference, LOG_FIELDS),
        "total_log_records": detection.total_log_records,
    }

    # Step 4 - evidence correlation
    corr = correlate(bundle, detection, incident, settings.context_minutes, settings.change_lookback_minutes)
    stage("Evidence correlation", "ok",
          f"{len(corr.metrics)} related metric rows ({sum(1 for m in corr.metrics if m['anomalies'])} anomalous), "
          f"{len(corr.traces)} related traces, {len(corr.changes)} recent change(s)")
    summary = evidence_summary(incident, bundle, detection, corr)
    result["correlation"] = _clean({
        "suspect_services": corr.suspect_services, "metrics": corr.metrics, "traces": corr.traces,
        "changes": corr.changes, "error_links": corr.error_links, "timeline": corr.timeline,
        "notes": corr.notes, "baselines": corr.metric_baselines,
    })
    result["evidence_summary"] = _clean(summary)
    result["metrics_series"] = records(bundle.metrics.drop(columns=["timestamp", "source_file"], errors="ignore"))
    result["evidence_index"] = {eid: {"type": e["type"], "summary": e["summary"],
                                      "timestamp": iso(e["timestamp"]) if e.get("timestamp") is not None else ""}
                                for eid, e in corr.registry.items()}

    # Step 5 - LLM investigation
    pkg = ContextPackage(
        incident={"incident_id": incident.incident_id, "title": incident.title, "description": incident.description,
                  "application": incident.application, "start": iso(incident.start_time), "end": iso(incident.end_time),
                  "reported_affected_service": incident.affected_service or None},
        detection_summary={"counts": detection.counts, "patterns": _clean(detection.patterns)[:10],
                           "affected_services": detection.affected_services,
                           "first_error": result["detection"]["first_error"]},
        log_records=[_log_record(r) for r in records(detection.context_records, LOG_FIELDS)],
        successful_records=[_log_record(r) for r in result["detection"]["successful_reference"]],
        metrics=result["correlation"]["metrics"],
        traces=result["correlation"]["traces"],
        changes=result["correlation"]["changes"],
        missing_modalities=bundle.missing_modalities,
        notes=corr.notes,
    )
    if detection.has_errors or corr.metrics or corr.traces:
        notify("LLM investigation", f"Sending pre-filtered evidence to {llm_cfg.describe()}…")
        llm = analyze(pkg, llm_cfg, provider)
    else:
        llm = None
    if llm is None:
        result["llm"] = {"status": "skipped", "error": "No errors or anomalies were detected, so no LLM analysis was requested."}
        stage("LLM investigation", "skipped", result["llm"]["error"])
    else:
        result["llm"] = _clean(llm.to_dict())
        if llm.status == "success":
            stage("LLM investigation", "ok", f"{len(llm.analysis['hypotheses'])} hypothesis(es) returned by {llm_cfg.model} "
                                              f"in {llm.duration_seconds:.1f} s")
        else:
            stage("LLM investigation", "failed", llm.error)

    # Step 6 - evidence verification (only when the LLM produced hypotheses)
    if llm is not None and llm.status == "success":
        metric_anomalies = {eid: e.get("anomalies", []) for eid, e in corr.registry.items() if e["type"] == "metric"}
        verification = verify_all(llm.analysis, corr.registry, llm.shown_evidence_ids, incident, bundle,
                                  detection.first_error_time, metric_anomalies,
                                  settings.context_minutes, settings.change_lookback_minutes)
        result["verification"] = _clean(verification)
        sc = verification["status_counts"]
        stage("Evidence verification", "ok", f"{sc['SUPPORTED']} supported, {sc['CONTRADICTED']} contradicted, "
                                             f"{sc['INSUFFICIENT EVIDENCE']} insufficient evidence")
    else:
        result["verification"] = None
        stage("Evidence verification", "skipped", "No LLM hypotheses to verify.")

    # Step 7 - report
    result["status"] = ("completed" if result["verification"] is not None
                        else ("completed_without_llm" if detection.has_errors or bundle.available_modalities else "failed"))
    result["completed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result["duration_seconds"] = round(time.perf_counter() - started, 2)
    result["report"] = build_report(result)
    stage("Report generation", "ok", "Structured investigation report generated")

    # Step 8 - storage
    if save:
        database.save_investigation(result, settings.db_path)
        stage("Database storage", "ok", f"Saved as {result['investigation_id']}")
    return result
