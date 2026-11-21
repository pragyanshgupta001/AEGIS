"""Evidence loading and normalisation (workflow step 2).

Supported inputs:
    logs     - JSON application logs (list of records)
    metrics  - CSV system metrics
    traces   - JSON distributed traces (list of traces with spans)
    changes  - CSV deployment / configuration changes

Every record receives a stable evidence identifier so that hypotheses can cite it
and the verifier can check it. Invalid files or records are reported as warnings,
never silently dropped and never "repaired" with invented values.
"""
from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TEXT_LEN = 1000  # long free-text fields are truncated for safety and prompt size

MODALITIES = ("logs", "metrics", "traces", "changes")
MODALITY_LABELS = {
    "logs": "Application logs (JSON)",
    "metrics": "System metrics (CSV)",
    "traces": "Distributed traces (JSON)",
    "changes": "Deployment / configuration changes (CSV)",
}
DEMO_FILES = {
    "logs": "application_logs.json",
    "metrics": "system_metrics.csv",
    "traces": "distributed_traces.json",
    "changes": "deployment_changes.csv",
}

LOG_REQUIRED = ("timestamp", "level", "service", "message")
METRIC_REQUIRED = ("timestamp", "service")
TRACE_REQUIRED = ("trace_id", "spans")
CHANGE_REQUIRED = ("timestamp", "service", "description")

LOG_COLUMNS = [
    "evidence_id", "timestamp", "timestamp_iso", "level", "service", "request_id",
    "message", "error_code", "exception", "status_code", "source_file",
]
SPAN_COLUMNS = [
    "evidence_id", "trace_id", "request_id", "span_id", "service", "operation",
    "duration_ms", "status", "error", "timestamp", "timestamp_iso",
]


@dataclass
class EvidenceBundle:
    logs: pd.DataFrame
    metrics: pd.DataFrame
    traces: list[dict]
    spans: pd.DataFrame
    changes: pd.DataFrame
    warnings: list[str] = field(default_factory=list)
    sources: dict[str, list[str]] = field(default_factory=dict)

    @property
    def available_modalities(self) -> list[str]:
        out = []
        if not self.logs.empty:
            out.append("logs")
        if not self.metrics.empty:
            out.append("metrics")
        if self.traces:
            out.append("traces")
        if not self.changes.empty:
            out.append("changes")
        return out

    @property
    def missing_modalities(self) -> list[str]:
        return [m for m in MODALITIES if m not in self.available_modalities]

    def counts(self) -> dict[str, int]:
        return {
            "logs": len(self.logs),
            "metrics": len(self.metrics),
            "traces": len(self.traces),
            "spans": len(self.spans),
            "changes": len(self.changes),
        }


# ----------------------------------------------------------------- helpers
def _clean_text(value) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:MAX_TEXT_LEN] + ("…" if len(text) > MAX_TEXT_LEN else "")


def _parse_ts(value) -> pd.Timestamp | None:
    if value is None or (isinstance(value, float) and pd.isna(value)) or str(value).strip() == "":
        return None
    ts = pd.to_datetime(value, utc=True, errors="coerce")
    return None if pd.isna(ts) else ts


def _iso(ts: pd.Timestamp | None) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts is not None and not pd.isna(ts) else ""


def _read_json(name: str, data: bytes, warnings: list[str]):
    if len(data) > MAX_FILE_BYTES:
        warnings.append(f"{name}: file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB and was skipped.")
        return None
    if not data.strip():
        warnings.append(f"{name}: file is empty.")
        return None
    try:
        return json.loads(data.decode("utf-8-sig"))
    except UnicodeDecodeError:
        warnings.append(f"{name}: file is not valid UTF-8 text.")
    except json.JSONDecodeError as exc:
        # Fall back to JSON Lines (one JSON object per line).
        try:
            return [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]
        except json.JSONDecodeError:
            warnings.append(f"{name}: invalid JSON ({exc.msg} at line {exc.lineno}).")
    return None


def _read_csv(name: str, data: bytes, warnings: list[str]) -> pd.DataFrame | None:
    if len(data) > MAX_FILE_BYTES:
        warnings.append(f"{name}: file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB and was skipped.")
        return None
    if not data.strip():
        warnings.append(f"{name}: file is empty.")
        return None
    try:
        df = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)
    except Exception as exc:  # pandas raises several parser error types
        warnings.append(f"{name}: could not be read as CSV ({exc}).")
        return None
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df


def _as_record_list(payload, name: str, keys: tuple[str, ...], warnings: list[str]) -> list:
    """Accept a JSON list, or an object wrapping a list under a common key."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in keys:
            if isinstance(payload.get(key), list):
                return payload[key]
    warnings.append(f"{name}: expected a JSON list of records.")
    return []


# ----------------------------------------------------------------- loaders
def load_logs(files: list[tuple[str, bytes]], warnings: list[str]) -> pd.DataFrame:
    rows = []
    for name, data in files:
        payload = _read_json(name, data, warnings)
        if payload is None:
            continue
        records = _as_record_list(payload, name, ("logs", "records", "events"), warnings)
        skipped = 0
        for rec in records:
            if not isinstance(rec, dict) or any(rec.get(k) in (None, "") for k in LOG_REQUIRED):
                skipped += 1
                continue
            ts = _parse_ts(rec.get("timestamp"))
            if ts is None:
                skipped += 1
                continue
            status = rec.get("status_code", rec.get("http_status", rec.get("status")))
            status = pd.to_numeric(status, errors="coerce")
            rows.append({
                "timestamp": ts,
                "timestamp_iso": _iso(ts),
                "level": _clean_text(rec.get("level")).upper(),
                "service": _clean_text(rec.get("service")).lower(),
                "request_id": _clean_text(rec.get("request_id") or rec.get("trace_request_id")),
                "message": _clean_text(rec.get("message")),
                "error_code": _clean_text(rec.get("error_code")),
                "exception": _clean_text(rec.get("exception")),
                "status_code": None if pd.isna(status) else int(status),
                "source_file": name,
            })
        if skipped:
            warnings.append(
                f"{name}: {skipped} log record(s) skipped (missing one of {', '.join(LOG_REQUIRED)} or invalid timestamp)."
            )
    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=LOG_COLUMNS)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    df.insert(0, "evidence_id", [f"LOG-{i + 1:04d}" for i in range(len(df))])
    return df[LOG_COLUMNS]


def load_metrics(files: list[tuple[str, bytes]], warnings: list[str]) -> pd.DataFrame:
    frames = []
    for name, data in files:
        df = _read_csv(name, data, warnings)
        if df is None:
            continue
        missing = [c for c in METRIC_REQUIRED if c not in df.columns]
        if missing:
            warnings.append(f"{name}: missing required column(s): {', '.join(missing)}.")
            continue
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        bad = int(df["timestamp"].isna().sum() + (df["service"].str.strip() == "").sum())
        df = df[df["timestamp"].notna() & (df["service"].str.strip() != "")].copy()
        if bad:
            warnings.append(f"{name}: {bad} metric row(s) skipped (invalid timestamp or missing service).")
        df["service"] = df["service"].str.strip().str.lower()
        for col in df.columns:
            if col not in ("timestamp", "service"):
                converted = pd.to_numeric(df[col], errors="coerce")
                if converted.notna().any():
                    df[col] = converted
        df["source_file"] = name
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=["evidence_id", "timestamp", "timestamp_iso", "service"])
    df = pd.concat(frames, ignore_index=True).sort_values(["timestamp", "service"], kind="stable")
    df = df.reset_index(drop=True)
    df.insert(0, "evidence_id", [f"MET-{i + 1:04d}" for i in range(len(df))])
    df.insert(2, "timestamp_iso", df["timestamp"].map(_iso))
    return df


def load_traces(files: list[tuple[str, bytes]], warnings: list[str]) -> tuple[list[dict], pd.DataFrame]:
    traces: list[dict] = []
    seen: set[str] = set()
    for name, data in files:
        payload = _read_json(name, data, warnings)
        if payload is None:
            continue
        records = _as_record_list(payload, name, ("traces", "records"), warnings)
        skipped = 0
        for rec in records:
            if not isinstance(rec, dict) or any(k not in rec for k in TRACE_REQUIRED) or not isinstance(rec["spans"], list):
                skipped += 1
                continue
            trace_id = _clean_text(rec["trace_id"])
            if not trace_id:
                skipped += 1
                continue
            base, n = trace_id, 2
            while trace_id in seen:  # keep identifiers unique across files
                trace_id = f"{base}-{n}"
                n += 1
            seen.add(trace_id)
            ts = _parse_ts(rec.get("timestamp"))
            spans = []
            for idx, span in enumerate(rec["spans"]):
                if not isinstance(span, dict) or not span.get("service"):
                    continue
                span_id = _clean_text(span.get("span_id")) or f"span{idx + 1}"
                duration = pd.to_numeric(span.get("duration_ms"), errors="coerce")
                spans.append({
                    "evidence_id": f"{trace_id}/{span_id}",
                    "span_id": span_id,
                    "parent_span_id": _clean_text(span.get("parent_span_id")),
                    "service": _clean_text(span.get("service")).lower(),
                    "operation": _clean_text(span.get("operation")),
                    "duration_ms": None if pd.isna(duration) else float(duration),
                    "status": _clean_text(span.get("status")).upper() or "UNKNOWN",
                    "error": _clean_text(span.get("error")),
                })
            if not spans:
                skipped += 1
                continue
            traces.append({
                "evidence_id": trace_id,
                "trace_id": trace_id,
                "request_id": _clean_text(rec.get("request_id")),
                "timestamp": ts,
                "timestamp_iso": _iso(ts),
                "spans": spans,
                "has_error": any(s["status"] == "ERROR" or s["error"] for s in spans),
                "services": sorted({s["service"] for s in spans}),
                "source_file": name,
            })
        if skipped:
            warnings.append(f"{name}: {skipped} trace(s) skipped (missing trace_id or spans).")
        missing_ts = sum(1 for t in traces if t["timestamp"] is None and t["source_file"] == name)
        if missing_ts:
            warnings.append(f"{name}: {missing_ts} trace(s) have no valid timestamp; time checks cannot use them.")
    traces.sort(key=lambda t: (t["timestamp"] is None, t["timestamp"] or pd.Timestamp.min.tz_localize("UTC")))
    span_rows = []
    for t in traces:
        for s in t["spans"]:
            span_rows.append({**s, "trace_id": t["trace_id"], "request_id": t["request_id"],
                              "timestamp": t["timestamp"], "timestamp_iso": t["timestamp_iso"]})
    spans_df = pd.DataFrame(span_rows, columns=SPAN_COLUMNS + ["parent_span_id"]) if span_rows else pd.DataFrame(columns=SPAN_COLUMNS)
    return traces, spans_df


def load_changes(files: list[tuple[str, bytes]], warnings: list[str]) -> pd.DataFrame:
    frames = []
    for name, data in files:
        df = _read_csv(name, data, warnings)
        if df is None:
            continue
        missing = [c for c in CHANGE_REQUIRED if c not in df.columns]
        if missing:
            warnings.append(f"{name}: missing required column(s): {', '.join(missing)}.")
            continue
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        bad = int(df["timestamp"].isna().sum())
        df = df[df["timestamp"].notna()].copy()
        if bad:
            warnings.append(f"{name}: {bad} change record(s) skipped (invalid timestamp).")
        df["service"] = df["service"].str.strip().str.lower()
        for col in ("change_id", "change_type", "version"):
            if col not in df.columns:
                df[col] = ""
        df["description"] = df["description"].map(_clean_text)
        df["source_file"] = name
        frames.append(df)
    if not frames:
        return pd.DataFrame(columns=["evidence_id", "timestamp", "timestamp_iso", "service", "change_type", "description"])
    df = pd.concat(frames, ignore_index=True).sort_values("timestamp", kind="stable").reset_index(drop=True)
    ids, seen = [], set()
    for i, cid in enumerate(df["change_id"].astype(str).str.strip()):
        eid = cid if cid and cid not in seen else f"CHG-{i + 1:04d}"
        seen.add(eid)
        ids.append(eid)
    df.insert(0, "evidence_id", ids)
    df.insert(2, "timestamp_iso", df["timestamp"].map(_iso))
    return df


# ----------------------------------------------------------------- bundle
def load_bundle(files: dict[str, list[tuple[str, bytes]]]) -> EvidenceBundle:
    """Load every uploaded file. ``files`` maps modality -> list of (filename, bytes)."""
    warnings: list[str] = []
    logs = load_logs(files.get("logs", []), warnings)
    metrics = load_metrics(files.get("metrics", []), warnings)
    traces, spans = load_traces(files.get("traces", []), warnings)
    changes = load_changes(files.get("changes", []), warnings)
    bundle = EvidenceBundle(
        logs=logs, metrics=metrics, traces=traces, spans=spans, changes=changes,
        warnings=warnings, sources={m: [n for n, _ in files.get(m, [])] for m in MODALITIES},
    )
    for modality in bundle.missing_modalities:
        if files.get(modality):
            warnings.append(f"No usable {MODALITY_LABELS[modality].lower()} could be read from the uploaded file(s).")
        else:
            warnings.append(f"No {MODALITY_LABELS[modality].lower()} were provided; related checks will be limited.")
    return bundle


def demo_files() -> dict[str, list[tuple[str, bytes]]]:
    from .config import DEMO_DATA_DIR

    out = {}
    for modality, filename in DEMO_FILES.items():
        path = Path(DEMO_DATA_DIR) / filename
        if path.exists():
            out[modality] = [(filename, path.read_bytes())]
    return out
