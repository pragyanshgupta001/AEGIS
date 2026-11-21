"""Rule-based error detection over the combined application log (workflow step 3).

The LLM is never asked to scan the whole log. Python rules first flag relevant
records; only those records plus their surrounding context are passed on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pandas as pd

ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "SEVERE"}
WARN_LEVELS = {"WARN", "WARNING"}

HTTP_5XX_RE = re.compile(r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s*|status(?:[ _]?code)?\s*[=:]?\s*)5\d{2}\b", re.IGNORECASE)
EXCEPTION_RE = re.compile(r"\b[A-Z][A-Za-z]*(?:Exception|Error|Timeout)\b")
NUMBER_RE = re.compile(r"\d+")

RULE_LABELS = {
    "error_level": "ERROR-level record",
    "warn_level": "WARN-level record",
    "exception": "Exception present",
    "http_5xx": "HTTP 5xx failure",
    "repeated": "Repeated error pattern",
}


@dataclass
class DetectionResult:
    flagged: pd.DataFrame                      # every flagged record with rule columns
    patterns: list[dict] = field(default_factory=list)
    affected_services: list[dict] = field(default_factory=list)
    request_ids: list[str] = field(default_factory=list)
    context_records: pd.DataFrame = field(default_factory=pd.DataFrame)
    successful_reference: pd.DataFrame = field(default_factory=pd.DataFrame)
    first_error_time: pd.Timestamp | None = None
    last_error_time: pd.Timestamp | None = None
    total_log_records: int = 0
    counts: dict = field(default_factory=dict)

    @property
    def has_errors(self) -> bool:
        return not self.flagged.empty


def _pattern_key(row) -> str:
    if row.get("error_code"):
        return str(row["error_code"])
    return NUMBER_RE.sub("#", str(row.get("message", ""))).strip().lower()[:120]


def detect_errors(logs: pd.DataFrame, start: pd.Timestamp, end: pd.Timestamp, context_minutes: int = 10) -> DetectionResult:
    if logs is None or logs.empty:
        return DetectionResult(flagged=pd.DataFrame(), total_log_records=0)

    df = logs.copy()
    df["rule_error_level"] = df["level"].isin(ERROR_LEVELS)
    df["rule_warn_level"] = df["level"].isin(WARN_LEVELS)
    df["rule_exception"] = (df["exception"].fillna("") != "") | df["message"].fillna("").str.contains(EXCEPTION_RE)
    msg_5xx = df["message"].fillna("").str.contains(HTTP_5XX_RE)
    code_5xx = pd.to_numeric(df["status_code"], errors="coerce").between(500, 599)
    df["rule_http_5xx"] = msg_5xx | code_5xx.fillna(False)
    df["flagged"] = df[["rule_error_level", "rule_warn_level", "rule_exception", "rule_http_5xx"]].any(axis=1)

    window_start = start - pd.Timedelta(minutes=context_minutes)
    window_end = end + pd.Timedelta(minutes=context_minutes)
    df["in_incident_window"] = df["timestamp"].between(start, end)
    df["in_context_window"] = df["timestamp"].between(window_start, window_end)

    flagged = df[df["flagged"]].copy()
    flagged["pattern_key"] = flagged.apply(_pattern_key, axis=1)
    pattern_counts = flagged["pattern_key"].value_counts()
    flagged["rule_repeated"] = flagged["pattern_key"].map(pattern_counts).fillna(0) >= 2

    def rules_for(row) -> list[str]:
        return [label for key, label in RULE_LABELS.items() if row.get(f"rule_{key}")]

    flagged["rules"] = flagged.apply(rules_for, axis=1)
    flagged["severity"] = flagged["level"].map(lambda lv: "ERROR" if lv in ERROR_LEVELS else ("WARN" if lv in WARN_LEVELS else "OTHER"))

    # Repeated patterns (grouped error signatures)
    patterns = []
    for key, group in flagged.groupby("pattern_key", sort=False):
        patterns.append({
            "pattern": key,
            "example_message": group.iloc[0]["message"],
            "occurrences": int(len(group)),
            "services": sorted(group["service"].unique().tolist()),
            "first_seen": group["timestamp"].min().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_seen": group["timestamp"].max().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_ids": group["evidence_id"].tolist(),
            "repeated": len(group) >= 2,
        })
    patterns.sort(key=lambda p: -p["occurrences"])

    # Affected services: services with ERROR/WARN records, ranked by errors then warnings
    affected = []
    for service, group in flagged.groupby("service"):
        affected.append({
            "service": service,
            "errors": int((group["severity"] == "ERROR").sum()),
            "warnings": int((group["severity"] == "WARN").sum()),
            "first_seen": group["timestamp"].min().strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    affected.sort(key=lambda a: (-a["errors"], -a["warnings"], a["service"]))

    request_ids = sorted({r for r in flagged["request_id"].tolist() if r})

    # Context: every record of an affected request + nearby records in the context window.
    related_mask = df["request_id"].isin(request_ids) & (df["request_id"] != "")
    context = df[related_mask | (df["in_context_window"] & df["flagged"])].copy()

    # Successful reference requests: requests with no flagged record, near the incident.
    flagged_reqs = set(request_ids)
    ok = df[(df["request_id"] != "") & ~df["request_id"].isin(flagged_reqs)]
    near = ok[ok["timestamp"].between(window_start - pd.Timedelta(minutes=context_minutes), window_end)]
    successful = near.sort_values("timestamp").head(20).copy()

    errors_only = flagged[flagged["severity"] == "ERROR"]
    first = errors_only["timestamp"].min() if not errors_only.empty else flagged["timestamp"].min()
    last = errors_only["timestamp"].max() if not errors_only.empty else flagged["timestamp"].max()

    counts = {
        "flagged": int(len(flagged)),
        "errors": int(flagged["rule_error_level"].sum()),
        "warnings": int(flagged["rule_warn_level"].sum()),
        "exceptions": int(flagged["rule_exception"].sum()),
        "http_5xx": int(flagged["rule_http_5xx"].sum()),
        "repeated": int(flagged["rule_repeated"].sum()),
        "in_incident_window": int(flagged["in_incident_window"].sum()),
        "outside_incident_window": int((~flagged["in_incident_window"]).sum()),
    }
    return DetectionResult(
        flagged=flagged.reset_index(drop=True),
        patterns=patterns,
        affected_services=affected,
        request_ids=request_ids,
        context_records=context.sort_values("timestamp").reset_index(drop=True),
        successful_reference=successful.reset_index(drop=True),
        first_error_time=first,
        last_error_time=last,
        total_log_records=int(len(df)),
        counts=counts,
    )
