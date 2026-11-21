"""SQLite persistence (workflow step 8).

Tables: incidents, investigations, detected_errors, hypotheses,
verification_results, reports. The full investigation result is also kept as
JSON so a previous investigation can be reopened exactly as it was produced.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    application TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    affected_service TEXT,
    is_demo INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    status TEXT NOT NULL,
    llm_status TEXT,
    llm_provider TEXT,
    llm_model TEXT,
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    estimated_cost_usd REAL,
    error_count INTEGER,
    leading_hypothesis TEXT,
    error_message TEXT,
    result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detected_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    evidence_id TEXT, timestamp TEXT, service TEXT, level TEXT,
    error_code TEXT, request_id TEXT, message TEXT, rules TEXT
);
CREATE TABLE IF NOT EXISTS hypotheses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    hypothesis_id TEXT, title TEXT, suspected_services TEXT, suspected_fault TEXT,
    explanation TEXT, model_confidence TEXT, supporting_ids TEXT, contradicting_ids TEXT
);
CREATE TABLE IF NOT EXISTS verification_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    hypothesis_id TEXT, status TEXT, support_count INTEGER, contradiction_count INTEGER,
    rationale TEXT, details_json TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    report_markdown TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_errors_service ON detected_errors(service);
"""


@contextmanager
def connect(db_path: Path):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def save_investigation(result: dict, db_path: Path) -> None:
    init_db(db_path)
    inc = result["incident"]
    llm = result.get("llm") or {}
    ver = result.get("verification") or {}
    analysis = llm.get("analysis") or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?)",
            (inc["incident_id"], inc["title"], inc["description"], inc.get("application", ""), inc["start_time"],
             inc["end_time"], inc.get("affected_service", ""), int(bool(inc.get("is_demo"))), now))
        leading = ver.get("leading_hypothesis_id")
        leading_title = next((h["title"] for h in analysis.get("hypotheses", []) if h["hypothesis_id"] == leading), None)
        conn.execute(
            "INSERT OR REPLACE INTO investigations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (result["investigation_id"], inc["incident_id"], result.get("status", ""), llm.get("status"),
             llm.get("provider"), llm.get("model"), result.get("started_at"), result.get("completed_at"),
             result.get("duration_seconds"), llm.get("prompt_tokens"), llm.get("completion_tokens"),
             llm.get("estimated_cost_usd"), len(result.get("detection", {}).get("errors", [])),
             leading_title, llm.get("error") or None, json.dumps(result, default=str)))
        conn.executemany(
            "INSERT INTO detected_errors (investigation_id, evidence_id, timestamp, service, level, error_code, "
            "request_id, message, rules) VALUES (?,?,?,?,?,?,?,?,?)",
            [(result["investigation_id"], e["evidence_id"], e.get("timestamp_iso"), e["service"], e["level"],
              e.get("error_code"), e.get("request_id"), e["message"], ", ".join(e.get("rules", [])))
             for e in result.get("detection", {}).get("errors", [])])
        conn.executemany(
            "INSERT INTO hypotheses (investigation_id, hypothesis_id, title, suspected_services, suspected_fault, "
            "explanation, model_confidence, supporting_ids, contradicting_ids) VALUES (?,?,?,?,?,?,?,?,?)",
            [(result["investigation_id"], h["hypothesis_id"], h["title"], ", ".join(h.get("suspected_services", [])),
              h.get("suspected_fault"), h.get("explanation"), h.get("model_confidence"),
              ", ".join(h.get("supporting_evidence_ids", [])), ", ".join(h.get("contradicting_evidence_ids", [])))
             for h in analysis.get("hypotheses", [])])
        conn.executemany(
            "INSERT INTO verification_results (investigation_id, hypothesis_id, status, support_count, "
            "contradiction_count, rationale, details_json) VALUES (?,?,?,?,?,?,?)",
            [(result["investigation_id"], v["hypothesis_id"], v["status"], v["support_count"],
              v["contradiction_count"], v["rationale"], json.dumps(v, default=str))
             for v in ver.get("results", [])])
        report = result.get("report") or {}
        conn.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?)",
                     ("RPT-" + result["investigation_id"][4:], result["investigation_id"],
                      report.get("markdown", ""), now))


def list_investigations(db_path: Path, limit: int = 200) -> list[dict]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT v.investigation_id, v.incident_id, i.title, i.application, i.start_time, i.is_demo, v.status, "
            "v.llm_status, v.llm_model, v.started_at, v.duration_seconds, v.error_count, v.leading_hypothesis "
            "FROM investigations v JOIN incidents i ON i.incident_id = v.incident_id "
            "ORDER BY v.started_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_investigation(investigation_id: str, db_path: Path) -> dict | None:
    init_db(db_path)
    with connect(db_path) as conn:
        row = conn.execute("SELECT result_json FROM investigations WHERE investigation_id = ?",
                           (investigation_id,)).fetchone()
    return json.loads(row["result_json"]) if row else None


def delete_investigation(investigation_id: str, db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.execute("DELETE FROM investigations WHERE investigation_id = ?", (investigation_id,))


def dashboard_stats(db_path: Path) -> dict:
    init_db(db_path)
    with connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM investigations WHERE status = 'completed'").fetchone()[0]
        partial = conn.execute("SELECT COUNT(*) FROM investigations WHERE status = 'completed_without_llm'").fetchone()[0]
        errors = conn.execute("SELECT COUNT(*) FROM detected_errors").fetchone()[0]
        svc_rows = conn.execute("SELECT service, COUNT(*) AS n FROM detected_errors GROUP BY service ORDER BY n DESC").fetchall()
        inv_svc = conn.execute("SELECT service, COUNT(DISTINCT investigation_id) AS n FROM detected_errors "
                               "GROUP BY service ORDER BY n DESC").fetchall()
        statuses = conn.execute("SELECT status FROM verification_results").fetchall()
    return {
        "total_investigations": total,
        "completed": completed,
        "completed_without_llm": partial,
        "total_errors": errors,
        "errors_by_service": [dict(r) for r in svc_rows],
        "investigations_by_service": [dict(r) for r in inv_svc],
        "verification_status_counts": dict(Counter(r[0] for r in statuses)),
    }
