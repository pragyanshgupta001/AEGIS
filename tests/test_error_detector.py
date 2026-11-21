import json

import pandas as pd

from modules.error_detector import detect_errors
from modules.evidence_loader import load_bundle


def run(bundle, incident):
    return detect_errors(bundle.logs, incident.start_time, incident.end_time, 10)


def test_flags_error_warn_and_http_5xx(bundle, incident):
    d = run(bundle, incident)
    assert d.counts["flagged"] == 6
    assert d.counts["errors"] == 4
    assert d.counts["warnings"] == 2
    assert d.counts["http_5xx"] == 2
    assert d.counts["exceptions"] == 3


def test_repeated_db_timeout_pattern(bundle, incident):
    d = run(bundle, incident)
    top = d.patterns[0]
    assert top["pattern"] == "DB_CONN_TIMEOUT"
    assert top["occurrences"] == 3
    assert top["services"] == ["order-service"]
    assert top["repeated"] is True


def test_affected_services_ranked_by_errors(bundle, incident):
    d = run(bundle, incident)
    assert [a["service"] for a in d.affected_services] == ["order-service", "api-gateway", "payment-service"]
    assert d.affected_services[0]["errors"] == 3


def test_request_ids_and_first_error(bundle, incident):
    d = run(bundle, incident)
    assert d.request_ids == ["req-1002", "req-1003", "req-1005"]
    assert d.first_error_time == pd.Timestamp("2026-10-14T10:04:12Z")


def test_successful_requests_are_not_flagged_but_kept_as_reference(bundle, incident):
    d = run(bundle, incident)
    flagged_reqs = set(d.flagged["request_id"])
    assert "req-1001" not in flagged_reqs
    assert "req-1001" in set(d.successful_reference["request_id"])


def test_context_contains_full_failed_request(bundle, incident):
    d = run(bundle, incident)
    req1002 = d.context_records[d.context_records["request_id"] == "req-1002"]
    assert "INFO" in set(req1002["level"])  # the successful steps before the failure are included


def test_3000_ms_is_not_mistaken_for_http_5xx():
    logs = [{"timestamp": "2026-10-14T10:00:00Z", "level": "INFO", "service": "a",
             "message": "request took 3000 ms, status 200"}]
    b = load_bundle({"logs": [("l.json", json.dumps(logs).encode())]})
    d = detect_errors(b.logs, pd.Timestamp("2026-10-14T09:00:00Z"), pd.Timestamp("2026-10-14T11:00:00Z"))
    assert not d.has_errors


def test_status_code_field_detected_as_5xx():
    logs = [{"timestamp": "2026-10-14T10:00:00Z", "level": "INFO", "service": "a", "status_code": 502,
             "message": "upstream call"}]
    b = load_bundle({"logs": [("l.json", json.dumps(logs).encode())]})
    d = detect_errors(b.logs, pd.Timestamp("2026-10-14T09:00:00Z"), pd.Timestamp("2026-10-14T11:00:00Z"))
    assert d.counts["http_5xx"] == 1


def test_empty_logs():
    d = detect_errors(pd.DataFrame(), pd.Timestamp("2026-10-14T09:00:00Z"), pd.Timestamp("2026-10-14T11:00:00Z"))
    assert not d.has_errors
