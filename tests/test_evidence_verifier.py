import copy

from conftest import SAMPLE_ANALYSIS

from modules.error_detector import detect_errors
from modules.evidence_correlator import correlate
from modules.evidence_verifier import CONTRADICTED, INSUFFICIENT, SUPPORTED, verify_all
from modules.llm_analyzer import LLMAnalysis


def verify(bundle, incident, analysis, shown=None):
    d = detect_errors(bundle.logs, incident.start_time, incident.end_time, 10)
    c = correlate(bundle, d, incident, 10, 60)
    analysis = LLMAnalysis.model_validate(analysis).model_dump()
    anomalies = {k: v.get("anomalies", []) for k, v in c.registry.items() if v["type"] == "metric"}
    shown = list(c.registry) if shown is None else shown
    return verify_all(analysis, c.registry, shown, incident, bundle, d.first_error_time, anomalies, 10, 60)


def by_id(out):
    return {r["hypothesis_id"]: r for r in out["results"]}


def test_pool_exhaustion_hypothesis_is_supported(bundle, incident):
    out = verify(bundle, incident, SAMPLE_ANALYSIS)
    h1 = by_id(out)["H1"]
    assert h1["status"] == SUPPORTED
    assert h1["support_types"] == 4  # logs, metrics, traces, changes
    assert h1["contradiction_count"] == 0
    assert out["leading_hypothesis_id"] == "H1"
    change = next(s for s in h1["supporting"] if s["evidence_id"] == "chg-501")
    assert "precedes first error by 6.2 min" in change["note"]


def test_payment_hypothesis_contradicted_by_healthy_metrics(bundle, incident):
    h2 = by_id(verify(bundle, incident, SAMPLE_ANALYSIS))["H2"]
    assert h2["status"] == CONTRADICTED
    assert any("within normal range" in c["reason"] for c in h2["contradictions"])
    assert any(n["evidence_id"] == "MET-0004" for n in h2["not_counted"])


def test_invented_identifier_is_flagged(bundle, incident):
    h3 = by_id(verify(bundle, incident, SAMPLE_ANALYSIS))["H3"]
    assert "LOG-9999" in h3["invalid_ids"]
    assert h3["status"] == CONTRADICTED  # product-service only logged successful activity


def test_model_confidence_is_ignored(bundle, incident):
    analysis = copy.deepcopy(SAMPLE_ANALYSIS)
    analysis["hypotheses"][1]["model_confidence"] = "high"
    assert by_id(verify(bundle, incident, analysis))["H2"]["status"] == CONTRADICTED


def test_ids_not_shown_to_model_do_not_count(bundle, incident):
    out = verify(bundle, incident, SAMPLE_ANALYSIS, shown=["LOG-0008"])
    h1 = by_id(out)["H1"]
    assert "MET-0003" in h1["not_shown_ids"]
    assert h1["status"] != SUPPORTED


def test_only_hallucinated_ids_give_insufficient(bundle, incident):
    analysis = {"incident_summary": "x", "hypotheses": [{
        "title": "made up", "suspected_services": ["order-service"],
        "supporting_evidence_ids": ["LOG-7777", "MET-7777"]}]}
    r = by_id(verify(bundle, incident, analysis))["H1"]
    assert r["status"] == INSUFFICIENT
    assert set(r["invalid_ids"]) == {"LOG-7777", "MET-7777"}


def test_records_outside_incident_period_not_counted(bundle, incident):
    analysis = {"incident_summary": "x", "hypotheses": [{
        "title": "early", "suspected_services": ["order-service"],
        "supporting_evidence_ids": ["LOG-0001", "LOG-0002"]}]}  # 10:00:02, successful, before window
    r = by_id(verify(bundle, incident, analysis))["H1"]
    assert r["support_count"] == 0
    assert r["status"] in (INSUFFICIENT, CONTRADICTED)


def test_hypothesis_without_service_is_insufficient(bundle, incident):
    analysis = {"incident_summary": "x", "hypotheses": [{
        "title": "vague", "suspected_services": [], "supporting_evidence_ids": ["LOG-0008", "MET-0003", "chg-501"]}]}
    assert by_id(verify(bundle, incident, analysis))["H1"]["status"] == INSUFFICIENT


def test_change_after_first_error_is_contradiction(bundle, incident):
    b = copy.deepcopy(bundle)
    idx = b.changes.index[b.changes["evidence_id"] == "chg-501"][0]
    b.changes.loc[idx, "timestamp"] = b.changes.loc[idx, "timestamp"] + __import__("pandas").Timedelta(minutes=10)
    analysis = {"incident_summary": "x", "hypotheses": [{
        "title": "config change", "suspected_services": ["order-service"], "supporting_evidence_ids": ["chg-501"]}]}
    r = by_id(verify(b, incident, analysis))["H1"]
    assert r["status"] == CONTRADICTED
    assert any("after the first error" in c["reason"] for c in r["contradictions"])
