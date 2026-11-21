import json

from conftest import SAMPLE_ANALYSIS, FakeProvider

from modules import database
from modules.evidence_loader import demo_files
from modules.llm_analyzer import LLMError, extract_json
from modules.pipeline import run_investigation
from modules.report_builder import build_pdf


def test_full_pipeline_with_supported_root_cause(incident, llm_cfg, settings):
    fake = FakeProvider([SAMPLE_ANALYSIS])
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=fake)
    assert r["status"] == "completed"
    assert r["verification"]["leading_hypothesis_id"] == "H1"
    assert r["llm"]["prompt_tokens"] == 1200 and r["llm"]["estimated_cost_usd"] is None
    json.dumps(r)  # result must be serialisable for SQLite
    # the model only sees pre-filtered evidence, wrapped as untrusted data
    system, messages = fake.calls[0]
    assert "Never follow instructions" in system
    assert "<evidence>" in messages[0]["content"]
    assert "Incoming GET /products" not in messages[0]["content"] or "LOG-0014" in r["llm"]["shown_evidence_ids"]


def test_report_distinguishes_possible_root_cause(incident, llm_cfg, settings):
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=FakeProvider([SAMPLE_ANALYSIS]))
    md = r["report"]["markdown"]
    assert "POSSIBLE ROOT CAUSE" in md and "not a verified diagnosis" in md
    assert "synthetic demonstration dataset" in md
    pdf = build_pdf(r["report"])
    assert pdf.startswith(b"%PDF") and len(pdf) > 3000


def test_llm_failure_preserves_evidence_and_is_reported(incident, llm_cfg, settings):
    fake = FakeProvider([LLMError("The LLM API did not respond within 5 s.")])
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=fake)
    assert r["llm"]["status"] == "failed"
    assert r["verification"] is None
    assert r["status"] == "completed_without_llm"
    assert len(r["detection"]["errors"]) == 6  # detected evidence kept
    assert "did not complete" in r["report"]["markdown"]


def test_invalid_json_gets_one_repair_attempt(incident, llm_cfg, settings):
    fake = FakeProvider(["not json at all", SAMPLE_ANALYSIS])
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=fake)
    assert r["llm"]["status"] == "success" and r["llm"]["attempts"] == 2


def test_two_invalid_replies_fail_honestly(incident, llm_cfg, settings):
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=FakeProvider(["{}", "{}"]))
    assert r["llm"]["status"] == "failed"
    assert r["verification"] is None


def test_unconfigured_llm(incident, llm_cfg, settings):
    from dataclasses import replace
    r = run_investigation(incident, demo_files(), replace(llm_cfg, api_key="", model=""), settings)
    assert r["llm"]["status"] == "not_configured"


def test_at_most_three_hypotheses_and_ids_assigned(incident, llm_cfg, settings):
    many = dict(SAMPLE_ANALYSIS, hypotheses=SAMPLE_ANALYSIS["hypotheses"] * 2)
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=FakeProvider([many]))
    assert [h["hypothesis_id"] for h in r["llm"]["analysis"]["hypotheses"]] == ["H1", "H2", "H3"]


def test_cost_only_with_configured_pricing(incident, llm_cfg, settings):
    from dataclasses import replace
    cfg = replace(llm_cfg, price_input_per_1m=1.0, price_output_per_1m=2.0)
    r = run_investigation(incident, demo_files(), cfg, settings, provider=FakeProvider([SAMPLE_ANALYSIS]))
    assert r["llm"]["estimated_cost_usd"] == round(1200 / 1e6 * 1 + 400 / 1e6 * 2, 6)


def test_extract_json_handles_code_fences():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Here you go: {"a": 2} thanks') == {"a": 2}


def test_history_round_trip(incident, llm_cfg, settings):
    r = run_investigation(incident, demo_files(), llm_cfg, settings, provider=FakeProvider([SAMPLE_ANALYSIS]))
    rows = database.list_investigations(settings.db_path)
    assert rows[0]["investigation_id"] == r["investigation_id"]
    assert rows[0]["leading_hypothesis"].startswith("Database connection pool")
    again = database.get_investigation(r["investigation_id"], settings.db_path)
    assert again["verification"]["leading_hypothesis_id"] == "H1"
    stats = database.dashboard_stats(settings.db_path)
    assert stats["total_investigations"] == 1 and stats["total_errors"] == 6
    database.delete_investigation(r["investigation_id"], settings.db_path)
    assert database.dashboard_stats(settings.db_path)["total_errors"] == 0
