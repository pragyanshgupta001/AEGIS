"""Shared test fixtures.

`FakeProvider` stands in for the LLM API in tests only. It is never used by the
application itself; the app always calls the real configured provider.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules.config import AppSettings, LLMConfig  # noqa: E402
from modules.evidence_loader import demo_files, load_bundle  # noqa: E402
from modules.incident_manager import build_incident  # noqa: E402

DEMO_START = "2026-10-14T10:04:00Z"
DEMO_END = "2026-10-14T10:13:00Z"

SAMPLE_ANALYSIS = {
    "incident_summary": "Order creation failed intermittently with database connection timeouts in order-service.",
    "affected_services": ["order-service", "api-gateway"],
    "detected_error_patterns": ["DB_CONN_TIMEOUT repeated 3 times in order-service"],
    "hypotheses": [
        {
            "title": "Database connection pool exhaustion after pool size reduction",
            "suspected_services": ["order-service", "database"],
            "suspected_fault": "connection pool exhausted",
            "explanation": "The pool maximum was reduced from 30 to 5 shortly before failures began.",
            "observed_facts": ["LOG-0008 shows ConnectionTimeout", "MET-0003 shows pool 100%"],
            "inferences": ["The smaller pool could not serve concurrent order requests"],
            "supporting_evidence_ids": ["LOG-0008", "LOG-0012", "LOG-0016", "MET-0003", "MET-0006",
                                        "MET-0007", "trace-2002/s7", "trace-2003/s10", "chg-501"],
            "contradicting_evidence_ids": [],
            "model_confidence": "high",
        },
        {
            "title": "Payment service failure",
            "suspected_services": ["payment-service"],
            "suspected_fault": "payment service unavailable",
            "explanation": "Payment requests were not initiated.",
            "supporting_evidence_ids": ["LOG-0013", "MET-0004"],
            "contradicting_evidence_ids": [],
            "model_confidence": "low",
        },
        {
            "title": "Product catalogue deployment regression",
            "suspected_services": ["product-service"],
            "suspected_fault": "regression in v1.8.0",
            "explanation": "A deployment happened before the incident.",
            "supporting_evidence_ids": ["chg-502", "LOG-9999"],
            "contradicting_evidence_ids": [],
            "model_confidence": "medium",
        },
    ],
    "recommended_next_steps": ["Restore the pool maximum to 30 in a test environment and compare."],
    "limitations_and_missing_evidence": ["No database-side metrics were provided."],
}


class FakeProvider:
    """Returns canned responses in order; records the prompts it was sent."""

    def __init__(self, responses, usage=None):
        self.responses = list(responses)
        self.usage = usage or {"prompt_tokens": 1200, "completion_tokens": 400}
        self.calls = []

    def complete(self, system, messages):
        self.calls.append((system, messages))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return (item if isinstance(item, str) else json.dumps(item)), self.usage


@pytest.fixture
def bundle():
    return load_bundle(demo_files())


@pytest.fixture
def incident():
    inc, errors = build_incident("Order creation failures", "Customers report failed checkouts.", "ShopEase",
                                 DEMO_START, DEMO_END, "order-service", is_demo=True)
    assert not errors
    return inc


@pytest.fixture
def llm_cfg():
    return LLMConfig(provider="openai_compatible", api_key="test", base_url="https://example.invalid/v1",
                     model="test-model", timeout_seconds=5, temperature=0.0, max_tokens=1000, json_mode=True,
                     price_input_per_1m=None, price_output_per_1m=None)


@pytest.fixture
def settings(tmp_path):
    return AppSettings(db_path=tmp_path / "test.db", change_lookback_minutes=60, context_minutes=10)
