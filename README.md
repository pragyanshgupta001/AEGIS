# AEGIS – Incident Investigation Dashboard

**Adaptive, Evidence-Grounded Intelligence System for Software Incident Investigation**
B.Tech Final Year Major Project · Department of Computer Engineering · ZHCET, AMU

AEGIS is an LLM-powered microservices incident investigation system designed to assist engineers in identifying and explaining potential root causes of distributed application failures. It analyzes operational evidence from logs, metrics, distributed traces, and deployment records to generate candidate root-cause hypotheses, verify them against available evidence, and produce structured, evidence-backed incident reports. Featuring adaptive rule-based investigation strategies, evidence quality assessment, and hypothesis verification, AEGIS aims to make microservices Root Cause Analysis (RCA) more transparent, reliable, and explainable. The system is designed to distinguish between supported, contradicted, and inconclusive hypotheses rather than relying on unsupported AI-generated diagnoses.
It investigates incidents in microservice applications. Python rules detect the errors, one LLM proposes up to three candidate root causes, and a separate Python verifier checks every hypothesis against the uploaded evidence before anything is reported. A hypothesis that passes is presented as an *evidence-supported possible root cause*, never as a confirmed diagnosis. AEGIS never changes or "fixes" any system.

---

## 1. Requirements

- Python 3.10 or newer
- An API key for one LLM provider (OpenAI, Groq, OpenRouter, Google Gemini, Anthropic), **or** a local
  [Ollama](https://ollama.com) server (free, no key)

## 2. Install

```bash
cd AEGIS
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS / Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Configure the API key

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

Open `.env` and set at least `LLM_API_KEY` and `LLM_MODEL` (and `LLM_BASE_URL` if not OpenAI). Examples:

| Provider | LLM_PROVIDER | LLM_BASE_URL | LLM_MODEL (example) |
|---|---|---|---|
| OpenAI | openai_compatible | https://api.openai.com/v1 | gpt-4o-mini |
| Groq | openai_compatible | https://api.groq.com/openai/v1 | llama-3.3-70b-versatile |
| Google Gemini | openai_compatible | https://generativelanguage.googleapis.com/v1beta/openai | gemini-2.0-flash |
| Ollama (local) | openai_compatible | http://localhost:11434/v1 | llama3.1 |
| Anthropic | anthropic | https://api.anthropic.com | claude-sonnet-4-5 |

Model names change over time; use one your provider currently lists. If your provider rejects the
`response_format` option, set `LLM_JSON_MODE=false`. Cost is shown only if you fill in
`LLM_PRICE_INPUT_PER_1M` and `LLM_PRICE_OUTPUT_PER_1M` from the provider's current pricing page.

The key is read only from `.env`; it is never hard-coded, logged or stored in the database.

## 4. Run

```bash
streamlit run app.py
```

The dashboard opens at http://localhost:8501.

## 5. Demonstration (sample incident)

1. Open **New Investigation** in the sidebar.
2. Click **Load Sample Incident**. The form is filled and the four files in `demo_data/` are attached.
3. Click **Start Investigation**. The status box shows each workflow step as it runs.
4. On **Investigation Results**, walk through the tabs:
   - **Summary** – timeline, errors by service, conclusion banner
   - **Detected Errors** – records flagged by Python rules, repeated patterns, error frequency
   - **Correlated Evidence** – latency and DB connection pool charts, related metrics, traces, changes
   - **Hypotheses & Verification** – each LLM hypothesis with the verifier's checks, supporting,
     contradicting and missing evidence, and its status
   - **Final Report** – full report, **Download report (PDF)**
5. Open **Investigation History** and click **Open report** to reopen it.

The sample is a synthetic, fictional e-commerce incident (14 Oct 2026, ~10:04–10:12 UTC): order creation fails
with database connection timeouts after a configuration change reduced the order-service connection pool
maximum from 30 to 5. Exact LLM wording varies between runs and models; the verifier decides each status.

Without an API key the app still runs: detection, correlation, charts and a partial report are produced, and
the report states plainly that no LLM analysis was performed.

## 6. Run the automated tests

```bash
python -m pytest -q
```

The tests use a stand-in LLM (`tests/conftest.py`) and a local mock HTTP server, so they need no API key or
internet access. They cover evidence loading, rule-based detection, correlation, verification decisions
(supported / contradicted / insufficient, invented identifiers, timing), LLM failure handling, JSON repair,
the HTTP adapters, PDF generation and database history.

## 7. How the workflow maps to the code

| Step | What happens | Module |
|---|---|---|
| 1 Incident submission | Validate form fields and time window | `modules/incident_manager.py` |
| 2 Evidence loading | Read JSON/CSV, assign evidence IDs (`LOG-0008`, `MET-0003`, `trace-2002/s7`, `chg-501`), report bad records | `modules/evidence_loader.py` |
| 3 Error detection | Python rules: ERROR, WARN, exceptions, HTTP 5xx, repeated patterns, services, request IDs | `modules/error_detector.py` |
| 4 Evidence correlation | Metrics by service + time (baseline vs. incident), traces by request ID, changes before the incident | `modules/evidence_correlator.py` |
| 5 LLM investigation | Bounded evidence package, untrusted-data prompt, strict JSON schema, ≤ 3 hypotheses | `modules/llm_analyzer.py` |
| 6 Evidence verification | Cited IDs exist, services match, timestamps in period, support / contradiction / missing evidence | `modules/evidence_verifier.py` |
| 7 Report generation | Structured report, Markdown + PDF | `modules/report_builder.py` |
| 8 Storage | SQLite: incidents, investigations, errors, hypotheses, verification results, reports | `modules/database.py` |
| Orchestration | Runs steps 2–8 in order | `modules/pipeline.py` |
| Charts | Plotly charts from uploaded data only | `modules/charts.py` |

### Verification rule (summary)

A cited record counts as support only if it exists, was actually shown to the model, concerns the suspected
service, falls inside the incident period (changes: up to 60 min before), and shows abnormal behaviour (a change
must also precede the first error). AEGIS then runs its own contradiction checks: healthy metrics or only
successful logs for the suspected service during the incident, or a cited change that happened after the first
error.

- **SUPPORTED**: ≥ 3 verified records from ≥ 2 evidence types, and support at least 3× the contradictions
- **CONTRADICTED**: contradictions exist and either outweigh the support or the support comes from only one
  evidence type (also when there is no support at all but there are contradictions)
- **INSUFFICIENT EVIDENCE**: everything else (including only invented IDs or no suspected service)

The model's own confidence is displayed but never used in the decision.

## 8. Evidence file formats

- **Application logs (JSON list)**: `timestamp`, `level`, `service`, `message`; optional `request_id`,
  `error_code`, `exception`, `status_code`
- **System metrics (CSV)**: `timestamp`, `service`, plus numeric columns such as `cpu_percent`,
  `memory_percent`, `latency_ms`, `error_rate_percent`, `db_connection_pool_used_percent`
- **Distributed traces (JSON list)**: `trace_id`, `request_id`, `timestamp`, `spans` (`span_id`, `service`,
  `operation`, `duration_ms`, `status`, optional `error`)
- **Deployment changes (CSV)**: `change_id`, `timestamp`, `service`, `change_type`, `description`, `version`

All timestamps are treated as UTC. Several files per type may be uploaded; they are combined.

## 9. Scope of this prototype

Included: one configurable LLM, rule-based error detection, evidence correlation, Python verification,
reports, history. Not included by design: multi-agent orchestration, automatic model routing, automatic
remediation, live monitoring integrations, Kubernetes/cloud deployment.

## 10. Project structure

```
AEGIS/
├── app.py                    Streamlit dashboard
├── requirements.txt
├── .env.example              configuration template (copy to .env)
├── .streamlit/config.toml    theme
├── modules/                  workflow modules (see table above)
├── demo_data/                synthetic sample incident (4 evidence files + README)
├── data/                     SQLite database (created on first run)
├── reports/                  output folder
└── tests/                    pytest suites
```
