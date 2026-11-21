"""AEGIS - Incident Investigation Dashboard (Streamlit front end).

Run with:  streamlit run app.py
"""
from __future__ import annotations

from datetime import date, time

import pandas as pd
import streamlit as st

from modules import charts, database
from modules.config import get_app_settings, get_llm_config
from modules.evidence_loader import MODALITY_LABELS, demo_files
from modules.incident_manager import build_incident
from modules.pipeline import run_investigation
from modules.report_builder import build_pdf, pattern_label

st.set_page_config(page_title="AEGIS – Incident Investigation Dashboard", layout="wide",
                   initial_sidebar_state="expanded")

SETTINGS = get_app_settings()
LLM_CFG = get_llm_config()
database.init_db(SETTINGS.db_path)

PAGES = ["Dashboard", "New Investigation", "Investigation Results", "Investigation History"]
STATUS_STYLE = {
    "SUPPORTED": ("#E6F4EA", "#1B5E20"),
    "CONTRADICTED": ("#FDE7E7", "#B71C1C"),
    "INSUFFICIENT EVIDENCE": ("#FFF4DD", "#7A4B00"),
    "completed": ("#E6F4EA", "#1B5E20"),
    "completed_without_llm": ("#FFF4DD", "#7A4B00"),
    "failed": ("#FDE7E7", "#B71C1C"),
    "ok": ("#E6F4EA", "#1B5E20"),
    "warn": ("#FFF4DD", "#7A4B00"),
    "skipped": ("#ECEFF3", "#455A64"),
}
SAMPLE = {
    "f_title": "Intermittent order creation failures",
    "f_desc": ("Customers reported that placing orders on the e-commerce store intermittently failed with "
               "HTTP 503 errors between roughly 10:04 and 10:12 UTC. Product browsing appeared unaffected."),
    "f_app": "ShopEase e-commerce platform (demo)",
    "f_start_date": date(2026, 10, 14), "f_start_time": time(10, 4),
    "f_end_date": date(2026, 10, 14), "f_end_time": time(10, 13),
    "f_service": "",
}

# --------------------------------------------------------------------------- styling
st.markdown("""
<style>
:root { --navy:#0B1F3A; --blue:#1E40AF; --line:#D5DEEA; }
[data-testid="stSidebar"] { background: linear-gradient(180deg,#0B1F3A 0%,#13305A 100%); }
[data-testid="stSidebar"] * { color:#F2F6FC !important; }
[data-testid="stSidebar"] .stRadio label p { font-size:1.02rem; }
.block-container { padding-top: 1.4rem; }
.aegis-header { background:#0B1F3A; color:#fff; padding:18px 24px; border-radius:12px; margin-bottom:18px; }
.aegis-header h1 { color:#fff; font-size:1.65rem; margin:0; }
.aegis-header p { color:#C9D6EA; margin:4px 0 0 0; font-size:.95rem; }
.kpi { background:#fff; border:1px solid var(--line); border-left:5px solid var(--blue); border-radius:10px;
       padding:14px 16px; }
.kpi .v { font-size:1.9rem; font-weight:700; color:var(--navy); line-height:1.1; }
.kpi .l { font-size:.85rem; color:#56667A; text-transform:uppercase; letter-spacing:.04em; }
.badge { display:inline-block; padding:3px 10px; border-radius:999px; font-weight:600; font-size:.8rem; }
.card { border:1px solid var(--line); border-radius:12px; padding:16px 18px; margin-bottom:14px; background:#fff; }
.conclusion { border-radius:12px; padding:16px 18px; margin:6px 0 14px 0; }
.stage { border:1px solid var(--line); border-radius:10px; padding:8px 10px; font-size:.82rem; height:100%; }
.small { color:#56667A; font-size:.85rem; }
</style>
""", unsafe_allow_html=True)


def badge(text: str) -> str:
    bg, fg = STATUS_STYLE.get(text, ("#ECEFF3", "#0B1F3A"))
    return f'<span class="badge" style="background:{bg};color:{fg}">{text}</span>'


def kpi(col, value, label):
    col.markdown(f'<div class="kpi"><div class="v">{value}</div><div class="l">{label}</div></div>',
                 unsafe_allow_html=True)


def header(title: str, subtitle: str):
    st.markdown(f'<div class="aegis-header"><h1>{title}</h1><p>{subtitle}</p></div>', unsafe_allow_html=True)


def show_chart(fig, empty_msg: str = "No data available for this chart."):
    if fig is None:
        st.caption(empty_msg)
    else:
        st.plotly_chart(fig)


def esc(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# --------------------------------------------------------------------------- state & navigation
def init_state():
    defaults = {"page": "Dashboard", "nav_target": None, "current_result": None, "sample_loaded": False,
                "f_title": "", "f_desc": "", "f_app": "", "f_service": "",
                "f_start_date": date.today(), "f_start_time": time(0, 0),
                "f_end_date": date.today(), "f_end_time": time(1, 0)}
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)
    if st.session_state.nav_target:
        st.session_state.page = st.session_state.nav_target
        st.session_state.nav_target = None


def go(page: str):
    st.session_state.nav_target = page


def open_investigation(inv_id: str):
    result = database.get_investigation(inv_id, SETTINGS.db_path)
    if result:
        st.session_state.current_result = result
        go("Investigation Results")


def load_sample():
    for k, v in SAMPLE.items():
        st.session_state[k] = v
    st.session_state.sample_loaded = True


def clear_sample():
    st.session_state.sample_loaded = False


init_state()

with st.sidebar:
    st.markdown("## AEGIS")
    st.caption("Adaptive, Evidence-Grounded Intelligence System for Software Incident Investigation")
    st.radio("Navigation", PAGES, key="page", label_visibility="collapsed")
    st.divider()
    st.markdown("**LLM configuration**")
    if LLM_CFG.is_configured:
        st.markdown(f"Provider: `{LLM_CFG.provider}`  \nModel: `{LLM_CFG.model}`")
    else:
        st.markdown("Not configured. Copy `.env.example` to `.env`, set `LLM_API_KEY` and `LLM_MODEL`, then restart.")
    st.caption("One LLM proposes hypotheses. Python rules detect errors and verify every hypothesis. "
               "AEGIS never changes production systems.")


# --------------------------------------------------------------------------- pages
def page_dashboard():
    header("AEGIS – Incident Investigation Dashboard",
           "Evidence-grounded investigation of incidents in microservice applications")
    stats = database.dashboard_stats(SETTINGS.db_path)
    c1, c2, c3, c4 = st.columns(4)
    kpi(c1, stats["total_investigations"], "Total investigations")
    kpi(c2, stats["total_errors"], "Total errors detected")
    kpi(c3, stats["completed"], "Investigations completed")
    kpi(c4, stats["completed_without_llm"], "Completed without LLM")
    st.write("")
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Recent investigations")
        recent = database.list_investigations(SETTINGS.db_path, limit=6)
        if not recent:
            st.info("No investigations yet. Open **New Investigation** and click **Load Sample Incident** to try the demo.")
        for r in recent:
            with st.container(border=True):
                a, b = st.columns([5, 1])
                a.markdown(f"**{esc(r['title'])}** &nbsp; {badge(r['status'])}", unsafe_allow_html=True)
                a.caption(f"{r['investigation_id']} · {r['started_at']} · {r['error_count']} error record(s) · "
                          f"Leading explanation: {r['leading_hypothesis'] or 'none supported'}")
                b.button("Open", key=f"dash_open_{r['investigation_id']}", on_click=open_investigation,
                         args=(r["investigation_id"],))
    with right:
        st.subheader("Most frequently affected services")
        show_chart(charts.dashboard_services(stats), "Affected services appear here after the first investigation.")
        vs = stats["verification_status_counts"]
        if vs:
            st.markdown("**Hypothesis verification outcomes (all investigations)**")
            st.markdown(" &nbsp; ".join(f"{badge(k)} {v}" for k, v in vs.items()), unsafe_allow_html=True)


def page_new_investigation():
    header("New Investigation", "Describe the incident and upload the evidence. AEGIS runs the full workflow automatically.")
    b1, b2, _ = st.columns([1.3, 1, 4])
    b1.button("Load Sample Incident", on_click=load_sample, type="secondary")
    if st.session_state.sample_loaded:
        b2.button("Clear sample", on_click=clear_sample)
        st.success("Sample incident loaded: the four synthetic demo evidence files from `demo_data/` will be used "
                   "for any evidence type you do not upload yourself.")

    st.subheader("1 · Incident details")
    c1, c2 = st.columns(2)
    c1.text_input("Incident title *", key="f_title", max_chars=150)
    c2.text_input("Application name *", key="f_app")
    st.text_area("Incident description *", key="f_desc", height=110)
    c1, c2, c3, c4, c5 = st.columns([1, 1, 1, 1, 1.4])
    c1.date_input("Start date (UTC) *", key="f_start_date")
    c2.time_input("Start time (UTC) *", key="f_start_time", step=60)
    c3.date_input("End date (UTC) *", key="f_end_date")
    c4.time_input("End time (UTC) *", key="f_end_time", step=60)
    c5.text_input("Affected service (optional)", key="f_service", placeholder="e.g. order-service")

    st.subheader("2 · Evidence files")
    st.caption("You may upload several files per evidence type. Uploaded content is treated as untrusted data.")
    u1, u2 = st.columns(2)
    uploads = {
        "logs": u1.file_uploader(MODALITY_LABELS["logs"], type=["json", "jsonl"], accept_multiple_files=True, key="up_logs"),
        "metrics": u2.file_uploader(MODALITY_LABELS["metrics"], type=["csv"], accept_multiple_files=True, key="up_metrics"),
        "traces": u1.file_uploader(MODALITY_LABELS["traces"], type=["json", "jsonl"], accept_multiple_files=True, key="up_traces"),
        "changes": u2.file_uploader(MODALITY_LABELS["changes"], type=["csv"], accept_multiple_files=True, key="up_changes"),
    }

    files: dict[str, list[tuple[str, bytes]]] = {}
    sample = demo_files() if st.session_state.sample_loaded else {}
    rows = []
    for modality, up in uploads.items():
        if up:
            files[modality] = [(f.name, f.getvalue()) for f in up]
            rows.append([MODALITY_LABELS[modality], ", ".join(f.name for f in up), "uploaded"])
        elif modality in sample:
            files[modality] = sample[modality]
            rows.append([MODALITY_LABELS[modality], sample[modality][0][0], "sample"])
        else:
            rows.append([MODALITY_LABELS[modality], "—", "not provided"])
    st.dataframe(pd.DataFrame(rows, columns=["Evidence type", "File(s)", "Source"]), hide_index=True)

    if not LLM_CFG.is_configured:
        st.warning("No LLM is configured. The investigation will still detect and correlate errors, but no "
                   "hypotheses will be generated until an API key is set in `.env`.")

    if st.button("Start Investigation", type="primary"):
        start = pd.Timestamp.combine(st.session_state.f_start_date, st.session_state.f_start_time)
        end = pd.Timestamp.combine(st.session_state.f_end_date, st.session_state.f_end_time)
        incident, errors = build_incident(st.session_state.f_title, st.session_state.f_desc, st.session_state.f_app,
                                          start, end, st.session_state.f_service,
                                          is_demo=st.session_state.sample_loaded and not any(uploads.values()))
        if "logs" not in files:
            errors.append("Application logs are required - error detection starts from the combined log file.")
        if errors:
            for e in errors:
                st.error(e)
            return
        with st.status("Running investigation…", expanded=True) as status:
            def progress(stage, detail):
                st.write(f"**{stage}** — {detail}")
            try:
                result = run_investigation(incident, files, LLM_CFG, SETTINGS, progress=progress)
            except Exception as exc:  # unexpected failure: show it, never fake a result
                status.update(label="Investigation failed", state="error")
                st.exception(exc)
                return
            llm_ok = (result.get("llm") or {}).get("status") == "success"
            status.update(label="Investigation complete" if llm_ok else "Investigation complete (without LLM analysis)",
                          state="complete" if llm_ok else "error", expanded=False)
        st.session_state.current_result = result
        go("Investigation Results")
        st.rerun()


def render_stages(result):
    stages = result.get("stages", [])
    cols = st.columns(len(stages))
    for col, s in zip(cols, stages):
        col.markdown(f'<div class="stage"><b>{esc(s["stage"])}</b><br>{badge(s["status"])}</div>',
                     unsafe_allow_html=True)


def conclusion_box(result):
    ver = result.get("verification")
    llm = result.get("llm") or {}
    analysis = llm.get("analysis") or {}
    if ver and ver.get("leading_hypothesis_id"):
        h = next(h for h in analysis["hypotheses"] if h["hypothesis_id"] == ver["leading_hypothesis_id"])
        v = next(v for v in ver["results"] if v["hypothesis_id"] == h["hypothesis_id"])
        st.markdown(
            f'<div class="conclusion" style="background:#E6F4EA;border:1px solid #A5D6A7">'
            f'<b>Leading evidence-supported explanation ({h["hypothesis_id"]}):</b> {esc(h["title"])}<br>'
            f'<span class="small">{esc(v["rationale"])} This is a <b>possible root cause</b>, not a verified '
            f'diagnosis — an engineer must confirm it before any remediation.</span></div>', unsafe_allow_html=True)
    elif ver:
        st.markdown('<div class="conclusion" style="background:#FFF4DD;border:1px solid #FFD27F">'
                    '<b>No hypothesis was sufficiently supported by the evidence.</b> No root cause is claimed. '
                    'See missing evidence and next steps in the report.</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="conclusion" style="background:#FDE7E7;border:1px solid #F2B8B8">'
                    f'<b>LLM investigation not completed.</b> {esc(llm.get("error", ""))}<br>'
                    f'<span class="small">The rule-based error detection and evidence correlation below are complete '
                    f'and have been preserved.</span></div>', unsafe_allow_html=True)


def tab_summary(result):
    det, corr = result["detection"], result["correlation"]
    llm = result.get("llm") or {}
    ver = result.get("verification") or {}
    c1, c2, c3, c4 = st.columns(4)
    kpi(c1, det["counts"].get("flagged", 0), "Flagged log records")
    kpi(c2, len(det["affected_services"]), "Affected services")
    kpi(c3, len((llm.get("analysis") or {}).get("hypotheses", [])), "Hypotheses")
    kpi(c4, ver.get("status_counts", {}).get("SUPPORTED", 0), "Supported")
    st.write("")
    analysis = llm.get("analysis") or {}
    if analysis.get("incident_summary"):
        st.markdown("**Incident summary** <span class='small'>(model-generated narrative, not itself verified)</span>",
                    unsafe_allow_html=True)
        st.write(analysis["incident_summary"])
    l, r = st.columns(2)
    with l:
        show_chart(charts.incident_timeline(result))
    with r:
        show_chart(charts.error_distribution(result))
    st.markdown("**Affected services**")
    if det["affected_services"]:
        st.dataframe(pd.DataFrame(det["affected_services"]), hide_index=True)
    else:
        st.caption("No service produced errors or warnings.")
    ev = result["evidence"]
    st.markdown(f"**Evidence used:** {', '.join(ev['available']) or 'none'}"
                + (f" &nbsp;·&nbsp; **Not provided:** {', '.join(ev['missing'])}" if ev["missing"] else ""),
                unsafe_allow_html=True)
    for w in ev["warnings"] + corr.get("notes", []):
        st.caption(f"• {w}")


def tab_errors(result):
    det = result["detection"]
    c = det["counts"]
    st.markdown(f"Python rules flagged **{c.get('flagged', 0)}** of **{det['total_log_records']}** log records "
                f"(ERROR {c.get('errors', 0)} · WARN {c.get('warnings', 0)} · exceptions {c.get('exceptions', 0)} · "
                f"HTTP 5xx {c.get('http_5xx', 0)} · repeated {c.get('repeated', 0)}). "
                f"First error **{det['first_error'] or '-'}**, last error **{det['last_error'] or '-'}**.")
    if det["errors"]:
        df = pd.DataFrame(det["errors"])
        df["rules"] = df["rules"].map(lambda r: ", ".join(r))
        cols = ["evidence_id", "timestamp_iso", "severity", "service", "request_id", "error_code", "message",
                "exception", "rules", "in_incident_window"]
        st.dataframe(df[[c for c in cols if c in df.columns]], hide_index=True)
    else:
        st.info("No error, warning, exception or HTTP 5xx records were found in the logs.")
    l, r = st.columns(2)
    with l:
        st.markdown("**Error patterns**")
        if det["patterns"]:
            st.dataframe(pd.DataFrame([{"pattern": pattern_label(p), "occurrences": p["occurrences"],
                                        "services": ", ".join(p["services"]), "repeated": p["repeated"],
                                        "first_seen": p["first_seen"], "last_seen": p["last_seen"]}
                                       for p in det["patterns"]]), hide_index=True)
    with r:
        show_chart(charts.error_frequency(result))
    with st.expander(f"Surrounding log context for failed requests ({len(det['context'])} records)"):
        st.dataframe(pd.DataFrame(det["context"]), hide_index=True)
    with st.expander(f"Successful reference requests ({len(det['successful_reference'])} records)"):
        st.caption("Successful requests near the incident, used as a comparison baseline.")
        st.dataframe(pd.DataFrame(det["successful_reference"]), hide_index=True)


def tab_correlation(result):
    corr = result["correlation"]
    st.markdown("**Suspect services (from rule-based detection):** " + (", ".join(corr["suspect_services"]) or "none"))
    l, r = st.columns(2)
    with l:
        show_chart(charts.service_latency(result), "No latency metrics were provided.")
    with r:
        show_chart(charts.pool_usage(result), "No database connection pool metrics were provided.")

    st.markdown("#### Related metrics")
    if corr["metrics"]:
        rows = [{"evidence_id": m["evidence_id"], "timestamp": m["timestamp"], "service": m["service"],
                 "phase": m["phase"], **m["values"], "anomalies": "; ".join(m["anomalies"]) or "normal"}
                for m in corr["metrics"]]
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.caption("No related metric rows.")

    st.markdown("#### Related distributed traces")
    if not corr["traces"]:
        st.caption("No related traces.")
    for t in corr["traces"]:
        label = (f"{t['evidence_id']} · {t['request_id']} · {t['path']} · "
                 + ("ERROR" if t["has_error"] else "OK") + f" (matched by {t['matched_by']})")
        with st.expander(label, expanded=t["has_error"]):
            st.dataframe(pd.DataFrame(t["spans"]), hide_index=True)
            if t["deepest_error_span"]:
                st.caption(f"Deepest failing span: {t['deepest_error_span']} ({t['deepest_error_service']}).")

    st.markdown("#### Recent deployment / configuration changes")
    if corr["changes"]:
        st.dataframe(pd.DataFrame(corr["changes"]), hide_index=True)
    else:
        st.caption("No changes in the look-back window.")

    with st.expander("Per-error evidence links"):
        st.dataframe(pd.DataFrame([{**l, "metric_ids": ", ".join(l["metric_ids"]), "trace_ids": ", ".join(l["trace_ids"]),
                                    "change_ids": ", ".join(l["change_ids"])} for l in corr["error_links"]]),
                     hide_index=True)


def tab_hypotheses(result):
    llm = result.get("llm") or {}
    ver = result.get("verification")
    if llm.get("status") != "success":
        st.error(f"LLM investigation status: **{llm.get('status', 'unknown')}**. {llm.get('error', '')}")
        st.caption("No hypotheses were generated, so nothing was verified. The detected evidence is preserved in the other tabs.")
        return
    analysis = llm["analysis"]
    vres = {v["hypothesis_id"]: v for v in (ver or {}).get("results", [])}
    index = result.get("evidence_index", {})
    st.caption("Hypotheses come from the LLM. Their status is decided by AEGIS' Python verifier using the uploaded "
               "evidence - the model's own confidence is shown for reference only.")
    for h in analysis["hypotheses"]:
        v = vres.get(h["hypothesis_id"], {})
        leading = (ver or {}).get("leading_hypothesis_id") == h["hypothesis_id"]
        with st.container(border=True):
            st.markdown(f"### {h['hypothesis_id']} · {esc(h['title'])} &nbsp; {badge(v.get('status', '-'))}"
                        + (" &nbsp; <span class='badge' style='background:#0B1F3A;color:#fff'>LEADING</span>" if leading else ""),
                        unsafe_allow_html=True)
            st.markdown(f"<span class='small'>Suspected service(s): <b>{esc(', '.join(h['suspected_services']) or '-')}</b> · "
                        f"Fault: {esc(h.get('suspected_fault') or '-')} · Model confidence (not used): "
                        f"{esc(h.get('model_confidence'))}</span>", unsafe_allow_html=True)
            st.markdown(f"**Verifier decision:** {v.get('rationale', '-')}")
            st.write(h.get("explanation", ""))
            a, b = st.columns(2)
            with a:
                st.markdown("**Observed facts (as stated by the model)**")
                for f in h.get("observed_facts", []) or ["—"]:
                    st.markdown(f"- {f}")
            with b:
                st.markdown("**Inferences (interpretation)**")
                for f in h.get("inferences", []) or ["—"]:
                    st.markdown(f"- {f}")
            st.markdown("**Verification checks**")
            st.dataframe(pd.DataFrame(v.get("checks", [])), hide_index=True)
            a, b = st.columns(2)
            with a:
                st.markdown(f"**Supporting evidence verified ({v.get('support_count', 0)})**")
                if v.get("supporting"):
                    st.dataframe(pd.DataFrame(v["supporting"]), hide_index=True)
                else:
                    st.caption("None.")
                if v.get("not_counted"):
                    st.markdown("**Cited but not counted**")
                    st.dataframe(pd.DataFrame(v["not_counted"]), hide_index=True)
            with b:
                st.markdown(f"**Contradicting evidence ({v.get('contradiction_count', 0)})**")
                if v.get("contradictions"):
                    st.dataframe(pd.DataFrame(v["contradictions"]), hide_index=True)
                else:
                    st.caption("None found.")
                if v.get("missing_evidence"):
                    st.markdown("**Missing evidence**")
                    for m in v["missing_evidence"]:
                        st.markdown(f"- {m}")
            cited = h.get("supporting_evidence_ids", []) + h.get("contradicting_evidence_ids", [])
            with st.expander("Look up cited evidence"):
                st.dataframe(pd.DataFrame([{"evidence_id": c, **index.get(c, {"type": "NOT FOUND", "summary": "identifier does not exist"})}
                                           for c in cited]), hide_index=True)
    if analysis.get("recommended_next_steps"):
        st.markdown("**Recommended next investigative steps (model suggestions)**")
        for s in analysis["recommended_next_steps"]:
            st.markdown(f"- {s}")
    if analysis.get("limitations_and_missing_evidence"):
        st.markdown("**Limitations stated by the model**")
        for s in analysis["limitations_and_missing_evidence"]:
            st.markdown(f"- {s}")


def tab_report(result):
    report = result["report"]
    llm = result.get("llm") or {}
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("LLM status", llm.get("status", "-"))
    c2.metric("Investigation time", f"{result.get('duration_seconds', 0)} s")
    c3.metric("Tokens (in / out)", f"{llm['prompt_tokens']} / {llm['completion_tokens']}"
              if llm.get("prompt_tokens") is not None else "not reported")
    c4.metric("Estimated cost", f"${llm['estimated_cost_usd']:.4f}" if llm.get("estimated_cost_usd") is not None
              else "not configured")
    d1, d2, _ = st.columns([1, 1, 3])
    try:
        pdf = build_pdf(report)
        d1.download_button("Download report (PDF)", pdf, file_name=f"{result['investigation_id']}.pdf",
                           mime="application/pdf", type="primary")
    except Exception as exc:  # keep the page usable even if PDF rendering fails
        d1.error(f"PDF could not be generated: {exc}")
    d2.download_button("Download report (Markdown)", report["markdown"], file_name=f"{result['investigation_id']}.md",
                       mime="text/markdown")
    with st.container(border=True):
        st.markdown(report["markdown"])


def page_results():
    result = st.session_state.current_result
    if result is None:
        header("Investigation Results", "No investigation is open")
        st.info("Run a **New Investigation** or open one from **Investigation History**.")
        recent = database.list_investigations(SETTINGS.db_path, limit=20)
        if recent:
            choice = st.selectbox("Or open a recent investigation", [r["investigation_id"] for r in recent],
                                  format_func=lambda i: next(f"{i} – {r['title']}" for r in recent if r["investigation_id"] == i))
            st.button("Open", on_click=open_investigation, args=(choice,))
        return
    inc = result["incident"]
    header(f"{esc(inc['title'])}",
           f"{inc['incident_id']} · {result['investigation_id']} · {inc.get('application', '')} · "
           f"window {inc['start_time']} – {inc['end_time']} (UTC)")
    if inc.get("is_demo"):
        st.caption("Evidence: bundled synthetic demonstration dataset (fictional application, not real-world data).")
    render_stages(result)
    st.write("")
    conclusion_box(result)
    tabs = st.tabs(["Summary", "Detected Errors", "Correlated Evidence", "Hypotheses & Verification", "Final Report"])
    with tabs[0]:
        tab_summary(result)
    with tabs[1]:
        tab_errors(result)
    with tabs[2]:
        tab_correlation(result)
    with tabs[3]:
        tab_hypotheses(result)
    with tabs[4]:
        tab_report(result)


def page_history():
    header("Investigation History", "Previous investigations stored in the local SQLite database")
    rows = database.list_investigations(SETTINGS.db_path)
    if not rows:
        st.info("No investigations have been stored yet.")
        return
    df = pd.DataFrame(rows)
    df["is_demo"] = df["is_demo"].map(bool)
    st.dataframe(df[["investigation_id", "title", "application", "started_at", "status", "llm_status", "llm_model",
                     "error_count", "leading_hypothesis", "duration_seconds", "is_demo"]],
                 hide_index=True)
    c1, c2, c3 = st.columns([3, 1, 1])
    choice = c1.selectbox("Select an investigation", df["investigation_id"].tolist(),
                          format_func=lambda i: f"{i} – {df.loc[df.investigation_id == i, 'title'].iloc[0]}")
    c2.write("")
    c2.button("Open report", type="primary", on_click=open_investigation, args=(choice,))
    c3.write("")
    if c3.button("Delete"):
        database.delete_investigation(choice, SETTINGS.db_path)
        if (st.session_state.current_result or {}).get("investigation_id") == choice:
            st.session_state.current_result = None
        st.rerun()


{"Dashboard": page_dashboard, "New Investigation": page_new_investigation,
 "Investigation Results": page_results, "Investigation History": page_history}[st.session_state.page]()
