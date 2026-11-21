"""Investigation report generation (workflow step 7).

One structured report model is built from the investigation result and rendered
both as Markdown (shown in the app) and as a PDF (downloaded).
A SUPPORTED hypothesis is always presented as an *evidence-supported possible
root cause*, never as a confirmed diagnosis.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

STATUS_TEXT = {
    "SUPPORTED": "SUPPORTED - available evidence supports this hypothesis",
    "CONTRADICTED": "CONTRADICTED - available evidence contains relevant contradictions",
    "INSUFFICIENT EVIDENCE": "INSUFFICIENT EVIDENCE - the evidence cannot settle this hypothesis",
}
DISCLAIMER = ("AEGIS reports possible root causes. A hypothesis marked SUPPORTED passed automated evidence "
              "checks but is not a verified diagnosis; an engineer must confirm it before any corrective action.")
DEMO_NOTICE = ("Evidence notice: this investigation used the bundled synthetic demonstration dataset "
               "(fictional e-commerce application). It is not real-world measured data.")


def pattern_label(p: dict) -> str:
    """Error code when the pattern is a code, otherwise the original example message."""
    key = p.get("pattern", "")
    return f"{key}: {p['example_message']}" if key and " " not in key else p.get("example_message", key)


def _section(title, paragraphs=None, bullets=None, table=None):
    return {"title": title, "paragraphs": paragraphs or [], "bullets": bullets or [], "table": table}


def build_report(result: dict) -> dict:
    inc = result["incident"]
    det = result.get("detection", {})
    corr = result.get("correlation", {})
    llm = result.get("llm") or {}
    ver = result.get("verification")
    analysis = llm.get("analysis") or {}
    hyps = {h["hypothesis_id"]: h for h in analysis.get("hypotheses", [])}
    vres = {v["hypothesis_id"]: v for v in (ver or {}).get("results", [])}
    leading_id = (ver or {}).get("leading_hypothesis_id")
    sections = []

    # 1. identification
    sections.append(_section("1. Incident identification", table={
        "headers": ["Field", "Value"],
        "rows": [
            ["Incident ID", inc["incident_id"]],
            ["Investigation ID", result["investigation_id"]],
            ["Title", inc["title"]],
            ["Application", inc.get("application", "")],
            ["Incident window (UTC)", f"{inc['start_time']} to {inc['end_time']}"],
            ["Reported affected service", inc.get("affected_service") or "not specified"],
            ["Investigation started", result.get("started_at", "")],
            ["LLM", f"{llm.get('provider', '-')} / {llm.get('model', '-')} ({llm.get('status', '-')})"],
        ]}))

    # 2. description
    sections.append(_section("2. Incident description", paragraphs=[inc["description"]]))

    # 3. summary / conclusion
    paras = []
    if ver is not None and leading_id:
        h = hyps[leading_id]
        paras.append(f"Leading evidence-supported explanation ({leading_id}): {h['title']}. "
                     f"{vres[leading_id]['rationale']}")
        paras.append("Classification: POSSIBLE ROOT CAUSE (evidence-supported) - not a verified diagnosis.")
    elif ver is not None:
        paras.append("No candidate hypothesis was sufficiently supported by the available evidence. "
                     "No root cause can be stated; see the missing information and next steps below.")
    elif llm.get("status") in ("failed", "not_configured"):
        paras.append(f"The LLM investigation did not complete: {llm.get('error', 'unknown error')} "
                     "No hypotheses were generated. The rule-based detection and correlation results below are complete.")
    else:
        paras.append(llm.get("error") or "No LLM analysis was performed.")
    if analysis.get("incident_summary"):
        paras.append(f"Model-generated summary (unverified narrative): {analysis['incident_summary']}")
    paras.append(DISCLAIMER)
    sections.append(_section("3. Investigation summary", paragraphs=paras))

    # 4. error detection
    c = det.get("counts", {})
    rows = [[pattern_label(p), str(p["occurrences"]), ", ".join(p["services"]), p["first_seen"], p["last_seen"]]
            for p in det.get("patterns", [])]
    sections.append(_section(
        "4. Error detection results (rule-based)",
        paragraphs=[f"{c.get('flagged', 0)} of {det.get('total_log_records', 0)} log records were flagged by Python rules: "
                    f"{c.get('errors', 0)} ERROR, {c.get('warnings', 0)} WARN, {c.get('exceptions', 0)} with exceptions, "
                    f"{c.get('http_5xx', 0)} HTTP 5xx, {c.get('repeated', 0)} belonging to repeated patterns. "
                    f"First error: {det.get('first_error') or 'n/a'}; last error: {det.get('last_error') or 'n/a'}. "
                    f"Failed request ids: {', '.join(det.get('request_ids', [])) or 'none'}."],
        table={"headers": ["Error pattern", "Count", "Services", "First seen", "Last seen"], "rows": rows} if rows else None))

    # 5. affected services
    rows = [[a["service"], str(a["errors"]), str(a["warnings"]), a["first_seen"]] for a in det.get("affected_services", [])]
    sections.append(_section("5. Affected services", table={"headers": ["Service", "Errors", "Warnings", "First seen"], "rows": rows}
                             if rows else None, paragraphs=[] if rows else ["No service produced errors or warnings."]))

    # 6. timeline
    rows = [[t["timestamp"], t["type"], t["service"], t["event"][:90], t["evidence_id"]] for t in corr.get("timeline", [])]
    sections.append(_section("6. Timeline of events (observed evidence only)",
                             table={"headers": ["Time (UTC)", "Type", "Service", "Event", "Evidence"], "rows": rows} if rows else None,
                             paragraphs=[] if rows else ["No events to show."]))

    # 7. hypotheses
    if hyps:
        for hid, h in hyps.items():
            v = vres.get(hid, {})
            bullets = [f"Verification status: {STATUS_TEXT.get(v.get('status'), v.get('status', '-'))}",
                       f"Verifier rationale: {v.get('rationale', '-')}",
                       f"Model's self-reported confidence (not used for the decision): {h.get('model_confidence', 'unknown')}",
                       f"Suspected service(s): {', '.join(h.get('suspected_services', [])) or '-'}",
                       f"Suspected fault: {h.get('suspected_fault') or '-'}"]
            paras = [f"Explanation (model-generated): {h.get('explanation', '')}"]
            if h.get("observed_facts"):
                paras.append("Observed facts cited by the model: " + " | ".join(h["observed_facts"]))
            if h.get("inferences"):
                paras.append("Inferences (interpretation, not observation): " + " | ".join(h["inferences"]))
            sup = v.get("supporting", [])
            paras.append("Supporting evidence verified by AEGIS: " + (
                "; ".join(f"{s['evidence_id']} ({s['summary']}{', ' + s['note'] if s.get('note') else ''})" for s in sup)
                if sup else "none"))
            if v.get("not_counted"):
                paras.append("Cited but not counted as support: " + "; ".join(
                    f"{s['evidence_id']} - {s['reason']}" for s in v["not_counted"]))
            paras.append("Contradicting evidence: " + (
                "; ".join(f"{x['evidence_id']} ({x['source']}): {x['reason']}" for x in v.get("contradictions", []))
                or "none found"))
            if v.get("missing_evidence"):
                paras.append("Missing evidence: " + " ".join(v["missing_evidence"]))
            sections.append(_section(f"7.{hid[1:]} Hypothesis {hid}: {h['title']}", paragraphs=paras, bullets=bullets))
    else:
        sections.append(_section("7. Candidate root-cause hypotheses", paragraphs=["No hypotheses were generated."]))

    # 8. leading explanation
    if leading_id:
        h = hyps[leading_id]
        sections.append(_section("8. Leading supported explanation", paragraphs=[
            f"{leading_id} - {h['title']} ({', '.join(h.get('suspected_services', []))}). "
            f"Status: SUPPORTED by {vres[leading_id]['support_count']} verified record(s) across "
            f"{vres[leading_id]['support_types']} evidence type(s).",
            "This is a possible root cause backed by evidence, not a confirmed diagnosis."]))
    else:
        sections.append(_section("8. Leading supported explanation", paragraphs=[
            "None - no hypothesis reached SUPPORTED status. No root cause is claimed."]))

    # 9. missing information
    missing = list(result.get("evidence", {}).get("warnings", []))
    missing += corr.get("notes", [])
    missing += analysis.get("limitations_and_missing_evidence", [])
    for v in vres.values():
        missing += v.get("missing_evidence", [])
    sections.append(_section("9. Missing information and limitations", bullets=list(dict.fromkeys(missing)) or ["None recorded."]))

    # 10. next steps
    steps = [f"(model suggestion) {s}" for s in analysis.get("recommended_next_steps", [])]
    if leading_id:
        steps.append("(AEGIS) Confirm the leading hypothesis manually before any remediation; AEGIS does not change systems.")
    else:
        steps.append("(AEGIS) Collect the missing evidence listed above and re-run the investigation.")
    sections.append(_section("10. Recommended next investigative steps", bullets=steps))

    # 11. usage
    usage = [f"LLM status: {llm.get('status', '-')}", f"Attempts: {llm.get('attempts', 0)}",
             f"LLM duration: {llm.get('duration_seconds', 0)} s",
             f"Total investigation duration: {result.get('duration_seconds', '-')} s"]
    if llm.get("prompt_tokens") is not None:
        usage.append(f"Tokens: {llm['prompt_tokens']} input / {llm['completion_tokens']} output")
    else:
        usage.append("Token usage: not reported by the provider")
    usage.append(f"Estimated cost: ${llm['estimated_cost_usd']:.6f}" if llm.get("estimated_cost_usd") is not None
                 else "Estimated cost: not shown (no pricing configured)")
    sections.append(_section("11. Model usage", bullets=usage))

    notices = [DEMO_NOTICE] if inc.get("is_demo") else []
    report = {
        "title": f"AEGIS Incident Investigation Report - {inc['incident_id']}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "leading_hypothesis_id": leading_id,
        "notices": notices,
        "sections": sections,
    }
    report["markdown"] = to_markdown(report)
    return report


def to_markdown(report: dict) -> str:
    lines = [f"# {report['title']}", f"_Generated {report['generated_at']}_", ""]
    for n in report.get("notices", []):
        lines += [f"> {n}", ""]
    for s in report["sections"]:
        lines.append(f"## {s['title']}")
        for p in s["paragraphs"]:
            lines += [p, ""]
        for b in s["bullets"]:
            lines.append(f"- {b}")
        if s["bullets"]:
            lines.append("")
        t = s.get("table")
        if t and t["rows"]:
            lines.append("| " + " | ".join(t["headers"]) + " |")
            lines.append("|" + "---|" * len(t["headers"]))
            for r in t["rows"]:
                lines.append("| " + " | ".join(str(x).replace("|", "/") for x in r) + " |")
            lines.append("")
    return "\n".join(lines)


def build_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    navy = colors.HexColor("#0B1F3A")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], textColor=navy, fontSize=16, alignment=TA_LEFT, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=navy, fontSize=12, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5)
    note = ParagraphStyle("note", parent=body, textColor=colors.HexColor("#7A4B00"),
                          backColor=colors.HexColor("#FFF4DD"), borderPadding=4)

    def P(text, style=body):
        return Paragraph(escape(str(text)), style)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm, title=report["title"])
    width = A4[0] - 32 * mm
    story = [P(report["title"], h1), P(f"Generated {report['generated_at']}", small), Spacer(1, 4)]
    for n in report.get("notices", []):
        story += [P(n, note), Spacer(1, 6)]
    for s in report["sections"]:
        story.append(P(s["title"], h2))
        for b in s["bullets"]:
            story.append(P(f"• {b}"))
        for p in s["paragraphs"]:
            story.append(P(p))
            story.append(Spacer(1, 2))
        t = s.get("table")
        if t and t["rows"]:
            data = [[P(h, small) for h in t["headers"]]] + [[P(c, small) for c in r] for r in t["rows"]]
            ncol = len(t["headers"])
            col_w = [width * 0.3, width * 0.7] if ncol == 2 else [width / ncol] * ncol
            if ncol == 5 and t["headers"][0].startswith("Time"):
                col_w = [width * 0.18, width * 0.1, width * 0.15, width * 0.42, width * 0.15]
            tbl = Table(data, colWidths=col_w, repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE5F2")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C4D6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8FC")]),
            ]))
            story += [tbl, Spacer(1, 4)]

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#56667A"))
        canvas.drawString(16 * mm, 9 * mm, "AEGIS - Adaptive, Evidence-Grounded Intelligence System | possible root causes, not verified diagnoses")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {_doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
