"""Python-based evidence verification of LLM hypotheses (workflow step 6).

The LLM never validates its own hypotheses. For each hypothesis this module:
    1. checks every cited evidence id exists and was actually shown to the model
    2. checks the cited records concern the suspected services
    3. checks the cited records fall inside the relevant incident period
    4. collects records that genuinely support the hypothesis
    5. runs its own contradiction checks (healthy metrics/logs, cause after effect)
    6. lists missing evidence
and assigns SUPPORTED / CONTRADICTED / INSUFFICIENT EVIDENCE.
The model's own confidence label is displayed but never used in the decision.
"""
from __future__ import annotations

import pandas as pd

from .evidence_loader import EvidenceBundle
from .incident_manager import Incident, iso

SUPPORTED = "SUPPORTED"
CONTRADICTED = "CONTRADICTED"
INSUFFICIENT = "INSUFFICIENT EVIDENCE"

TYPE_GROUP = {"log": "logs", "metric": "metrics", "trace": "traces", "span": "traces", "change": "changes"}


def _record_services(eid: str, entry: dict, registry: dict) -> set[str]:
    services = set(entry.get("services", []))
    if entry["type"] == "span":  # a span is relevant if its whole trace touches the service
        parent = registry.get(eid.split("/")[0])
        if parent:
            services |= set(parent.get("services", []))
    return services


def _time_ok(entry: dict, incident: Incident, context_minutes: int, lookback_minutes: int) -> tuple[bool | None, str]:
    ts = entry.get("timestamp")
    if ts is None or pd.isna(ts):
        return None, "record has no timestamp"
    if entry["type"] == "change":
        lo = incident.start_time - pd.Timedelta(minutes=lookback_minutes)
        hi = incident.end_time
    else:
        lo = incident.start_time - pd.Timedelta(minutes=context_minutes)
        hi = incident.end_time + pd.Timedelta(minutes=context_minutes)
    if lo <= ts <= hi:
        return True, iso(ts)
    return False, f"{iso(ts)} is outside {iso(lo)} – {iso(hi)}"


def verify_hypothesis(hyp: dict, registry: dict, shown_ids: set[str], incident: Incident,
                      bundle: EvidenceBundle, first_error: pd.Timestamp | None,
                      metric_anomalies: dict[str, list[str]], context_minutes: int,
                      lookback_minutes: int) -> dict:
    services = {s.lower() for s in hyp.get("suspected_services", []) if s}
    known_services = set(bundle.logs["service"]) | set(bundle.metrics["service"]) | set(bundle.changes["service"])
    if not bundle.spans.empty:
        known_services |= set(bundle.spans["service"])

    checks: list[dict] = []
    supporting: list[dict] = []
    not_counted: list[dict] = []
    invalid_ids: list[str] = []
    not_shown_ids: list[str] = []
    contradictions: list[dict] = []
    missing: list[str] = []

    # ---- 1. existence of cited ids (supporting + contradicting)
    cited_support = list(dict.fromkeys(hyp.get("supporting_evidence_ids", [])))
    cited_contra = list(dict.fromkeys(hyp.get("contradicting_evidence_ids", [])))
    for eid in cited_support + cited_contra:
        if eid not in registry:
            invalid_ids.append(eid)
        elif eid not in shown_ids:
            not_shown_ids.append(eid)
    valid_support = [e for e in cited_support if e in registry and e in shown_ids]
    checks.append({
        "check": "Cited evidence identifiers exist",
        "result": "pass" if not invalid_ids and not not_shown_ids and cited_support else ("fail" if not valid_support else "warn"),
        "detail": (f"{len(valid_support)} of {len(cited_support)} supporting ids are valid"
                   + (f"; unknown ids: {', '.join(invalid_ids)}" if invalid_ids else "")
                   + (f"; ids not provided to the model: {', '.join(not_shown_ids)}" if not_shown_ids else "")),
    })

    # ---- 2. suspected services are named and exist in the evidence
    unknown_services = sorted(services - known_services)
    if not services:
        checks.append({"check": "Suspected service matches evidence", "result": "fail",
                       "detail": "The hypothesis does not name a suspected service."})
    else:
        checks.append({
            "check": "Suspected service matches evidence",
            "result": "pass" if not unknown_services else ("warn" if services - set(unknown_services) else "fail"),
            "detail": ("Services found in evidence: " + ", ".join(sorted(services - set(unknown_services)) or ["none"])
                       + (f"; not present in any evidence: {', '.join(unknown_services)}" if unknown_services else "")),
        })

    # ---- 3 & 4. per-record relevance, timing and abnormality
    service_mismatch = time_fail = 0
    for eid in valid_support:
        entry = registry[eid]
        rec_services = _record_services(eid, entry, registry)
        relevant = bool(services & rec_services)
        t_ok, t_detail = _time_ok(entry, incident, context_minutes, lookback_minutes)
        reason = None
        if not relevant:
            service_mismatch += 1
            reason = f"concerns {', '.join(sorted(rec_services))}, not the suspected service"
        elif t_ok is False:
            time_fail += 1
            reason = f"timestamp {t_detail}"
        elif t_ok is None:
            reason = "no timestamp, timing cannot be verified"
        elif entry["type"] == "change" and first_error is not None and entry["timestamp"] > first_error:
            reason = "change happened after the first error, so it cannot explain its onset"
        elif not entry.get("abnormal"):
            reason = "record shows normal behaviour"
        item = {"evidence_id": eid, "type": entry["type"], "summary": entry["summary"]}
        if reason:
            not_counted.append({**item, "reason": reason})
        else:
            if entry["type"] == "change" and first_error is not None:
                mins = (first_error - entry["timestamp"]).total_seconds() / 60
                item["note"] = f"precedes first error by {mins:.1f} min"
            supporting.append(item)
    checks.append({
        "check": "Cited records concern the suspected service",
        "result": "pass" if valid_support and service_mismatch == 0 else ("warn" if service_mismatch < len(valid_support) else "fail"),
        "detail": f"{len(valid_support) - service_mismatch} of {len(valid_support)} valid cited records match",
    })
    checks.append({
        "check": "Timestamps within incident period",
        "result": "pass" if valid_support and time_fail == 0 else ("warn" if time_fail < len(valid_support) else "fail"),
        "detail": (f"Incident {iso(incident.start_time)} – {iso(incident.end_time)} "
                   f"(±{context_minutes} min context, changes up to {lookback_minutes} min before); "
                   f"{time_fail} record(s) outside"),
    })

    # ---- 5a. contradictions cited by the model (validated, inside the context window)
    for eid in cited_contra:
        if eid not in registry or eid not in shown_ids:
            continue
        entry = registry[eid]
        t_ok, _ = _time_ok(entry, incident, context_minutes, lookback_minutes)
        if t_ok:
            contradictions.append({"evidence_id": eid, "source": "cited by LLM", "summary": entry["summary"],
                                   "reason": "the model itself identified this record as weakening the hypothesis"})

    # ---- 5b. independent contradiction checks
    in_window = lambda ts: ts is not None and not pd.isna(ts) and incident.start_time <= ts <= incident.end_time  # noqa: E731
    for svc in sorted(services):
        m = (bundle.metrics[(bundle.metrics["service"] == svc) & bundle.metrics["timestamp"].map(in_window).astype(bool)]
             if not bundle.metrics.empty else bundle.metrics)
        if not m.empty:
            healthy = [eid for eid in m["evidence_id"] if not metric_anomalies.get(eid)]
            if len(healthy) == len(m):
                contradictions.append({
                    "evidence_id": ", ".join(healthy), "source": "AEGIS check",
                    "summary": f"{svc} metrics during the incident",
                    "reason": f"all {len(m)} metric sample(s) for {svc} during the incident are within normal range"})
        lg = (bundle.logs[(bundle.logs["service"] == svc) & bundle.logs["timestamp"].map(in_window).astype(bool)]
              if not bundle.logs.empty else bundle.logs)
        if not lg.empty:
            flagged = [eid for eid in lg["evidence_id"] if registry.get(eid, {}).get("abnormal")]
            if not flagged:
                contradictions.append({
                    "evidence_id": ", ".join(lg["evidence_id"].head(3)), "source": "AEGIS check",
                    "summary": f"{svc} log activity during the incident",
                    "reason": f"{svc} logged only successful activity during the incident ({len(lg)} record(s), no errors or warnings)"})
    cited_changes = [e for e in valid_support if registry[e]["type"] == "change"
                     and services & set(registry[e]["services"])]
    if cited_changes and first_error is not None and all(registry[e]["timestamp"] > first_error for e in cited_changes):
        contradictions.append({"evidence_id": ", ".join(cited_changes), "source": "AEGIS check",
                               "summary": "change timing", "reason": "every cited change occurred after the first error"})

    # ---- 6. missing evidence
    for modality in bundle.missing_modalities:
        missing.append(f"No {modality} were provided for this incident.")
    for svc in sorted(services - set(unknown_services)):
        if not bundle.metrics.empty and bundle.metrics[bundle.metrics["service"] == svc].empty:
            missing.append(f"No metrics available for {svc}.")
        if not bundle.spans.empty and bundle.spans[bundle.spans["service"] == svc].empty:
            missing.append(f"No trace spans recorded for {svc}.")
    if invalid_ids:
        missing.append("The model cited identifiers that do not exist in the evidence: " + ", ".join(invalid_ids) + ".")
    if not_shown_ids:
        missing.append("The model cited records it was not given: " + ", ".join(not_shown_ids) + ".")

    # ---- decision
    support_count = len(supporting)
    support_types = len({TYPE_GROUP[s["type"]] for s in supporting})
    contra_count = len(contradictions)
    checks.append({"check": "Supporting evidence found", "result": "pass" if support_types >= 2 else ("warn" if support_count else "fail"),
                   "detail": f"{support_count} record(s) across {support_types} evidence type(s)"})
    checks.append({"check": "Contradicting evidence", "result": "pass" if contra_count == 0 else "fail",
                   "detail": f"{contra_count} contradiction(s) found"})

    if not services:
        status, rationale = INSUFFICIENT, "No suspected service was named, so the hypothesis cannot be checked."
    elif support_count == 0 and contra_count > 0:
        status, rationale = CONTRADICTED, "No cited record supports the hypothesis and the evidence contradicts it."
    elif support_count == 0:
        status, rationale = INSUFFICIENT, "None of the cited records could be verified as supporting evidence."
    elif contra_count > 0 and (support_count <= contra_count or support_types < 2):
        status, rationale = CONTRADICTED, (f"Contradicting evidence ({contra_count}) outweighs the verified support "
                                           f"({support_count} record(s), {support_types} evidence type(s)).")
    elif support_types >= 2 and support_count >= 3 and support_count >= 3 * contra_count:
        if invalid_ids and len(invalid_ids) >= len(valid_support):
            status, rationale = INSUFFICIENT, "Too many cited identifiers do not exist; the citation set is unreliable."
        else:
            status = SUPPORTED
            rationale = (f"{support_count} verified record(s) from {support_types} independent evidence types support "
                         f"the hypothesis" + (f"; {contra_count} weaker contradiction(s) noted." if contra_count else
                                              " and no contradiction was found."))
    else:
        status, rationale = INSUFFICIENT, (f"Verified support is limited ({support_count} record(s), {support_types} "
                                           f"evidence type(s)) or mixed with {contra_count} contradiction(s).")

    return {
        "hypothesis_id": hyp.get("hypothesis_id", ""),
        "title": hyp.get("title", ""),
        "status": status,
        "rationale": rationale,
        "model_confidence": hyp.get("model_confidence", "unknown"),
        "support_count": support_count,
        "support_types": support_types,
        "contradiction_count": contra_count,
        "supporting": supporting,
        "not_counted": not_counted,
        "contradictions": contradictions,
        "invalid_ids": invalid_ids,
        "not_shown_ids": not_shown_ids,
        "missing_evidence": list(dict.fromkeys(missing)),
        "checks": checks,
        "score": support_count + support_types - 2 * contra_count,
    }


def verify_all(analysis: dict, registry: dict, shown_ids: list[str], incident: Incident, bundle: EvidenceBundle,
               first_error, metric_anomalies: dict, context_minutes: int, lookback_minutes: int) -> dict:
    shown = set(shown_ids)
    results = [verify_hypothesis(h, registry, shown, incident, bundle, first_error, metric_anomalies,
                                 context_minutes, lookback_minutes)
               for h in analysis.get("hypotheses", [])]
    supported = [r for r in results if r["status"] == SUPPORTED]
    leading = max(supported, key=lambda r: r["score"])["hypothesis_id"] if supported else None
    return {"results": results, "leading_hypothesis_id": leading,
            "status_counts": {s: sum(r["status"] == s for r in results) for s in (SUPPORTED, CONTRADICTED, INSUFFICIENT)}}
