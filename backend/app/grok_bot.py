"""Grok Bot investigation workflow.

Five fixed steps — ingest, detect, correlate, reason, report — turn a
log file into an evidence-backed case. The reason step calls Grok when
XAI_API_KEY is set and otherwise keeps the local summary. The ledger,
graph, and recommendations always come from the rules.
"""

import logging

from app import grok_client
from app.detect import detect
from app.graph import build_graph
from app.models import CaseInfo, Event, Investigation, Stats, WorkflowStep
from app.report import build_report, local_summary
from app.samples import load_sample

logger = logging.getLogger("sentinel.grok_bot")

LOCAL_NOTE = (
    "Grok Bot used the local evidence reasoner. Set XAI_API_KEY on the API process "
    "to have Grok rewrite the summary. The evidence ledger is produced by the rules either way."
)
GROK_NOTE = (
    "Grok rewrote the summary from the rule output. The evidence ledger was not written by the model, "
    "and the draft was kept only because every event id in it belongs to this file."
)
DISCARD_NOTE = (
    "Grok Bot called Grok, discarded the draft, and kept the local summary. "
    "Drafts are discarded when the call fails, when they cite events that are not in the file, "
    "or when they include attack procedure."
)


def investigate_sample(sample_id: str, *, allow_grok: bool = True) -> Investigation:
    case, events = load_sample(sample_id)
    return investigate(events, case, allow_grok=allow_grok)


def investigate(events: list[Event], case: CaseInfo, *, allow_grok: bool = True) -> Investigation:
    findings = detect(events)
    graph = build_graph(events, findings)
    allowed_ids = {event_id for finding in findings for event_id in finding.evidence_ids}
    summary = local_summary(events, findings)
    source = "local-evidence-reasoner"
    note = LOCAL_NOTE
    if allow_grok and findings:
        try:
            summary = grok_client.rewrite_summary(summary, allowed_ids)
            source = "grok"
            note = GROK_NOTE
        except grok_client.GrokUnavailable:
            logger.info("Grok rewrite skipped because XAI_API_KEY is unset")
        except grok_client.GrokError:
            logger.info("Grok rewrite discarded")
            note = DISCARD_NOTE

    report = build_report(
        events,
        findings,
        title=f"Incident report: {case.title}",
        summary=summary,
        reasoning_source=source,
        reasoning_note=note,
    )
    evidence_count = len(allowed_ids)
    workflow = [
        WorkflowStep(
            id="ingest",
            name="Ingest",
            detail=f"Parsed {len(events)} events from {case.title}.",
        ),
        WorkflowStep(
            id="detect",
            name="Detect",
            detail=(
                f"{len(findings)} findings. {evidence_count} events are cited as evidence. "
                "Rules cover repeated authentication failures, off-hours external success, "
                "privileged group changes, new services on hosts already on the path, "
                "network logons from those hosts, sensitive share names, and transfers over 100 MB."
            ),
        ),
        WorkflowStep(
            id="correlate",
            name="Correlate",
            detail=f"Built an attack graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges. Every edge cites at least one event.",
        ),
        WorkflowStep(
            id="reason",
            name="Reason",
            detail=note,
        ),
        WorkflowStep(
            id="report",
            name="Report",
            detail=(
                f"Risk {report.risk}. "
                f"{sum(1 for item in report.conclusions if item.kind == 'observed')} observed conclusions, "
                f"{sum(1 for item in report.conclusions if item.kind == 'hypothesis')} hypotheses, "
                f"{len(report.recommendations)} defensive actions."
            ),
        ),
    ]
    return Investigation(
        case=case,
        events=events,
        findings=findings,
        graph=graph,
        workflow=workflow,
        report=report,
        stats=Stats(
            event_count=len(events),
            evidence_count=evidence_count,
            finding_count=len(findings),
            host_count=sum(1 for node in graph.nodes if node.kind == "host"),
            edge_count=len(graph.edges),
        ),
    )
