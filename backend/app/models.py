"""Shared records for an investigation.

Every finding cites event ids. The report ledger is built from those
citations, so a sentence in the ledger always points at a parsed event.
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

SCOPE_NOTE = (
    "This report does not validate vulnerabilities by exploiting them. "
    "Observed statements restate parsed events. Hypotheses are labeled and stay inside what those events can support."
)

Severity = Literal["low", "medium", "high"]
Origin = Literal["sample", "upload"]
ConclusionKind = Literal["observed", "hypothesis"]
ReasoningSource = Literal["grok", "local-evidence-reasoner"]
NodeKind = Literal["external_ip", "user", "host", "share", "external_dest"]


class Event(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    timestamp: datetime
    host: str
    source: str = "unknown"
    event_type: str
    user: str | None = None
    src_ip: str | None = None
    src_host: str | None = None
    dest_ip: str | None = None
    dest_host: str | None = None
    result: str = "success"
    detail: str = ""
    byte_count: int | None = None

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    summary: str
    evidence_ids: list[str]
    rule_ids: list[str] = Field(default_factory=list)
    entities: dict[str, str] = Field(default_factory=dict)


class GraphNode(BaseModel):
    id: str
    label: str
    kind: NodeKind
    rank: int = 0
    lane: int = 0
    detail: str = ""
    flags: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    kind: str
    evidence_ids: list[str]
    denied: bool = False


class Graph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Conclusion(BaseModel):
    statement: str
    evidence_ids: list[str]
    kind: ConclusionKind


class Recommendation(BaseModel):
    title: str
    detail: str
    evidence_ids: list[str]


class WorkflowStep(BaseModel):
    id: str
    name: str
    detail: str
    owner: str = "grok-bot"


class CaseInfo(BaseModel):
    id: str
    title: str
    subtitle: str
    note: str
    origin: Origin


class Report(BaseModel):
    title: str
    summary: str
    risk: Severity
    risk_rationale: str
    root_cause: str
    conclusions: list[Conclusion]
    recommendations: list[Recommendation]
    rules_fired: list[str]
    rules_silent: list[str]
    reasoning_source: ReasoningSource
    reasoning_note: str
    scope_note: str = SCOPE_NOTE


class Stats(BaseModel):
    event_count: int
    evidence_count: int
    finding_count: int
    host_count: int
    edge_count: int


class Investigation(BaseModel):
    case: CaseInfo
    events: list[Event]
    findings: list[Finding]
    graph: Graph
    workflow: list[WorkflowStep]
    report: Report
    stats: Stats


class SampleSummary(BaseModel):
    id: str
    title: str
    subtitle: str
    note: str
    event_count: int
