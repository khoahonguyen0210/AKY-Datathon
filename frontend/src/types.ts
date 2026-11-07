export type Severity = "low" | "medium" | "high";

export interface EventRecord {
  id: string;
  timestamp: string;
  host: string;
  source: string;
  event_type: string;
  user: string | null;
  src_ip: string | null;
  src_host: string | null;
  dest_ip: string | null;
  dest_host: string | null;
  result: string;
  detail: string;
  byte_count: number | null;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  summary: string;
  evidence_ids: string[];
  rule_ids: string[];
  entities: Record<string, string>;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "external_ip" | "user" | "host" | "share" | "external_dest";
  rank: number;
  lane: number;
  detail: string;
  flags: string[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  kind: string;
  evidence_ids: string[];
  denied: boolean;
}

export interface Conclusion {
  statement: string;
  evidence_ids: string[];
  kind: "observed" | "hypothesis";
}

export interface Recommendation {
  title: string;
  detail: string;
  evidence_ids: string[];
}

export interface WorkflowStep {
  id: string;
  name: string;
  detail: string;
  owner: string;
}

export interface Investigation {
  case: {
    id: string;
    title: string;
    subtitle: string;
    note: string;
    origin: "sample" | "upload";
  };
  events: EventRecord[];
  findings: Finding[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  workflow: WorkflowStep[];
  report: {
    title: string;
    summary: string;
    risk: Severity;
    risk_rationale: string;
    root_cause: string;
    conclusions: Conclusion[];
    recommendations: Recommendation[];
    rules_fired: string[];
    rules_silent: string[];
    reasoning_source: "grok" | "local-evidence-reasoner";
    reasoning_note: string;
    scope_note: string;
  };
  stats: {
    event_count: number;
    evidence_count: number;
    finding_count: number;
    host_count: number;
    edge_count: number;
  };
}

export type Selection =
  | { kind: "finding"; id: string }
  | { kind: "node"; id: string }
  | { kind: "edge"; id: string }
  | { kind: "event"; id: string };
