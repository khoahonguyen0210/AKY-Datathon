import type { EventRecord, Investigation, Selection } from "./types";

export function highlightFor(
  investigation: Investigation,
  selection: Selection | null,
): { nodes: string[]; edges: string[] } {
  if (!selection) return { nodes: [], edges: [] };
  const { edges } = investigation.graph;
  if (selection.kind === "finding") {
    const finding = investigation.findings.find((item) => item.id === selection.id);
    const ids = new Set(finding?.evidence_ids ?? []);
    const matched = edges.filter((edge) => edge.evidence_ids.some((id) => ids.has(id)));
    return { nodes: endpoints(matched), edges: matched.map((edge) => edge.id) };
  }
  if (selection.kind === "edge") {
    const edge = edges.find((item) => item.id === selection.id);
    if (!edge) return { nodes: [], edges: [] };
    return { nodes: [edge.source, edge.target], edges: [edge.id] };
  }
  if (selection.kind === "node") {
    const matched = edges.filter((edge) => edge.source === selection.id || edge.target === selection.id);
    return { nodes: [...new Set([selection.id, ...endpoints(matched)])], edges: matched.map((edge) => edge.id) };
  }
  const matched = edges.filter((edge) => edge.evidence_ids.includes(selection.id));
  return { nodes: endpoints(matched), edges: matched.map((edge) => edge.id) };
}

export function eventsFor(investigation: Investigation, selection: Selection | null): EventRecord[] {
  const byId = new Map(investigation.events.map((event) => [event.id, event]));
  const ids = evidenceIds(investigation, selection);
  return ids
    .map((id) => byId.get(id))
    .filter((event): event is EventRecord => Boolean(event))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp) || a.id.localeCompare(b.id));
}

export function selectionTitle(investigation: Investigation, selection: Selection | null): string {
  if (!selection) return "Evidence";
  if (selection.kind === "finding") {
    return investigation.findings.find((item) => item.id === selection.id)?.title ?? "Finding";
  }
  if (selection.kind === "node") {
    return investigation.graph.nodes.find((item) => item.id === selection.id)?.label ?? "Node";
  }
  if (selection.kind === "edge") {
    return investigation.graph.edges.find((item) => item.id === selection.id)?.label ?? "Path";
  }
  return selection.id;
}

function evidenceIds(investigation: Investigation, selection: Selection | null): string[] {
  if (!selection) return [];
  if (selection.kind === "finding") {
    return investigation.findings.find((item) => item.id === selection.id)?.evidence_ids ?? [];
  }
  if (selection.kind === "edge") {
    return investigation.graph.edges.find((item) => item.id === selection.id)?.evidence_ids ?? [];
  }
  if (selection.kind === "event") return [selection.id];
  const ids = new Set<string>();
  for (const edge of investigation.graph.edges) {
    if (edge.source === selection.id || edge.target === selection.id) {
      edge.evidence_ids.forEach((id) => ids.add(id));
    }
  }
  return [...ids];
}

function endpoints(edges: { source: string; target: string }[]): string[] {
  const nodes = new Set<string>();
  for (const edge of edges) {
    nodes.add(edge.source);
    nodes.add(edge.target);
  }
  return [...nodes];
}
