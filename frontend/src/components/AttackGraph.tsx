import cytoscape, { type Core } from "cytoscape";
import { useEffect, useRef } from "react";
import type { GraphEdge, GraphNode } from "../types";

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
  hotNodes: string[];
  hotEdges: string[];
  onSelectNode: (id: string) => void;
  onSelectEdge: (id: string) => void;
}

function shortEdgeLabel(edge: GraphEdge): string {
  if (edge.denied) return "Denied";
  const labels: Record<string, string> = {
    auth: "Authenticated",
    session: edge.label.toLowerCase().includes("vpn") ? "VPN" : "Session",
    privilege: edge.label.replace("Added to ", ""),
    lateral: "Logon",
    access: "Finance",
    transfer: "Transfer",
    account: "Second account",
  };
  return labels[edge.kind] ?? edge.label;
}

export function AttackGraph({ nodes, edges, hotNodes, hotEdges, onSelectNode, onSelectEdge }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const handlers = useRef({ onSelectNode, onSelectEdge });
  handlers.current = { onSelectNode, onSelectEdge };

  useEffect(() => {
    const container = containerRef.current;
    if (!container || nodes.length === 0) return;
    container.style.height = "560px";
    container.style.width = "100%";
    let alive = true;
    const cy = cytoscape({
      container,
      elements: [
        ...nodes.map((node) => ({
          data: {
            id: node.id,
            label: node.label,
            kind: node.kind,
          },
          position: { x: 80 + node.rank * 190, y: 70 + node.lane * 170 },
        })),
        ...edges.map((edge) => ({
          data: {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            label: shortEdgeLabel(edge),
            denied: edge.denied ? "yes" : "no",
          },
        })),
      ],
      layout: { name: "preset" },
      minZoom: 0.35,
      maxZoom: 2,
      boxSelectionEnabled: false,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "background-color": "#24302a",
            color: "#e7f0ea",
            "font-family": "IBM Plex Mono, ui-monospace, monospace",
            "font-size": 11,
            "text-wrap": "wrap",
            "text-max-width": "120px",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 8,
            "text-background-color": "#101410",
            "text-background-opacity": 0.88,
            "text-background-padding": "3px",
            "text-background-shape": "roundrectangle",
            width: 22,
            height: 22,
            "border-width": 0,
          },
        },
        { selector: 'node[kind = "external_ip"]', style: { "background-color": "#ff5d4a", width: 18, height: 18 } },
        { selector: 'node[kind = "external_dest"]', style: { "background-color": "#ffb020", width: 18, height: 18 } },
        { selector: 'node[kind = "user"]', style: { "background-color": "#8fd0ff", shape: "ellipse" } },
        { selector: 'node[kind = "host"]', style: { "background-color": "#d6ff4a", width: 26, height: 26 } },
        { selector: 'node[kind = "share"]', style: { "background-color": "#e7f0ea", shape: "round-rectangle" } },
        {
          selector: "edge",
          style: {
            width: 1.6,
            "line-color": "#8ea498",
            "target-arrow-color": "#8ea498",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "control-point-step-size": 70,
            label: "data(label)",
            color: "#d5e6db",
            "font-family": "IBM Plex Mono, ui-monospace, monospace",
            "font-size": 9,
            "text-background-color": "#101410",
            "text-background-opacity": 0.9,
            "text-background-padding": "2px",
            "text-rotation": "autorotate",
          },
        },
        {
          selector: 'edge[denied = "yes"]',
          style: {
            "line-style": "dashed",
            "line-color": "#ff5d4a",
            "target-arrow-color": "#ff5d4a",
            color: "#ffb1a8",
          },
        },
        {
          selector: ".hot",
          style: {
            "line-color": "#d6ff4a",
            "target-arrow-color": "#d6ff4a",
            width: 2.6,
            "border-width": 3,
            "border-color": "#d6ff4a",
            opacity: 1,
          },
        },
        { selector: ".dim", style: { opacity: 0.5 } },
      ],
    });
    const fit = () => {
      if (!alive || cy.destroyed()) return;
      cy.resize();
      cy.fit(undefined, 28);
    };
    fit();
    requestAnimationFrame(fit);
    cy.on("tap", "node", (event) => {
      handlers.current.onSelectNode(event.target.id());
    });
    cy.on("tap", "edge", (event) => {
      handlers.current.onSelectEdge(event.target.id());
    });
    cyRef.current = cy;
    const observer = new ResizeObserver(() => {
      if (!cy.destroyed()) cy.resize();
    });
    observer.observe(container);
    void document.fonts?.ready.then(() => {
      if (alive && !cy.destroyed()) fit();
    });
    return () => {
      alive = false;
      observer.disconnect();
      cy.destroy();
      container.style.height = "560px";
      cyRef.current = null;
    };
  }, [nodes, edges]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("hot dim");
    if (hotNodes.length === 0 && hotEdges.length === 0) return;
    cy.elements().addClass("dim");
    for (const id of hotNodes) cy.getElementById(id).removeClass("dim").addClass("hot");
    for (const id of hotEdges) cy.getElementById(id).removeClass("dim").addClass("hot");
  }, [nodes, edges, hotNodes, hotEdges]);

  if (nodes.length === 0) {
    return (
      <div className="flex h-[560px] items-center justify-center px-8 text-center" data-testid="attack-graph">
        <p className="max-w-sm text-sm leading-6 text-mute">
          No attack path. None of the detection rules fired, so there is nothing to connect.
        </p>
      </div>
    );
  }

  return (
    <div className="relative h-[560px] w-full" data-testid="attack-graph">
      <div ref={containerRef} className="cy-panel h-[560px] w-full" />
      <button
        type="button"
        className="absolute right-3 top-3 rounded-full border border-line bg-ink/80 px-3 py-1 font-mono text-[11px] text-mute hover:text-paper"
        onClick={() => cyRef.current?.fit(undefined, 36)}
      >
        Fit
      </button>
    </div>
  );
}
