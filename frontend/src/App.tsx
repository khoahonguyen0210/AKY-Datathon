import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, fetchHealth, investigateSample, uploadLogs } from "./api";
import { AttackGraph } from "./components/AttackGraph";
import { Evidence } from "./components/Evidence";
import { Findings } from "./components/Findings";
import { ReportView } from "./components/ReportView";
import { eventsFor, highlightFor, selectionTitle } from "./selection";
import type { Investigation, Selection } from "./types";

export function App() {
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [grokConfigured, setGrokConfigured] = useState<boolean | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchHealth()
      .then((health) => setGrokConfigured(health.grok_configured))
      .catch(() => setGrokConfigured(null));
  }, []);

  function adopt(next: Investigation) {
    setInvestigation(next);
    setSelection(next.findings[0] ? { kind: "finding", id: next.findings[0].id } : null);
    setShowAll(false);
    setError(null);
  }

  async function runSample(sampleId: string) {
    setLoading(true);
    setError(null);
    try {
      adopt(await investigateSample(sampleId));
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The investigation API is not responding.");
    } finally {
      setLoading(false);
    }
  }

  async function runFile(file: File) {
    setLoading(true);
    setError(null);
    try {
      adopt(await uploadLogs(file));
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The file could not be investigated.");
    } finally {
      setLoading(false);
    }
  }

  const highlight = useMemo(
    () => (investigation ? highlightFor(investigation, selection) : { nodes: [], edges: [] }),
    [investigation, selection],
  );
  const cited = useMemo(() => {
    const ids = new Set<string>();
    investigation?.findings.forEach((finding) => finding.evidence_ids.forEach((id) => ids.add(id)));
    return ids;
  }, [investigation]);
  const evidence = investigation ? eventsFor(investigation, selection) : [];
  const selectedNode =
    investigation && selection?.kind === "node"
      ? investigation.graph.nodes.find((node) => node.id === selection.id)
      : undefined;
  const selectedEdge =
    investigation && selection?.kind === "edge"
      ? investigation.graph.edges.find((edge) => edge.id === selection.id)
      : undefined;

  return (
    <div className="mx-auto min-h-screen max-w-[1440px] px-4 py-5 md:px-6">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-line pb-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-signal">Investigation workbench</p>
          <h1 className="font-serif text-4xl leading-none text-paper md:text-5xl">SENTINEL</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] text-mute" data-testid="reasoner">
            {grokConfigured ? "Grok API connected" : "Local evidence reasoner"}
          </span>
          <button
            type="button"
            className="rounded-full border border-line px-3 py-1.5 text-sm text-paper hover:border-mute disabled:opacity-50"
            disabled={loading}
            onClick={() => void runSample("benign")}
          >
            Quiet office day
          </button>
          <button
            type="button"
            data-testid="run-northwind"
            className="rounded-full bg-signal px-3 py-1.5 text-sm font-semibold text-ink disabled:opacity-50"
            disabled={loading}
            onClick={() => void runSample("northwind")}
          >
            {loading ? "Investigating…" : "Investigate Northwind"}
          </button>
          <button
            type="button"
            className="rounded-full border border-line px-3 py-1.5 text-sm text-paper hover:border-mute"
            onClick={() => inputRef.current?.click()}
          >
            Upload logs
          </button>
          <input
            ref={inputRef}
            data-testid="upload-input"
            className="hidden"
            type="file"
            accept=".json,.jsonl,.csv,.txt,application/json,text/csv,text/plain"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void runFile(file);
              event.target.value = "";
            }}
          />
        </div>
      </header>

      {error ? (
        <p className="mt-4 rounded-xl border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger" role="alert">
          {error}
        </p>
      ) : null}

      {!investigation ? (
        <Hero
          dragging={dragging}
          loading={loading}
          onRun={() => void runSample("northwind")}
          onUpload={() => inputRef.current?.click()}
          onDrag={setDragging}
          onFile={(file) => void runFile(file)}
        />
      ) : (
        <>
          <CaseBar investigation={investigation} />
          <Workflow investigation={investigation} />
          <div className="mt-4 grid items-stretch gap-4 lg:grid-cols-[300px_minmax(0,1fr)_320px]">
            <section className="h-[420px] overflow-hidden rounded-2xl border border-line bg-panel lg:h-[640px]">
              <Findings
                findings={investigation.findings}
                events={investigation.events}
                selectedId={selection?.kind === "finding" ? selection.id : null}
                onSelect={(id) => setSelection({ kind: "finding", id })}
              />
            </section>
            <section className="flex h-auto flex-col overflow-hidden rounded-2xl border border-line bg-panel lg:h-[640px]">
              <div className="relative min-h-[420px] flex-1">
                <AttackGraph
                  nodes={investigation.graph.nodes}
                  edges={investigation.graph.edges}
                  hotNodes={highlight.nodes}
                  hotEdges={highlight.edges}
                  onSelectNode={(id) => setSelection({ kind: "node", id })}
                  onSelectEdge={(id) => setSelection({ kind: "edge", id })}
                />
              </div>
              <Legend />
            </section>
            <section className="h-[420px] overflow-hidden rounded-2xl border border-line bg-panel lg:h-[640px]">
              <Evidence
                title={selectionTitle(investigation, selection)}
                detail={selectedNode?.detail ?? (selectedEdge?.denied ? "The logon in these events was denied." : undefined)}
                flags={selectedNode?.flags}
                events={evidence}
                selectedEventId={selection?.kind === "event" ? selection.id : null}
                onSelectEvent={(id) => setSelection({ kind: "event", id })}
              />
            </section>
          </div>
          <ReportView
            investigation={investigation}
            cited={cited}
            selectedEventId={selection?.kind === "event" ? selection.id : null}
            showAll={showAll}
            onToggleAll={() => setShowAll((value) => !value)}
            onSelectEvent={(id) => {
              setSelection({ kind: "event", id });
              document.getElementById(`event-${id}`)?.scrollIntoView({ block: "nearest" });
            }}
            onSelectFinding={(id) => setSelection({ kind: "finding", id })}
          />
        </>
      )}
    </div>
  );
}

function CaseBar({ investigation }: { investigation: Investigation }) {
  const { case: caseInfo, stats, report } = investigation;
  return (
    <div className="mt-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold">{caseInfo.title}</h2>
          <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-mute">
            {caseInfo.origin === "sample" ? "Fictional sample" : "Uploaded file"}
          </span>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-mute">
          {caseInfo.subtitle}. {caseInfo.note}
        </p>
      </div>
      <dl className="flex flex-wrap gap-4 font-mono text-[11px] text-mute">
        <Metric label="Events" value={String(stats.event_count)} />
        <Metric label="Cited" value={String(stats.evidence_count)} />
        <Metric label="Findings" value={String(stats.finding_count)} />
        <Metric label="Hosts" value={String(stats.host_count)} />
        <Metric label="Risk" value={report.risk} />
      </dl>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="uppercase tracking-[0.14em]">{label}</dt>
      <dd className="mt-1 text-sm text-paper">{value}</dd>
    </div>
  );
}

function Workflow({ investigation }: { investigation: Investigation }) {
  return (
    <ol className="mt-4 grid gap-2 sm:grid-cols-5" data-testid="workflow">
      {investigation.workflow.map((step, index) => (
        <li key={step.id} className="rounded-xl border border-line bg-panel px-3 py-2">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-signal">
            Grok Bot {index + 1}
          </p>
          <p className="mt-1 text-sm font-medium">{step.name}</p>
          <p className="mt-1 line-clamp-3 text-[11px] leading-4 text-mute">{step.detail}</p>
        </li>
      ))}
    </ol>
  );
}

function Legend() {
  const items = [
    ["bg-danger", "External address"],
    ["bg-sky", "Account"],
    ["bg-signal", "Host"],
    ["bg-paper", "Share"],
    ["bg-warn", "Transfer destination"],
  ];
  return (
    <div className="flex flex-wrap items-center gap-3 border-t border-line px-4 py-2">
      {items.map(([swatch, label]) => (
        <span key={label} className="flex items-center gap-1.5 font-mono text-[10px] text-mute">
          <span className={`h-2 w-2 rounded-full ${swatch}`} />
          {label}
        </span>
      ))}
      <span className="font-mono text-[10px] text-danger">Dashed line · denied logon</span>
    </div>
  );
}

function Hero({
  dragging,
  loading,
  onRun,
  onUpload,
  onDrag,
  onFile,
}: {
  dragging: boolean;
  loading: boolean;
  onRun: () => void;
  onUpload: () => void;
  onDrag: (active: boolean) => void;
  onFile: (file: File) => void;
}) {
  return (
    <section
      className={`mt-8 rounded-3xl border px-6 py-16 text-center md:px-16 ${dragging ? "border-signal bg-signal/5" : "border-line bg-panel/80"}`}
      onDragOver={(event) => {
        event.preventDefault();
        onDrag(true);
      }}
      onDragLeave={() => onDrag(false)}
      onDrop={(event) => {
        event.preventDefault();
        onDrag(false);
        const file = event.dataTransfer.files?.[0];
        if (file) onFile(file);
      }}
    >
      <p className="font-serif text-4xl leading-tight text-paper md:text-6xl">From raw logs to a path you can defend.</p>
      <p className="mx-auto mt-5 max-w-2xl text-sm leading-6 text-mute md:text-base">
        SENTINEL reads a log file, keeps the events that match its rules, and draws how those events connect.
        Northwind Logistics is a fictional overnight case: repeated VPN failures, a group change, movement between machines, and a large outbound transfer.
        Every finding cites the log line it came from.
      </p>
      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        <button
          type="button"
          className="rounded-full bg-signal px-5 py-2.5 text-sm font-semibold text-ink disabled:opacity-50"
          disabled={loading}
          onClick={onRun}
        >
          {loading ? "Investigating…" : "Investigate Northwind"}
        </button>
        <button type="button" className="rounded-full border border-line px-5 py-2.5 text-sm text-paper" onClick={onUpload}>
          Upload logs
        </button>
        <a className="text-sm text-signal hover:underline" href="/api/samples/northwind/logs">
          Download the sample
        </a>
      </div>
      <p className="mt-6 font-mono text-[11px] text-mute">JSONL, a JSON array, or CSV · timestamp, host, event_type · 2 MB max</p>
    </section>
  );
}
