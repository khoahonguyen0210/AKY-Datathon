import { categoryLabel, formatTime, severityClass, toMarkdown } from "../format";
import type { EventRecord, Investigation } from "../types";

interface Props {
  investigation: Investigation;
  cited: Set<string>;
  selectedEventId: string | null;
  showAll: boolean;
  onToggleAll: () => void;
  onSelectEvent: (id: string) => void;
  onSelectFinding: (id: string) => void;
}

export function ReportView({
  investigation,
  cited,
  selectedEventId,
  showAll,
  onToggleAll,
  onSelectEvent,
  onSelectFinding,
}: Props) {
  const { report } = investigation;
  const visible = showAll ? investigation.events : investigation.events.filter((event) => cited.has(event.id));
  return (
    <section className="mt-4 space-y-4" data-testid="report">
      <div className="rounded-2xl border border-line bg-panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">Incident report</p>
            <h2 className="mt-1 font-serif text-3xl text-paper">{report.title}</h2>
          </div>
          <div className="flex items-center gap-2">
            <span className={`rounded-full px-3 py-1 font-mono text-xs uppercase ${severityClass(report.risk)}`} data-testid="risk">
              Risk {report.risk}
            </span>
            <button
              type="button"
              className="rounded-full border border-line px-3 py-1 text-sm text-paper hover:border-signal"
              onClick={() => download(investigation)}
            >
              Download
            </button>
          </div>
        </div>
        <p className="mt-4 max-w-4xl text-sm leading-6 text-paper">{report.summary}</p>
        <p className="mt-3 max-w-4xl text-sm leading-6 text-mute">{report.root_cause}</p>
        <p className="mt-3 max-w-4xl text-xs leading-5 text-mute">{report.reasoning_note}</p>
        <div className="mt-4 flex flex-wrap gap-1.5">
          {report.rules_fired.map((rule) => (
            <span key={rule} className="rounded-full bg-signal/10 px-2 py-1 font-mono text-[10px] text-signal">
              {rule}
            </span>
          ))}
          {report.rules_silent.map((rule) => (
            <span key={rule} className="rounded-full bg-ink px-2 py-1 font-mono text-[10px] text-mute">
              {rule} silent
            </span>
          ))}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-line bg-panel p-5">
          <h3 className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">Evidence ledger</h3>
          <p className="mt-2 text-xs leading-5 text-mute">
            Observed rows restate parsed events. Hypotheses are inferences and stay attached to the same ids.
          </p>
          <ol className="mt-4 space-y-4">
            {report.conclusions.map((item, index) => (
              <li key={`${item.kind}-${index}`} className="border-t border-line pt-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`rounded-full px-2 py-0.5 font-mono text-[10px] uppercase ${
                      item.kind === "observed" ? "bg-ok/15 text-ok" : "bg-warn/15 text-warn"
                    }`}
                  >
                    {item.kind}
                  </span>
                  {item.evidence_ids.map((id) => (
                    <button
                      key={id}
                      type="button"
                      className="font-mono text-[11px] text-signal hover:underline"
                      onClick={() => onSelectEvent(id)}
                    >
                      {id}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-sm leading-6">{item.statement}</p>
              </li>
            ))}
            {report.conclusions.length === 0 ? (
              <li className="text-sm leading-6 text-mute">The ledger is empty because no rule fired.</li>
            ) : null}
          </ol>
        </div>
        <div className="rounded-2xl border border-line bg-panel p-5">
          <h3 className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">What to do next</h3>
          <ol className="mt-4 space-y-4">
            {report.recommendations.map((action) => (
              <li key={action.title} className="border-t border-line pt-3">
                <p className="text-sm font-medium">{action.title}</p>
                <p className="mt-1 text-sm leading-6 text-mute">{action.detail}</p>
              </li>
            ))}
          </ol>
          <p className="mt-5 text-xs leading-5 text-mute">{report.scope_note}</p>
          <p className="mt-2 text-xs leading-5 text-mute">{report.risk_rationale}</p>
        </div>
      </div>

      <div className="rounded-2xl border border-line bg-panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">Timeline</h3>
          <button type="button" className="font-mono text-[11px] text-signal hover:underline" onClick={onToggleAll}>
            {showAll ? "Cited events only" : `Entire file (${investigation.events.length})`}
          </button>
        </div>
        <ol className="mt-4 divide-y divide-line">
          {visible.map((event) => (
            <TimelineRow
              key={event.id}
              event={event}
              cited={cited.has(event.id)}
              selected={selectedEventId === event.id}
              onSelect={() => onSelectEvent(event.id)}
            />
          ))}
        </ol>
        {investigation.findings.length > 0 ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {investigation.findings.map((finding) => (
              <button
                key={finding.id}
                type="button"
                className="rounded-full border border-line px-2 py-1 font-mono text-[10px] text-mute hover:border-signal hover:text-paper"
                onClick={() => onSelectFinding(finding.id)}
              >
                {categoryLabel(finding.category)}
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function TimelineRow({
  event,
  cited,
  selected,
  onSelect,
}: {
  event: EventRecord;
  cited: boolean;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        id={`event-${event.id}`}
        onClick={onSelect}
        className={`flex w-full gap-3 py-2.5 text-left ${selected ? "bg-panel-2" : ""} ${cited ? "" : "opacity-60"}`}
      >
        <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${cited ? "bg-signal" : "bg-line"}`} />
        <span className="w-40 shrink-0 font-mono text-[11px] text-mute">{formatTime(event.timestamp)}</span>
        <span className="min-w-0">
          <span className="font-mono text-[11px] text-signal">{event.id}</span>
          <span className="ml-2 text-sm">
            {event.host}
            {event.user ? ` · ${event.user}` : ""} · {event.event_type}
          </span>
          <span className="mt-0.5 block text-xs leading-5 text-mute">{event.detail}</span>
        </span>
      </button>
    </li>
  );
}

function download(investigation: Investigation) {
  const blob = new Blob([toMarkdown(investigation)], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinel-${investigation.case.id}-report.md`;
  link.click();
  URL.revokeObjectURL(url);
}
