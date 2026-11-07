import { categoryLabel, clock, severityClass } from "../format";
import type { EventRecord, Finding } from "../types";

interface Props {
  findings: Finding[];
  events: EventRecord[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export function Findings({ findings, events, selectedId, onSelect }: Props) {
  const times = new Map(events.map((event) => [event.id, event.timestamp]));
  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="finding-list">
      <div className="flex items-baseline justify-between px-4 pt-4">
        <h2 className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">Findings</h2>
        <span className="font-mono text-[11px] text-mute">{findings.length}</span>
      </div>
      <div className="mt-2 flex-1 space-y-2 overflow-auto px-3 pb-3">
        {findings.length === 0 ? (
          <p className="px-1 py-6 text-sm leading-6 text-mute">
            Nothing crossed a rule threshold. Single failures, office-hours logons, and the backup job stay in the file as context.
          </p>
        ) : (
          findings.map((finding) => {
            const first = finding.evidence_ids.map((id) => times.get(id)).find(Boolean);
            const selected = selectedId === finding.id;
            return (
              <button
                key={finding.id}
                type="button"
                data-testid={`finding-${finding.id}`}
                aria-pressed={selected}
                onClick={() => onSelect(finding.id)}
                className={`w-full rounded-xl border px-3 py-3 text-left transition ${
                  selected ? "border-signal bg-panel-2" : "border-line bg-ink/40 hover:border-mute"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`rounded-full px-2 py-0.5 font-mono text-[10px] uppercase ${severityClass(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className="font-mono text-[10px] uppercase tracking-wide text-mute">
                    {categoryLabel(finding.category)}
                  </span>
                  {first ? <span className="ml-auto font-mono text-[10px] text-mute">{clock(first)}</span> : null}
                </div>
                <p className="mt-2 text-sm font-medium leading-5">{finding.title}</p>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
