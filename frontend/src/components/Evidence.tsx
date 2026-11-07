import { formatTime } from "../format";
import type { EventRecord, GraphNode } from "../types";

interface Props {
  title: string;
  detail?: string;
  flags?: string[];
  events: EventRecord[];
  selectedEventId: string | null;
  onSelectEvent: (id: string) => void;
}

export function Evidence({ title, detail, flags = [], events, selectedEventId, onSelectEvent }: Props) {
  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="evidence-panel">
      <div className="px-4 pt-4">
        <h2 className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">Evidence</h2>
        <p className="mt-2 text-sm font-medium leading-5">{title}</p>
        {detail ? <p className="mt-1 text-xs leading-5 text-mute">{detail}</p> : null}
        {flags.length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1">
            {flags.map((flag) => (
              <span key={flag} className="rounded-full bg-signal/15 px-2 py-0.5 font-mono text-[10px] text-signal">
                {flag}
              </span>
            ))}
          </div>
        ) : null}
      </div>
      <div className="mt-3 flex-1 space-y-2 overflow-auto px-3 pb-3">
        {events.length === 0 ? (
          <p className="px-1 text-sm leading-6 text-mute">Select a finding, a machine, or a line on the graph. The events behind that choice show up here.</p>
        ) : (
          events.map((event) => {
            const selected = selectedEventId === event.id;
            return (
              <button
                key={event.id}
                type="button"
                onClick={() => onSelectEvent(event.id)}
                className={`w-full rounded-xl border px-3 py-2.5 text-left ${
                  selected ? "border-signal bg-panel-2" : "border-line bg-ink/40 hover:border-mute"
                }`}
              >
                <div className="flex items-center gap-2 font-mono text-[10px] text-mute">
                  <span className="text-signal">{event.id}</span>
                  <span>{formatTime(event.timestamp)}</span>
                  <span className={`ml-auto uppercase ${event.result === "failure" ? "text-danger" : "text-ok"}`}>
                    {event.result}
                  </span>
                </div>
                <p className="mt-1 text-xs leading-5 text-paper">
                  <span className="text-mute">{event.host}</span>
                  {event.user ? ` · ${event.user}` : ""} · {event.event_type}
                </p>
                <p className="mt-1 text-xs leading-5 text-mute">{event.detail}</p>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

export function nodeCopy(node: GraphNode | undefined): { detail?: string; flags?: string[] } {
  if (!node) return {};
  return { detail: node.detail, flags: node.flags };
}
