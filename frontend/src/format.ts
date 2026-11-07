import type { Investigation, Severity } from "./types";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const day = String(date.getUTCDate()).padStart(2, "0");
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  const seconds = String(date.getUTCSeconds()).padStart(2, "0");
  return `${day} ${MONTHS[date.getUTCMonth()]} ${hours}:${minutes}:${seconds} UTC`;
}

export function clock(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  const seconds = String(date.getUTCSeconds()).padStart(2, "0");
  return `${hours}:${minutes}:${seconds}`;
}

export const CATEGORY_LABEL: Record<string, string> = {
  initial_access: "Initial access",
  privilege: "Privilege change",
  persistence: "New service",
  lateral_movement: "Lateral movement",
  collection: "Collection",
  exfiltration: "Outbound transfer",
};

export function categoryLabel(category: string): string {
  return CATEGORY_LABEL[category] ?? category.replaceAll("_", " ");
}

export function severityClass(severity: Severity): string {
  if (severity === "high") return "bg-danger/15 text-danger";
  if (severity === "medium") return "bg-warn/15 text-warn";
  return "bg-ok/15 text-ok";
}

export function toMarkdown(investigation: Investigation): string {
  const { report, case: caseInfo } = investigation;
  const lines = [
    `# ${report.title}`,
    "",
    `${caseInfo.subtitle}. ${caseInfo.note}`,
    "",
    `Risk: ${report.risk}`,
    "",
    report.risk_rationale,
    "",
    "## Summary",
    "",
    report.summary,
    "",
    "## Root cause supported by the logs",
    "",
    report.root_cause,
    "",
    "## Evidence ledger",
    "",
  ];
  for (const item of report.conclusions) {
    const ids = item.evidence_ids.join(", ");
    lines.push(`- **${item.kind}** (${ids}): ${item.statement}`);
  }
  lines.push("", "## Defensive actions", "");
  for (const action of report.recommendations) {
    const ids = action.evidence_ids.length ? ` _(${action.evidence_ids.join(", ")})_` : "";
    lines.push(`- **${action.title}.** ${action.detail}${ids}`);
  }
  lines.push("", report.scope_note, "", `Reasoning: ${report.reasoning_note}`, "");
  return lines.join("\n");
}
