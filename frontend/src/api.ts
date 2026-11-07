import type { Investigation } from "./types";

export class ApiError extends Error {}

async function readError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
  } catch {
    /* The body was not JSON. */
  }
  return `Request failed (${response.status}).`;
}

export async function fetchHealth(): Promise<{ status: string; grok_configured: boolean }> {
  const response = await fetch("/api/health");
  if (!response.ok) throw new ApiError(await readError(response));
  return response.json() as Promise<{ status: string; grok_configured: boolean }>;
}

export async function investigateSample(sampleId: string): Promise<Investigation> {
  const response = await fetch(`/api/samples/${sampleId}/investigation`);
  if (!response.ok) throw new ApiError(await readError(response));
  return response.json() as Promise<Investigation>;
}

export async function uploadLogs(file: File): Promise<Investigation> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch("/api/investigate", { method: "POST", body });
  if (!response.ok) throw new ApiError(await readError(response));
  return response.json() as Promise<Investigation>;
}
