import type {
  ExecutionSession,
  MetricsOverview,
  MetricsTrends,
  Resolution,
  ResolutionContext,
  ResolutionFeedback,
  RunDiff,
  RunDetail,
  RunSummary,
  ScannerInfo,
} from "../types";
import { getApiBase, getApiToken } from "./storage";

export type RunCreateRequest = {
  scanner_ids?: string[];
  options?: Record<string, unknown>;
};

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const base = getApiBase().replace(/\/+$/, "");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  const token = getApiToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return fetch(`${base}${path}`, { ...init, headers });
}

async function readJson<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`API ${resp.status}: ${text || resp.statusText}`);
  }
  return (await resp.json()) as T;
}

export async function apiHealth(): Promise<{ status: string }> {
  const resp = await apiFetch("/api/health");
  return readJson(resp);
}

export async function apiListScanners(): Promise<ScannerInfo[]> {
  const resp = await apiFetch("/api/scanners");
  return readJson(resp);
}

export async function apiCreateRun(body: RunCreateRequest): Promise<RunSummary> {
  const resp = await apiFetch("/api/runs", { method: "POST", body: JSON.stringify(body) });
  return readJson(resp);
}

export async function apiListRuns(limit = 50): Promise<RunSummary[]> {
  const resp = await apiFetch(`/api/runs?limit=${encodeURIComponent(String(limit))}`);
  return readJson(resp);
}

export async function apiGetRun(runId: string): Promise<RunDetail> {
  const resp = await apiFetch(`/api/runs/${encodeURIComponent(runId)}`);
  return readJson(resp);
}

export async function apiGetRunDiff(runId: string, against: string = "previous"): Promise<RunDiff> {
  const resp = await apiFetch(
    `/api/runs/${encodeURIComponent(runId)}/diff?against=${encodeURIComponent(against)}`,
  );
  return readJson(resp);
}

export async function apiMetricsOverview(): Promise<MetricsOverview> {
  const resp = await apiFetch("/api/metrics/overview");
  return readJson(resp);
}

export async function apiMetricsTrends(days = 30): Promise<MetricsTrends> {
  const resp = await apiFetch(`/api/metrics/trends?days=${encodeURIComponent(String(days))}`);
  return readJson(resp);
}

// AI Resolution API

export async function apiGenerateResolution(
  findingId: string,
  context?: ResolutionContext,
): Promise<Resolution> {
  const resp = await apiFetch(`/api/findings/${encodeURIComponent(findingId)}/resolve`, {
    method: "POST",
    body: JSON.stringify(context || {}),
  });
  return readJson(resp);
}

export async function apiGetResolution(resolutionId: string): Promise<Resolution> {
  const resp = await apiFetch(`/api/resolutions/${encodeURIComponent(resolutionId)}`);
  return readJson(resp);
}

export async function apiGetResolutionHistory(fingerprint: string): Promise<Resolution[]> {
  const resp = await apiFetch(`/api/resolutions/history/${encodeURIComponent(fingerprint)}`);
  return readJson(resp);
}

export async function apiSubmitResolutionFeedback(
  resolutionId: string,
  feedback: ResolutionFeedback,
): Promise<Resolution> {
  const resp = await apiFetch(`/api/resolutions/${encodeURIComponent(resolutionId)}/feedback`, {
    method: "POST",
    body: JSON.stringify(feedback),
  });
  return readJson(resp);
}

export async function apiMarkResolutionApplied(resolutionId: string): Promise<Resolution> {
  const resp = await apiFetch(`/api/resolutions/${encodeURIComponent(resolutionId)}/mark-applied`, {
    method: "POST",
  });
  return readJson(resp);
}

// Agent execution API

export async function apiCreateSession(resolutionId: string): Promise<ExecutionSession> {
  const resp = await apiFetch(
    `/api/resolutions/${encodeURIComponent(resolutionId)}/sessions`,
    { method: "POST" },
  );
  return readJson(resp);
}

export async function apiGetSession(sessionId: string): Promise<ExecutionSession> {
  const resp = await apiFetch(`/api/sessions/${encodeURIComponent(sessionId)}`);
  return readJson(resp);
}

export async function apiApproveStep(
  sessionId: string,
  stepOrder: number,
  confirmedRisk = false,
): Promise<ExecutionSession> {
  const resp = await apiFetch(
    `/api/sessions/${encodeURIComponent(sessionId)}/steps/${stepOrder}/approve`,
    { method: "POST", body: JSON.stringify({ confirmed_risk: confirmedRisk }) },
  );
  return readJson(resp);
}

export async function apiSkipStep(
  sessionId: string,
  stepOrder: number,
): Promise<ExecutionSession> {
  const resp = await apiFetch(
    `/api/sessions/${encodeURIComponent(sessionId)}/steps/${stepOrder}/skip`,
    { method: "POST" },
  );
  return readJson(resp);
}

export async function apiAbortSession(sessionId: string): Promise<ExecutionSession> {
  const resp = await apiFetch(
    `/api/sessions/${encodeURIComponent(sessionId)}/abort`,
    { method: "POST" },
  );
  return readJson(resp);
}

export function openSessionStream(sessionId: string): EventSource {
  const base = getApiBase().replace(/\/+$/, "");
  const token = getApiToken();
  const url = new URL(`${base}/api/sessions/${encodeURIComponent(sessionId)}/stream`);
  if (token) url.searchParams.set("token", token);
  return new EventSource(url.toString());
}
