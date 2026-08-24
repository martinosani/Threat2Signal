// ---------------------------------------------------------------------------
// Typed fetch wrapper for all API calls.
// All endpoints go through fetchApi — single place for error handling.
// ---------------------------------------------------------------------------

import type {
  Advisory,
  AdvisoryAsset,
  AdvisoryCve,
  AdvisoryDetail,
  AnalysisResult,
  AttackTechnique,
  Behavior,
  DetectionRule,
  ExtractionLogEntry,
  Ioc,
  IocAdvisoryDetail,
  IocSearchResponse,
  IocStatsResponse,
  LlmStats,
  MsrcCve,
  MsrcCveDetail,
  MsrcStatsResponse,
  PaginatedResponse,
  StatsResponse,
  TriageStatus,
} from './types';

class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// -- Auth token management --------------------------------------------------

let _authToken: string | null = null;

function setAuthToken(token: string | null): void {
  _authToken = token;
}

function authHeaders(): Record<string, string> {
  if (!_authToken) return {};
  return { Authorization: `Bearer ${_authToken}` };
}

function handleExpiredSession(): never {
  setAuthToken(null);
  localStorage.removeItem('threat2signal_auth_token');
  localStorage.removeItem('threat2signal_auth_user');
  window.location.href = '/login';
  throw new ApiError(401, 'Session expired');
}

async function fetchApi<T>(
  path: string,
  params?: Record<string, string>,
): Promise<T> {
  const url = new URL(path, window.location.origin);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value != null) url.searchParams.set(key, value);
    }
  }

  const response = await fetch(url.toString(), { headers: authHeaders() });

  if (response.status === 401) handleExpiredSession();

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new ApiError(response.status, text);
  }

  return response.json() as Promise<T>;
}

async function postApi<T>(
  path: string,
  body?: Record<string, unknown>,
): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (response.status === 401) handleExpiredSession();

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new ApiError(response.status, text);
  }

  return response.json() as Promise<T>;
}

async function patchApi<T>(
  path: string,
  body: Record<string, unknown>,
): Promise<T> {
  const response = await fetch(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });

  if (response.status === 401) handleExpiredSession();

  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new ApiError(response.status, text);
  }

  return response.json() as Promise<T>;
}

// --- Per-endpoint functions ---

export function fetchAdvisories(
  params?: Record<string, string>,
): Promise<PaginatedResponse<Advisory>> {
  return fetchApi<PaginatedResponse<Advisory>>('/api/advisories', params);
}

export function fetchAdvisory(id: number): Promise<AdvisoryDetail> {
  return fetchApi<AdvisoryDetail>(`/api/advisories/${id}`);
}

export function fetchStats(): Promise<StatsResponse> {
  return fetchApi<StatsResponse>('/api/stats');
}

export function fetchAnalysis(id: number): Promise<AnalysisResult> {
  return fetchApi<AnalysisResult>(`/api/advisories/${id}/analysis`);
}

export function triggerAnalysis(id: number, force = false): Promise<AnalysisResult> {
  const qs = force ? '?force=true' : '';
  return postApi<AnalysisResult>(`/api/advisories/${id}/analysis${qs}`);
}

export function updateTriage(
  id: number,
  status: TriageStatus,
): Promise<{ id: number; advisory_id: string; triage_status: TriageStatus }> {
  return patchApi<{ id: number; advisory_id: string; triage_status: TriageStatus }>(
    `/api/advisories/${id}/triage`,
    { status },
  );
}

export function fetchMsrcCves(
  params?: Record<string, string>,
): Promise<PaginatedResponse<MsrcCve>> {
  return fetchApi<PaginatedResponse<MsrcCve>>('/api/msrc/cves', params);
}

export function fetchMsrcCve(cveId: string): Promise<MsrcCveDetail> {
  return fetchApi<MsrcCveDetail>(`/api/msrc/cves/${encodeURIComponent(cveId)}`);
}

export function fetchAdvisoryCves(id: number): Promise<AdvisoryCve[]> {
  return fetchApi<AdvisoryCve[]>(`/api/advisories/${id}/cves`);
}

export function fetchMsrcStats(): Promise<MsrcStatsResponse> {
  return fetchApi<MsrcStatsResponse>('/api/msrc/stats');
}

export function fetchLlmStats(): Promise<LlmStats> {
  return fetchApi<LlmStats>('/api/stats/llm');
}

// --- Extraction artifact endpoints ---

export function fetchAdvisoryIocs(
  id: number,
  type?: string,
): Promise<Ioc[]> {
  const params: Record<string, string> = {};
  if (type) params.type = type;
  return fetchApi<Ioc[]>(`/api/advisories/${id}/iocs`, params);
}

export function fetchAdvisoryDetectionRules(
  id: number,
  format?: string,
): Promise<DetectionRule[]> {
  const params: Record<string, string> = {};
  if (format) params.format = format;
  return fetchApi<DetectionRule[]>(`/api/advisories/${id}/detection-rules`, params);
}

export function fetchAdvisoryTechniques(
  id: number,
  framework?: string,
): Promise<AttackTechnique[]> {
  const params: Record<string, string> = {};
  if (framework) params.framework = framework;
  return fetchApi<AttackTechnique[]>(`/api/advisories/${id}/techniques`, params);
}

export function fetchAdvisoryBehaviors(
  id: number,
): Promise<Behavior[]> {
  return fetchApi<Behavior[]>(`/api/advisories/${id}/behaviors`);
}

export function fetchAdvisoryAssets(
  id: number,
  type?: string,
): Promise<AdvisoryAsset[]> {
  const params: Record<string, string> = {};
  if (type) params.type = type;
  return fetchApi<AdvisoryAsset[]>(`/api/advisories/${id}/assets`, params);
}

export async function exportAdvisoryIocs(
  id: number,
  format: 'csv' | 'stix2',
): Promise<Blob> {
  const url = `/api/advisories/${id}/iocs/export?format=${format}`;
  const response = await fetch(url, { headers: authHeaders() });
  if (response.status === 401) handleExpiredSession();
  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new ApiError(response.status, text);
  }
  return response.blob();
}

export async function exportNavigatorLayer(id: number): Promise<Blob> {
  const url = `/api/advisories/${id}/techniques/navigator`;
  const response = await fetch(url, { headers: authHeaders() });
  if (response.status === 401) handleExpiredSession();
  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new ApiError(response.status, text);
  }
  return response.blob();
}

export function fetchExtractionLogs(
  id: number,
  severity?: string,
): Promise<ExtractionLogEntry[]> {
  const params: Record<string, string> = {};
  if (severity) params.severity = severity;
  return fetchApi<ExtractionLogEntry[]>(`/api/advisories/${id}/extraction-logs`, params);
}

// --- Cross-advisory IOC Search (WS-10) ---

export function fetchIocs(
  params?: Record<string, string>,
): Promise<IocSearchResponse> {
  return fetchApi<IocSearchResponse>('/api/iocs', params);
}

export function fetchIocStats(): Promise<IocStatsResponse> {
  return fetchApi<IocStatsResponse>('/api/iocs/stats');
}

export function fetchIocAdvisories(
  type: string,
  value: string,
): Promise<IocAdvisoryDetail[]> {
  return fetchApi<IocAdvisoryDetail[]>(
    `/api/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}/advisories`,
  );
}

export async function exportIocsGlobal(
  format: 'csv' | 'stix2',
  params?: Record<string, string>,
): Promise<Blob> {
  const url = new URL('/api/iocs/export', window.location.origin);
  url.searchParams.set('format', format);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value != null) url.searchParams.set(key, value);
    }
  }
  const response = await fetch(url.toString(), { headers: authHeaders() });
  if (response.status === 401) handleExpiredSession();
  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText);
    throw new ApiError(response.status, text);
  }
  return response.blob();
}

function triggerDownload(blob: Blob, filename: string): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

export { ApiError, authHeaders, setAuthToken, triggerDownload };
