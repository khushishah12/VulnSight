import { apiGet, apiPost } from "./client";
import type { DiscoveredEndpoint, ScanSession, ScanStatusResponse } from "../types";

interface ScanListResponse {
  items: ScanSession[];
  total: number;
  limit: number;
  offset: number;
}

export async function fetchScans(status?: string, limit = 50): Promise<ScanListResponse> {
  const query = new URLSearchParams();
  if (status) query.set("status", status);
  query.set("limit", String(limit));
  return apiGet<ScanListResponse>(`/scans?${query.toString()}`);
}

export async function fetchScan(scanId: string): Promise<ScanSession> {
  return apiGet<ScanSession>(`/scans/${scanId}`);
}

export async function fetchScanStatus(scanId: string): Promise<ScanStatusResponse> {
  return apiGet<ScanStatusResponse>(`/scans/${scanId}/status`);
}

export async function createScan(
  name: string,
  targetUrl: string,
  profile = "lean_mvp",
): Promise<ScanSession> {
  return apiPost<ScanSession>("/scans", {
    name,
    profile,
    targets: [{ url: targetUrl, is_authorized: true }],
  });
}

export async function startScan(scanId: string): Promise<ScanStatusResponse> {
  return apiPost<ScanStatusResponse>(`/scans/${scanId}/start`);
}

export async function cancelScan(scanId: string): Promise<ScanStatusResponse> {
  return apiPost<ScanStatusResponse>(`/scans/${scanId}/cancel`);
}

export async function fetchScanEndpoints(scanId: string): Promise<DiscoveredEndpoint[]> {
  try {
    const res = await apiGet<{ items: DiscoveredEndpoint[] }>(`/scans/${scanId}/endpoints`);
    return res.items ?? [];
  } catch {
    return [];
  }
}
