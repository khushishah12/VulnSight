import { apiGet, apiPost } from "./client";
import type { ReportItem } from "../types";

export async function createReport(
  scanId: string,
  format: "pdf" | "html" | "json" = "pdf",
  _title = "Vulnerability Assessment Report",
  _version = "1.0",
): Promise<ReportItem> {
  // Primary endpoint: POST /scans/{scanId}/reports with format
  try {
    return await apiPost<ReportItem>(`/scans/${scanId}/reports`, { format });
  } catch {
    // Secondary fallback: POST /reports with scan_id and format
    return await apiPost<ReportItem>("/reports", { scan_id: scanId, format });
  }
}

export async function fetchScanReports(scanId?: string): Promise<ReportItem[]> {
  try {
    const url = scanId ? `/scans/${scanId}/reports` : "/reports";
    const res = await apiGet<{ items?: ReportItem[] } | ReportItem[]>(url);
    if (Array.isArray(res)) return res;
    return res.items ?? [];
  } catch {
    return [];
  }
}

export async function fetchAllReports(): Promise<ReportItem[]> {
  try {
    const res = await apiGet<{ items?: ReportItem[] } | ReportItem[]>("/reports");
    if (Array.isArray(res)) return res;
    return res.items ?? [];
  } catch {
    return [];
  }
}

export async function fetchReport(reportId: string): Promise<ReportItem> {
  return apiGet<ReportItem>(`/reports/${reportId}`);
}

export function getReportDownloadUrl(reportId: string): string {
  return `/api/v1/reports/${reportId}/download`;
}
