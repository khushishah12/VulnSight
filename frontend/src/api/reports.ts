import { apiGet, apiPost } from "./client";
import type { ReportItem } from "../types";

export async function createReport(
  scanId: string,
  title = "Vulnerability Assessment Report",
  version = "1.0",
): Promise<ReportItem> {
  return apiPost<ReportItem>("/reports", {
    scan_id: scanId,
    title,
    version,
  });
}

export async function fetchScanReports(scanId: string): Promise<ReportItem[]> {
  try {
    return await apiGet<ReportItem[]>(`/scans/${scanId}/reports`);
  } catch {
    return [];
  }
}

export async function fetchReport(reportId: string): Promise<ReportItem> {
  return apiGet<ReportItem>(`/reports/${reportId}`);
}
