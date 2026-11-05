import { apiGet, apiPatch, apiPost } from "./client";
import type {
  FindingDetail,
  FindingSummary,
  RemediationGuide,
  RemediationItem,
  VerificationRunItem,
} from "../types";

interface FindingListResponse {
  items: FindingSummary[];
  total: number;
  limit: number;
  offset: number;
}

export async function fetchScanFindings(
  scanId: string,
  params?: {
    severity?: string;
    status?: string;
    owasp_category?: string;
    limit?: number;
    offset?: number;
  },
): Promise<FindingListResponse> {
  const query = new URLSearchParams();
  if (params?.severity) query.set("severity", params.severity);
  if (params?.status) query.set("status", params.status);
  if (params?.owasp_category) query.set("owasp_category", params.owasp_category);
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  return apiGet<FindingListResponse>(`/scans/${scanId}/findings?${query.toString()}`);
}

export async function fetchFinding(findingId: string): Promise<FindingDetail> {
  return apiGet<FindingDetail>(`/findings/${findingId}`);
}

export async function fetchFindingRemediationGuide(findingId: string): Promise<RemediationGuide> {
  return apiGet<RemediationGuide>(`/findings/${findingId}/remediation-guide`);
}

export async function updateFindingRemediation(
  findingId: string,
  status: string,
  notes?: string,
): Promise<RemediationItem> {
  return apiPatch<RemediationItem>(`/findings/${findingId}/remediation`, {
    status,
    notes,
  });
}

export async function requestFixVerification(
  findingId: string,
  note?: string,
  executeNow = true,
): Promise<VerificationRunItem> {
  return apiPost<VerificationRunItem>(`/findings/${findingId}/verify`, {
    note,
    execute_now: executeNow,
  });
}
