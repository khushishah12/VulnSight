import { apiGet } from "./client";
import type { RemediationGuide } from "../types";

export async function fetchAllRemediationGuides(): Promise<RemediationGuide[]> {
  return apiGet<RemediationGuide[]>("/remediation-center");
}

export async function fetchRemediationGuideByCheck(checkId: string): Promise<RemediationGuide> {
  return apiGet<RemediationGuide>(`/remediation-center/${encodeURIComponent(checkId)}`);
}
