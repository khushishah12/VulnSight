import type {
  DatabaseHealthResponse,
  HealthResponse,
} from "../types/health";
import { apiGet } from "./client";

export function getHealth(): Promise<HealthResponse> {
  return apiGet<HealthResponse>("/health");
}

export function getDatabaseHealth(): Promise<DatabaseHealthResponse> {
  return apiGet<DatabaseHealthResponse>("/health/db");
}

export const checkDatabaseHealth = getDatabaseHealth;
