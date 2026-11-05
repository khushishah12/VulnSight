import { useCallback, useEffect, useState } from "react";

import { getDatabaseHealth, getHealth } from "../api/health";
import { ApiError } from "../api/client";
import {
  isDatabaseErrorResponse,
  type DatabaseHealthResponse,
  type HealthResponse,
} from "../types/health";

export type ApiStatus = "checking" | "online" | "offline";
export type DatabaseStatus =
  | "checking"
  | "connected"
  | "not_configured"
  | "unavailable";

export function useHealthCheck() {
  const [api, setApi] = useState<HealthResponse | null>(null);
  const [database, setDatabase] = useState<DatabaseHealthResponse | null>(null);
  const [apiStatus, setApiStatus] = useState<ApiStatus>("checking");
  const [databaseStatus, setDatabaseStatus] =
    useState<DatabaseStatus>("checking");
  const [apiError, setApiError] = useState<string | null>(null);
  const [databaseError, setDatabaseError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const load = useCallback(async () => {
    const [healthResult, databaseResult] = await Promise.allSettled([
      getHealth(),
      getDatabaseHealth(),
    ]);

    if (healthResult.status === "fulfilled") {
      setApi(healthResult.value);
      setApiStatus("online");
    } else {
      setApi(null);
      setApiStatus("offline");
      setApiError(
        "Cannot reach the FastAPI backend. Start it on http://127.0.0.1:8000.",
      );
    }

    if (databaseResult.status === "fulfilled") {
      setDatabase(databaseResult.value);
      setDatabaseStatus("connected");
    } else {
      setDatabase(null);

      const reason = databaseResult.reason;
      if (
        reason instanceof ApiError &&
        reason.status === 503 &&
        isDatabaseErrorResponse(reason.payload)
      ) {
        setDatabaseError(reason.payload.detail);
        setDatabaseStatus(
          reason.payload.detail.toLowerCase().includes("not configured")
            ? "not_configured"
            : "unavailable",
        );
      } else {
        setDatabaseError(
          "The database health endpoint could not be reached. Check that the API is running.",
        );
        setDatabaseStatus("unavailable");
      }
    }

    setIsLoading(false);
  }, []);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setApiStatus("checking");
    setDatabaseStatus("checking");
    setApi(null);
    setDatabase(null);
    setApiError(null);
    setDatabaseError(null);
    await load();
  }, [load]);

  useEffect(() => {
    // The check is intentionally started once when the page mounts.
    // oxlint-disable-next-line react/set-state-in-effect
    void load();
  }, [load]);

  return {
    api,
    database,
    apiStatus,
    databaseStatus,
    apiError,
    databaseError,
    isLoading,
    refresh,
  };
}
