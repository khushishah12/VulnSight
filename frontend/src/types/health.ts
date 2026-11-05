export type HealthResponse = {
  status: "ok";
  service: string;
  version: string;
  environment: string;
};

export type DatabaseHealthResponse = {
  status: "ok";
  database: "connected";
  latency_ms: number;
};

export type DatabaseErrorResponse = {
  status: "error";
  database: "unavailable";
  detail: string;
};

export function isDatabaseErrorResponse(
  value: unknown,
): value is DatabaseErrorResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    "detail" in value &&
    typeof (value as { detail: unknown }).detail === "string"
  );
}
