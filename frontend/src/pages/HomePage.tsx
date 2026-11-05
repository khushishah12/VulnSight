import { HealthCard } from "../components/HealthCard";
import { useHealthCheck } from "../hooks/useHealthCheck";
import { formatLatency } from "../utils/format";

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-slate-800 py-2.5 last:border-0">
      <dt className="text-sm text-slate-400">{label}</dt>
      <dd className="text-right text-sm font-medium text-slate-100">{value}</dd>
    </div>
  );
}

function CheckItem({
  label,
  detail,
  state,
}: {
  label: string;
  detail: string;
  state: "ok" | "waiting" | "error";
}) {
  const dot =
    state === "ok"
      ? "bg-emerald-400"
      : state === "waiting"
        ? "bg-amber-400"
        : "bg-rose-400";

  return (
    <li className="flex gap-3 py-3">
      <span className={`mt-1.5 size-2.5 shrink-0 rounded-full ${dot}`} />
      <div>
        <p className="text-sm font-medium text-slate-200">{label}</p>
        <p className="mt-0.5 text-sm text-slate-500">{detail}</p>
      </div>
    </li>
  );
}

export function HomePage() {
  const {
    api,
    database,
    apiStatus,
    databaseStatus,
    apiError,
    databaseError,
    isLoading,
    refresh,
  } = useHealthCheck();

  const apiTone =
    apiStatus === "online"
      ? "ok"
      : apiStatus === "checking"
        ? "checking"
        : "error";

  const databaseTone =
    databaseStatus === "connected"
      ? "ok"
      : databaseStatus === "checking"
        ? "checking"
        : databaseStatus === "not_configured"
          ? "warning"
          : "error";

  return (
    <div>
      <section className="max-w-3xl">
        <p className="text-xs font-semibold uppercase tracking-[0.28em] text-emerald-400">
          Step 3 · Foundation checkpoint
        </p>
        <h1 className="mt-4 text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          Confirm React, FastAPI, and Neon are talking to each other.
        </h1>
        <p className="mt-5 text-base leading-7 text-slate-400">
          This page is intentionally small. It calls the backend health
          endpoints and shows whether the API is reachable and whether the
          backend can run a test query against Neon PostgreSQL.
        </p>

        <div className="mt-8 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={isLoading}
            className="inline-flex items-center gap-2 rounded-xl bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isLoading ? (
              <span className="size-4 animate-spin rounded-full border-2 border-slate-900/30 border-t-slate-900" />
            ) : (
              <svg
                aria-hidden="true"
                viewBox="0 0 24 24"
                fill="none"
                className="size-4"
              >
                <path
                  d="M20 11a8 8 0 1 0-2.34 5.66M20 5v6h-6"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            )}
            {isLoading ? "Checking…" : "Refresh status"}
          </button>

          <a
            href="http://127.0.0.1:8000/docs"
            target="_blank"
            rel="noreferrer"
            className="rounded-xl border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
          >
            Open API docs
          </a>
        </div>
      </section>

      <div className="mt-12 grid gap-5 lg:grid-cols-2">
        <HealthCard
          title="FastAPI backend"
          description="The API process and its version."
          tone={apiTone}
          badge={
            apiStatus === "online"
              ? "Online"
              : apiStatus === "checking"
                ? "Checking"
                : "Offline"
          }
        >
          {api ? (
            <dl>
              <DetailRow label="Service" value={api.service} />
              <DetailRow label="Version" value={api.version} />
              <DetailRow label="Environment" value={api.environment} />
              <DetailRow label="Endpoint" value="/api/v1/health" />
            </dl>
          ) : (
            <p className="rounded-xl border border-rose-400/20 bg-rose-400/5 p-4 text-sm leading-6 text-rose-200">
              {apiError ??
                "Start the backend with uvicorn, then refresh this page."}
            </p>
          )}
        </HealthCard>

        <HealthCard
          title="Neon PostgreSQL"
          description="A real SELECT 1 executed by FastAPI."
          tone={databaseTone}
          badge={
            databaseStatus === "connected"
              ? "Connected"
              : databaseStatus === "checking"
                ? "Checking"
                : databaseStatus === "not_configured"
                  ? "Not configured"
                  : "Unavailable"
          }
        >
          {database ? (
            <dl>
              <DetailRow label="Connection" value="TLS + asyncpg" />
              <DetailRow label="Test query" value="SELECT 1" />
              <DetailRow
                label="Round trip"
                value={formatLatency(database.latency_ms)}
              />
              <DetailRow label="Endpoint" value="/api/v1/health/db" />
            </dl>
          ) : (
            <div
              className={`rounded-xl border p-4 text-sm leading-6 ${
                databaseStatus === "not_configured"
                  ? "border-amber-400/20 bg-amber-400/5 text-amber-100"
                  : "border-rose-400/20 bg-rose-400/5 text-rose-200"
              }`}
            >
              <p>
                {databaseError ??
                  "Add DATABASE_URL to backend/.env, restart FastAPI, then refresh."}
              </p>
              {databaseStatus === "not_configured" && (
                <p className="mt-2 text-amber-200/70">
                  Use the direct Neon connection string, not the pooled one.
                </p>
              )}
            </div>
          )}
        </HealthCard>
      </div>

      <section className="mt-6 grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Checkpoint
          </h2>
          <ul className="mt-3 divide-y divide-slate-800">
            <CheckItem
              label="React development server"
              detail="Vite is serving this page on port 5173."
              state="ok"
            />
            <CheckItem
              label="FastAPI health endpoint"
              detail={
                apiStatus === "online"
                  ? "The backend returned a valid health response."
                  : apiStatus === "checking"
                    ? "Checking http://127.0.0.1:8000/api/v1/health…"
                    : "The API is offline. Start the backend on 127.0.0.1:8000."
              }
              state={
                apiStatus === "online"
                  ? "ok"
                  : apiStatus === "checking"
                    ? "waiting"
                    : "error"
              }
            />
            <CheckItem
              label="Neon database connection"
              detail={
                databaseStatus === "connected"
                  ? "FastAPI connected to Neon and executed SELECT 1."
                  : databaseStatus === "checking"
                    ? "Running SELECT 1 through FastAPI…"
                    : databaseStatus === "not_configured"
                      ? "Waiting for a direct Neon connection string in backend/.env."
                      : "The database check failed. Review the API log."
              }
              state={
                databaseStatus === "connected"
                  ? "ok"
                  : databaseStatus === "checking" ||
                      databaseStatus === "not_configured"
                    ? "waiting"
                    : "error"
              }
            />
            <CheckItem
              label="Credentials isolated from the browser"
              detail="Only FastAPI reads backend/.env. React calls /api/v1."
              state="ok"
            />
          </ul>
        </div>

        <aside className="rounded-2xl border border-emerald-400/15 bg-emerald-400/5 p-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-emerald-300">
            Security boundary
          </h2>
          <p className="mt-3 text-sm leading-6 text-emerald-100/80">
            The browser never receives a database driver, connection string, or
            database password. Vite only proxies HTTP requests to FastAPI, and
            FastAPI is the only component that talks to Neon.
          </p>
          <p className="mt-4 rounded-lg bg-slate-950/40 p-3 font-mono text-xs text-emerald-200/80">
            React → /api/v1 → FastAPI → Neon
          </p>
        </aside>
      </section>
    </div>
  );
}
