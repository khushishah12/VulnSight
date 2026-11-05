import { useEffect, useState } from "react";
import { cancelScan, fetchScan, fetchScanStatus } from "../api/scans";
import { useNavigation } from "../context/NavigationContext";
import {
  ArrowRightIcon,
  CheckCircleIcon,
  RefreshCwIcon,
  StopIcon,
  TerminalIcon,
} from "../components/ui/Icons";
import { StatusBadge } from "../components/ui/Badge";
import { ErrorAlert } from "../components/ui/Feedback";
import type { ScanSession, ScanStatusResponse } from "../types";

export function LiveScanProgressPage() {
  const { params, navigate } = useNavigation();
  const scanId = params.scanId;

  const [scan, setScan] = useState<ScanSession | null>(null);
  const [statusData, setStatusData] = useState<ScanStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [logs, setLogs] = useState<string[]>([
    "Initializing VulnSight scanning coordinator...",
    "Validating target URL against allowed host scope...",
  ]);

  useEffect(() => {
    if (!scanId) return;

    let isMounted = true;
    let pollTimer: number | undefined;

    async function initialFetch() {
      try {
        const fullScan = await fetchScan(scanId);
        if (isMounted) setScan(fullScan);
      } catch (err) {
        if (isMounted) setError(err instanceof Error ? err.message : "Failed to load scan.");
      }
    }

    async function pollStatus() {
      try {
        const res = await fetchScanStatus(scanId);
        if (!isMounted) return;
        setStatusData(res);

        // Update logs dynamically based on timeline
        setLogs((prev) => {
          const newLogs = [...prev];
          if (res.started_at && !newLogs.some((l) => l.includes("Reconnaissance phase active"))) {
            newLogs.push("DNS resolution completed. Target scope validated.");
            newLogs.push("Reconnaissance phase active: HTTP & HTML inspection started.");
          }
          if (res.status === "completed" && !newLogs.some((l) => l.includes("All 10 OWASP Top 10:2025"))) {
            newLogs.push("All 10 OWASP Top 10:2025 modular detection engines completed.");
            newLogs.push("Technical evidence redacted and persisted with SHA-256 integrity hashes.");
            newLogs.push("Assessment session completed successfully.");
          }
          if (res.status === "cancelled") {
            newLogs.push("Assessment cancelled by operator.");
          }
          if (res.status === "failed") {
            newLogs.push(`Assessment failed: ${res.status_message || "Unknown error"}`);
          }
          return newLogs;
        });

        // Auto-navigate to results once completed
        if (res.status === "completed") {
          setTimeout(() => {
            if (isMounted) {
              navigate("scan-results", { scanId });
            }
          }, 1800);
          return;
        }

        if (res.status === "running" || res.status === "pending") {
          pollTimer = setTimeout(pollStatus, 1500);
        }
      } catch (err) {
        if (isMounted) setError(err instanceof Error ? err.message : "Polling status failed.");
      }
    }

    initialFetch();
    pollStatus();

    return () => {
      isMounted = false;
      clearTimeout(pollTimer);
    };
  }, [scanId]);

  async function handleCancel() {
    if (!scanId) return;
    setCancelling(true);
    try {
      await cancelScan(scanId);
      const updated = await fetchScanStatus(scanId);
      setStatusData(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel scan.");
    } finally {
      setCancelling(false);
    }
  }

  const currentStatus = statusData?.status || scan?.status || "pending";
  const isFinished = currentStatus === "completed" || currentStatus === "failed" || currentStatus === "cancelled";

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
              Live Assessment Execution
            </h1>
            <StatusBadge status={currentStatus} />
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Session ID: {scanId}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {!isFinished && (
            <button
              type="button"
              onClick={handleCancel}
              disabled={cancelling}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-500/30 text-rose-300 text-xs font-semibold transition cursor-pointer"
            >
              <StopIcon className="w-3.5 h-3.5" />
              <span>{cancelling ? "Stopping..." : "Cancel Scan"}</span>
            </button>
          )}

          {currentStatus === "completed" && (
            <button
              type="button"
              onClick={() => navigate("scan-results", { scanId: scanId! })}
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs tracking-wide transition shadow-sm cursor-pointer"
            >
              <span>View Results</span>
              <ArrowRightIcon className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {error && <ErrorAlert title="Execution Warning" message={error} />}

      {/* Pipeline Stages Progress */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
          Assessment Pipeline Stages
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Stage 1 */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono text-slate-400">Step 1</span>
              <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="font-semibold text-slate-200 text-xs">Target Scope Validation</div>
            <div className="text-[11px] text-slate-400 mt-1">DNS, SSRF, & RFC checks</div>
          </div>

          {/* Stage 2 */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono text-slate-400">Step 2</span>
              {currentStatus !== "pending" ? (
                <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
              ) : (
                <RefreshCwIcon className="w-4 h-4 text-sky-400 animate-spin" />
              )}
            </div>
            <div className="font-semibold text-slate-200 text-xs">Reconnaissance Phase</div>
            <div className="text-[11px] text-slate-400 mt-1">Headers, HTML, & Endpoints</div>
          </div>

          {/* Stage 3 */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono text-slate-400">Step 3</span>
              {currentStatus === "completed" ? (
                <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
              ) : currentStatus === "running" ? (
                <RefreshCwIcon className="w-4 h-4 text-amber-400 animate-spin" />
              ) : (
                <span className="w-2 h-2 rounded-full bg-slate-700" />
              )}
            </div>
            <div className="font-semibold text-slate-200 text-xs">OWASP Top 10 Scanners</div>
            <div className="text-[11px] text-slate-400 mt-1">A01 - A10 Non-Destructive</div>
          </div>

          {/* Stage 4 */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono text-slate-400">Step 4</span>
              {currentStatus === "completed" ? (
                <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
              ) : (
                <span className="w-2 h-2 rounded-full bg-slate-700" />
              )}
            </div>
            <div className="font-semibold text-slate-200 text-xs">Evidence Persistence</div>
            <div className="text-[11px] text-slate-400 mt-1">SHA-256 & Neon Storage</div>
          </div>
        </div>

        {/* Live Execution Logs Feed */}
        <div className="space-y-2 pt-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
              <TerminalIcon className="w-4 h-4 text-emerald-400" />
              <span>Execution Log Stream</span>
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              {currentStatus === "running" ? "Streaming..." : "Completed"}
            </span>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-slate-300 space-y-1.5 h-64 overflow-y-auto">
            {logs.map((log, index) => (
              <div key={index} className="flex items-start gap-2 leading-relaxed">
                <span className="text-slate-600 select-none">[{index + 1}]</span>
                <span className={log.includes("completed") ? "text-emerald-400" : log.includes("active") ? "text-sky-300" : "text-slate-300"}>
                  {log}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
