import { useEffect, useState } from "react";
import { fetchScans } from "../api/scans";
import { useNavigation } from "../context/NavigationContext";
import {
  PlayIcon,
  RefreshCwIcon,
} from "../components/ui/Icons";
import { StatusBadge } from "../components/ui/Badge";
import { EmptyState, ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import type { ScanSession } from "../types";

export function ScanHistoryPage() {
  const { navigate } = useNavigation();
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadScans() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchScans(statusFilter || undefined, 50);
      setScans(res.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadScans();
  }, [statusFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
            Assessment Session History
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Durable records of all security scans executed against authorized targets
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={loadScans}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 text-xs font-medium transition cursor-pointer"
          >
            <RefreshCwIcon className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={() => navigate("new-scan")}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs tracking-wide transition shadow-sm cursor-pointer"
          >
            <PlayIcon className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {error && <ErrorAlert title="History Error" message={error} onRetry={loadScans} />}

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 text-xs">
        {["", "completed", "running", "failed", "cancelled"].map((st) => (
          <button
            key={st}
            type="button"
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded-lg border font-medium capitalize transition cursor-pointer ${
              statusFilter === st
                ? "bg-slate-800 text-slate-100 border-emerald-500/50"
                : "bg-slate-900/60 text-slate-400 border-slate-800 hover:bg-slate-800/40"
            }`}
          >
            {st || "All Statuses"}
          </button>
        ))}
      </div>

      {/* Scans Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <LoadingSkeleton count={5} />
        ) : scans.length === 0 ? (
          <EmptyState
            title="No Scans in History"
            message="No assessment sessions match the selected filter."
            action={
              <button
                type="button"
                onClick={() => navigate("new-scan")}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs tracking-wide transition shadow"
              >
                Launch Assessment
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-[10px] font-semibold tracking-wider uppercase text-slate-400 font-mono">
                <tr>
                  <th className="px-5 py-3">Assessment Name</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Targets</th>
                  <th className="px-5 py-3">Findings</th>
                  <th className="px-5 py-3">Profile</th>
                  <th className="px-5 py-3">Timestamp</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => {
                      if (scan.status === "running") {
                        navigate("live-scan", { scanId: scan.id });
                      } else {
                        navigate("scan-results", { scanId: scan.id });
                      }
                    }}
                    className="hover:bg-slate-800/40 transition cursor-pointer"
                  >
                    <td className="px-5 py-3.5">
                      <div className="font-semibold text-slate-100">{scan.name}</div>
                      <div className="text-[10px] font-mono text-slate-500">ID: {scan.id}</div>
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-5 py-3.5 font-mono text-slate-400">
                      {scan.target_count || 1} target(s)
                    </td>
                    <td className="px-5 py-3.5 font-mono">
                      <span className="text-amber-400 font-semibold">{scan.finding_count ?? 0}</span>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-slate-400">
                      {scan.profile}
                    </td>
                    <td className="px-5 py-3.5 text-slate-400">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono">
                      <span className="text-emerald-400 hover:text-emerald-300 font-medium">
                        Open &rarr;
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
