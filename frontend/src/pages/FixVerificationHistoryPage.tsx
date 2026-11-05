import { useEffect, useState } from "react";
import { fetchScans } from "../api/scans";
import { fetchFinding, fetchScanFindings } from "../api/findings";
import { useNavigation } from "../context/NavigationContext";
import {
  RefreshCwIcon,
} from "../components/ui/Icons";
import { StatusBadge } from "../components/ui/Badge";
import { EmptyState, ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import type { VerificationRunItem } from "../types";

interface VerificationRow {
  run: VerificationRunItem;
  findingTitle: string;
  findingId: string;
  severity: string;
  category: string;
}

export function FixVerificationHistoryPage() {
  const { navigate } = useNavigation();
  const [rows, setRows] = useState<VerificationRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadVerificationHistory() {
    setLoading(true);
    setError(null);
    try {
      const scansRes = await fetchScans(undefined, 20);
      const allRows: VerificationRow[] = [];

      for (const scan of scansRes.items.slice(0, 5)) {
        const findingsRes = await fetchScanFindings(scan.id, { limit: 50 });
        for (const f of findingsRes.items) {
          try {
            const detail = await fetchFinding(f.id);
            if (detail.verification_runs && detail.verification_runs.length > 0) {
              for (const run of detail.verification_runs) {
                allRows.push({
                  run,
                  findingTitle: detail.title,
                  findingId: detail.id,
                  severity: detail.severity,
                  category: detail.owasp_category,
                });
              }
            }
          } catch {
            // continue
          }
        }
      }

      // Sort by creation date descending
      allRows.sort((a, b) => new Date(b.run.created_at).getTime() - new Date(a.run.created_at).getTime());
      setRows(allRows);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fix verification history.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadVerificationHistory();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
            Fix Verification Audit History
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Durable log of automated and operator-initiated re-tests across remediated findings
          </p>
        </div>

        <button
          type="button"
          onClick={loadVerificationHistory}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 text-xs font-medium transition cursor-pointer"
        >
          <RefreshCwIcon className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh History</span>
        </button>
      </div>

      {error && <ErrorAlert title="Verification History Error" message={error} onRetry={loadVerificationHistory} />}

      {/* History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <LoadingSkeleton count={4} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No Fix Verifications Found"
            message="When you request fix verification on remediated findings, the audit records will appear here."
            action={
              <button
                type="button"
                onClick={() => navigate("findings")}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs tracking-wide transition shadow"
              >
                Inspect Findings
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-[10px] font-semibold tracking-wider uppercase text-slate-400 font-mono">
                <tr>
                  <th className="px-5 py-3">Outcome</th>
                  <th className="px-5 py-3">Associated Finding</th>
                  <th className="px-5 py-3">OWASP</th>
                  <th className="px-5 py-3">Result Summary</th>
                  <th className="px-5 py-3">Timestamp</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {rows.map((row) => (
                  <tr
                    key={row.run.id}
                    onClick={() => navigate("finding-detail", { findingId: row.findingId })}
                    className="hover:bg-slate-800/40 transition cursor-pointer"
                  >
                    <td className="px-5 py-3.5">
                      <StatusBadge status={row.run.status} />
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="font-semibold text-slate-200 line-clamp-1">{row.findingTitle}</div>
                      <div className="text-[10px] font-mono text-slate-500">ID: {row.findingId.slice(0, 8)}...</div>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-emerald-400 font-semibold">
                      {row.category}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-slate-300 max-w-sm truncate" title={row.run.result_summary || "Verification queued"}>
                      {row.run.result_summary || "Queued in durable verification pipeline"}
                    </td>
                    <td className="px-5 py-3.5 text-slate-400">
                      {new Date(row.run.created_at).toLocaleString()}
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
