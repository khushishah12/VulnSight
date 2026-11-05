import { useEffect, useState } from "react";
import { fetchScans } from "../api/scans";
import { fetchScanFindings } from "../api/findings";
import { useNavigation } from "../context/NavigationContext";
import {
  AlertTriangleIcon,
  ArrowRightIcon,
  CheckCircleIcon,
  LayersIcon,
  PlayIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
} from "../components/ui/Icons";
import { SecurityScoreGauge } from "../components/ui/SecurityScoreGauge";
import { StatCard } from "../components/ui/StatCard";
import { StatusBadge } from "../components/ui/Badge";
import { EmptyState, ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import type { FindingSummary, ScanSession } from "../types";

export function DashboardPage() {
  const { navigate } = useNavigation();
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const scansRes = await fetchScans(undefined, 20);
      setScans(scansRes.items);

      // Aggregate findings from recent scans
      let allFindings: FindingSummary[] = [];
      const completedScans = scansRes.items.filter((s) => s.status === "completed");
      if (completedScans.length > 0) {
        // fetch findings from top 3 scans
        const topScans = completedScans.slice(0, 3);
        const findingPromises = topScans.map((s) => fetchScanFindings(s.id, { limit: 100 }));
        const results = await Promise.all(findingPromises);
        results.forEach((r) => {
          allFindings = [...allFindings, ...r.items];
        });
      }
      setFindings(allFindings);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard metrics.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  // Compute severity distribution
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;
  const totalFindings = findings.length;

  // OWASP Top 10 category coverage counters
  const owaspCategories = [
    { id: "A01", name: "Broken Access Control" },
    { id: "A02", name: "Security Misconfig" },
    { id: "A03", name: "Supply Chain Failures" },
    { id: "A04", name: "Cryptographic Failures" },
    { id: "A05", name: "Injection Flaws" },
    { id: "A06", name: "Insecure Design" },
    { id: "A07", name: "Auth Failures" },
    { id: "A08", name: "Integrity Failures" },
    { id: "A09", name: "Logging & Alerting" },
    { id: "A10", name: "Exceptional Conditions" },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
            Security Posture & Telemetry
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time vulnerability findings, risk prioritization, and remediation status
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 hover:bg-slate-800 text-xs font-medium transition cursor-pointer"
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

      {error && <ErrorAlert message={error} onRetry={loadData} />}

      {/* Main KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans Executed"
          value={scans.length}
          subtitle={`${scans.filter((s) => s.status === "completed").length} completed`}
          icon={<LayersIcon className="w-4 h-4" />}
          highlightColor="#10b981"
        />
        <StatCard
          title="Active Weaknesses"
          value={totalFindings}
          subtitle={`${criticalCount + highCount} require immediate remediation`}
          icon={<AlertTriangleIcon className="w-4 h-4 text-rose-400" />}
          highlightColor="#f43f5e"
        />
        <StatCard
          title="Verified Remediations"
          value={findings.filter((f) => f.status === "verified" || f.status === "remediated").length}
          subtitle="Fixed through verification engine"
          icon={<CheckCircleIcon className="w-4 h-4 text-emerald-400" />}
          highlightColor="#14b8a6"
        />
        <StatCard
          title="Targets in Scope"
          value={scans.reduce((acc, s) => acc + (s.target_count || 1), 0)}
          subtitle="Authorized infrastructure"
          icon={<ShieldCheckIcon className="w-4 h-4 text-sky-400" />}
          highlightColor="#0284c7"
        />
      </div>

      {/* Security Posture Gauge + Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Documented Security Score Gauge */}
        <div className="lg:col-span-1">
          <SecurityScoreGauge
            criticalCount={criticalCount}
            highCount={highCount}
            mediumCount={mediumCount}
            lowCount={lowCount}
          />
        </div>

        {/* Severity Distribution & Ratio Bar */}
        <div className="lg:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">
              Vulnerability Severity Breakdown
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              {totalFindings} Active Findings
            </span>
          </div>

          {/* Visual Multi-Segment Bar */}
          <div className="space-y-2">
            <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden flex">
              {totalFindings > 0 ? (
                <>
                  <div
                    style={{ width: `${(criticalCount / totalFindings) * 100}%` }}
                    className="bg-rose-500 h-full"
                    title={`Critical: ${criticalCount}`}
                  />
                  <div
                    style={{ width: `${(highCount / totalFindings) * 100}%` }}
                    className="bg-orange-500 h-full"
                    title={`High: ${highCount}`}
                  />
                  <div
                    style={{ width: `${(mediumCount / totalFindings) * 100}%` }}
                    className="bg-amber-500 h-full"
                    title={`Medium: ${mediumCount}`}
                  />
                  <div
                    style={{ width: `${(lowCount / totalFindings) * 100}%` }}
                    className="bg-sky-500 h-full"
                    title={`Low: ${lowCount}`}
                  />
                </>
              ) : (
                <div className="bg-emerald-500/40 w-full h-full" />
              )}
            </div>

            {/* Severity Legend */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4">
              <div
                onClick={() => navigate("findings", { severity: "critical" })}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 cursor-pointer hover:border-rose-500/40 transition"
              >
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Critical</span>
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                </div>
                <div className="text-xl font-bold font-mono text-rose-400 mt-1">
                  {criticalCount}
                </div>
              </div>

              <div
                onClick={() => navigate("findings", { severity: "high" })}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 cursor-pointer hover:border-orange-500/40 transition"
              >
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>High</span>
                  <span className="w-2 h-2 rounded-full bg-orange-500" />
                </div>
                <div className="text-xl font-bold font-mono text-orange-400 mt-1">
                  {highCount}
                </div>
              </div>

              <div
                onClick={() => navigate("findings", { severity: "medium" })}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 cursor-pointer hover:border-amber-500/40 transition"
              >
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Medium</span>
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                </div>
                <div className="text-xl font-bold font-mono text-amber-400 mt-1">
                  {mediumCount}
                </div>
              </div>

              <div
                onClick={() => navigate("findings", { severity: "low" })}
                className="bg-slate-950/60 border border-slate-800 rounded-lg p-3 cursor-pointer hover:border-sky-500/40 transition"
              >
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>Low</span>
                  <span className="w-2 h-2 rounded-full bg-sky-500" />
                </div>
                <div className="text-xl font-bold font-mono text-sky-400 mt-1">
                  {lowCount}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* OWASP Top 10:2025 Category Coverage Grid */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">
              OWASP Top 10:2025 Category Coverage
            </h3>
            <p className="text-xs text-slate-400">Coverage across active assessments</p>
          </div>
          <button
            type="button"
            onClick={() => navigate("remediation-center")}
            className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 font-medium transition cursor-pointer"
          >
            <span>Browse Remediation Center</span>
            <ArrowRightIcon className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
          {owaspCategories.map((cat) => {
            const count = findings.filter((f) => f.owasp_category.startsWith(cat.id)).length;
            const hasFlaws = count > 0;
            return (
              <div
                key={cat.id}
                onClick={() => navigate("findings", { category: cat.id })}
                className={`p-3 rounded-lg border transition cursor-pointer ${
                  hasFlaws
                    ? "bg-slate-950/80 border-amber-500/30 hover:border-amber-500/60"
                    : "bg-slate-950/40 border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-slate-300">
                    {cat.id}
                  </span>
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      hasFlaws
                        ? "bg-amber-500/20 text-amber-300"
                        : "bg-emerald-500/10 text-emerald-400"
                    }`}
                  >
                    {hasFlaws ? `${count} flaws` : "Pass"}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 truncate" title={cat.name}>
                  {cat.name}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">
              Recent Assessment Sessions
            </h3>
            <p className="text-xs text-slate-400">Live and completed security scans</p>
          </div>
          <button
            type="button"
            onClick={() => navigate("scan-history")}
            className="text-xs text-slate-400 hover:text-slate-200 transition font-medium"
          >
            View All Scans &rarr;
          </button>
        </div>

        {loading ? (
          <LoadingSkeleton count={3} />
        ) : scans.length === 0 ? (
          <EmptyState
            title="No Scans Created"
            message="Configure and launch your first authorized assessment against a target."
            action={
              <button
                type="button"
                onClick={() => navigate("new-scan")}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs tracking-wide transition shadow"
              >
                Start First Scan
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-[10px] font-semibold tracking-wider uppercase text-slate-400 font-mono">
                <tr>
                  <th className="px-5 py-3">Scan Name</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Targets</th>
                  <th className="px-5 py-3">Findings</th>
                  <th className="px-5 py-3">Created</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {scans.slice(0, 5).map((scan) => (
                  <tr
                    key={scan.id}
                    className="hover:bg-slate-800/40 transition cursor-pointer"
                    onClick={() => {
                      if (scan.status === "running") {
                        navigate("live-scan", { scanId: scan.id });
                      } else {
                        navigate("scan-results", { scanId: scan.id });
                      }
                    }}
                  >
                    <td className="px-5 py-3.5 font-medium text-slate-100">
                      {scan.name}
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-5 py-3.5 font-mono text-slate-400">
                      {scan.target_count || 1} target(s)
                    </td>
                    <td className="px-5 py-3.5 font-mono">
                      <span className="text-amber-400 font-semibold">
                        {scan.finding_count ?? 0}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-slate-400">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono">
                      <span className="text-emerald-400 hover:text-emerald-300 font-medium">
                        Open Console &rarr;
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
