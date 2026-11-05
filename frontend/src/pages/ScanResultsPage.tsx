import { useEffect, useState } from "react";
import { fetchScan, fetchScanEndpoints } from "../api/scans";
import { fetchScanFindings } from "../api/findings";
import { useNavigation } from "../context/NavigationContext";
import {
  AlertTriangleIcon,
  ArrowRightIcon,
  CheckCircleIcon,
  FileTextIcon,
  LayersIcon,
  ShieldIcon,
} from "../components/ui/Icons";
import { StatusBadge, SeverityBadge } from "../components/ui/Badge";
import { SecurityScoreGauge } from "../components/ui/SecurityScoreGauge";
import { StatCard } from "../components/ui/StatCard";
import { ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import type { DiscoveredEndpoint, FindingSummary, ScanSession } from "../types";

export function ScanResultsPage() {
  const { params, navigate } = useNavigation();
  const scanId = params.scanId;

  const [scan, setScan] = useState<ScanSession | null>(null);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;

    async function loadScanData() {
      setLoading(true);
      setError(null);
      try {
        const [scanData, findingsRes, endpointsData] = await Promise.all([
          fetchScan(scanId!),
          fetchScanFindings(scanId!, { limit: 100 }),
          fetchScanEndpoints(scanId!),
        ]);
        setScan(scanData);
        setFindings(findingsRes.items);
        setEndpoints(endpointsData);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load scan results.");
      } finally {
        setLoading(false);
      }
    }

    loadScanData();
  }, [scanId]);

  if (loading) return <LoadingSkeleton count={4} />;
  if (error || !scan) return <ErrorAlert title="Scan Results Error" message={error || "Scan not found."} />;

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;

  return (
    <div className="space-y-6">
      {/* Executive Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
              {scan.name}
            </h1>
            <StatusBadge status={scan.status} />
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Target: {scan.targets?.[0]?.url || "Authorized Scope"} | Profile: {scan.profile}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => navigate("reports", { scanId: scan.id })}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 hover:bg-slate-800 text-xs font-medium transition cursor-pointer"
          >
            <FileTextIcon className="w-3.5 h-3.5 text-slate-400" />
            <span>Export Report</span>
          </button>
          <button
            type="button"
            onClick={() => navigate("findings", { scanId: scan.id })}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs tracking-wide transition shadow-sm cursor-pointer"
          >
            <ShieldIcon className="w-3.5 h-3.5" />
            <span>Inspect All Findings ({findings.length})</span>
          </button>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Discovered Weaknesses"
          value={findings.length}
          subtitle="OWASP Top 10:2025"
          icon={<AlertTriangleIcon className="w-4 h-4 text-amber-400" />}
          highlightColor="#f59e0b"
        />
        <StatCard
          title="Critical / High"
          value={criticalCount + highCount}
          subtitle="Immediate remediation"
          icon={<ShieldIcon className="w-4 h-4 text-rose-400" />}
          highlightColor="#f43f5e"
        />
        <StatCard
          title="Discovered Endpoints"
          value={endpoints.length}
          subtitle="Reconnaissance crawl"
          icon={<LayersIcon className="w-4 h-4 text-sky-400" />}
          highlightColor="#0284c7"
        />
        <StatCard
          title="Scan Timing"
          value={scan.finished_at ? "Completed" : "Running"}
          subtitle={new Date(scan.created_at).toLocaleTimeString()}
          icon={<CheckCircleIcon className="w-4 h-4 text-emerald-400" />}
          highlightColor="#10b981"
        />
      </div>

      {/* Posture Score & Vulnerability Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <SecurityScoreGauge
            criticalCount={criticalCount}
            highCount={highCount}
            mediumCount={mediumCount}
            lowCount={lowCount}
          />
        </div>

        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">
              Top Findings In This Session
            </h3>
            <button
              type="button"
              onClick={() => navigate("findings", { scanId: scan.id })}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium"
            >
              See all {findings.length} &rarr;
            </button>
          </div>

          {findings.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-400">
              No vulnerabilities detected on this target.
            </div>
          ) : (
            <div className="space-y-2">
              {findings.slice(0, 4).map((f) => (
                <div
                  key={f.id}
                  onClick={() => navigate("finding-detail", { findingId: f.id })}
                  className="p-3 bg-slate-950/70 border border-slate-800 hover:border-slate-700 rounded-lg flex items-center justify-between transition cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={f.severity} />
                    <div>
                      <div className="text-xs font-semibold text-slate-200">{f.title}</div>
                      <div className="text-[11px] text-slate-400 font-mono">
                        {f.check_id} | {f.affected_url || "General Target Scope"}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-slate-300">
                      Score {f.risk_score}
                    </span>
                    <ArrowRightIcon className="w-3.5 h-3.5 text-slate-400" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Discovered Endpoints Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">
              Reconnaissance Endpoint Inventory
            </h3>
            <p className="text-xs text-slate-400">
              {endpoints.length} endpoints collected during safe URL discovery
            </p>
          </div>
        </div>

        {endpoints.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No endpoints were discovered for this target.
          </div>
        ) : (
          <div className="overflow-x-auto max-h-72">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 sticky top-0 border-b border-slate-800 text-[10px] font-semibold tracking-wider uppercase text-slate-400 font-mono">
                <tr>
                  <th className="px-5 py-3">Method</th>
                  <th className="px-5 py-3">Path</th>
                  <th className="px-5 py-3">HTTP Status</th>
                  <th className="px-5 py-3">Content Type</th>
                  <th className="px-5 py-3">Discovered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {endpoints.slice(0, 20).map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-800/40 transition">
                    <td className="px-5 py-2.5 font-mono font-semibold text-emerald-400">
                      {ep.method}
                    </td>
                    <td className="px-5 py-2.5 font-mono text-slate-200">
                      {ep.path}
                    </td>
                    <td className="px-5 py-2.5 font-mono">
                      <span className={`px-2 py-0.5 rounded text-[11px] ${
                        ep.status_code && ep.status_code < 400
                          ? "bg-emerald-500/10 text-emerald-400"
                          : "bg-amber-500/10 text-amber-400"
                      }`}>
                        {ep.status_code || "N/A"}
                      </span>
                    </td>
                    <td className="px-5 py-2.5 font-mono text-slate-400">
                      {ep.content_type || "text/html"}
                    </td>
                    <td className="px-5 py-2.5 text-slate-400">
                      {new Date(ep.discovered_at).toLocaleTimeString()}
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
