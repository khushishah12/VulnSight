import { useEffect, useState } from "react";
import { fetchScanFindings } from "../api/findings";
import { fetchScans } from "../api/scans";
import { useNavigation } from "../context/NavigationContext";
import {
  SearchIcon,
} from "../components/ui/Icons";
import { SeverityBadge, StatusBadge, RiskScoreBadge } from "../components/ui/Badge";
import { EmptyState, ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import type { FindingSummary, ScanSession } from "../types";

export function FindingsListPage() {
  const { params, navigate } = useNavigation();
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>(params.scanId || "");
  const [selectedSeverity, setSelectedSeverity] = useState<string>(params.severity || "");
  const [selectedCategory, setSelectedCategory] = useState<string>(params.category || "");
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch available scans
      const scansRes = await fetchScans(undefined, 30);
      setScans(scansRes.items);

      let targetScanId = selectedScanId;
      if (!targetScanId && scansRes.items.length > 0) {
        // default to first completed scan or first scan
        const completed = scansRes.items.find((s) => s.status === "completed");
        targetScanId = completed ? completed.id : scansRes.items[0].id;
        setSelectedScanId(targetScanId);
      }

      if (targetScanId) {
        const findingsRes = await fetchScanFindings(targetScanId, {
          severity: selectedSeverity || undefined,
          owasp_category: selectedCategory || undefined,
          limit: 100,
        });
        setFindings(findingsRes.items);
      } else {
        setFindings([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load findings.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [selectedScanId, selectedSeverity, selectedCategory]);

  // Filter client-side by search query
  const filteredFindings = findings.filter((f) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      f.title.toLowerCase().includes(term) ||
      f.check_id.toLowerCase().includes(term) ||
      (f.affected_url && f.affected_url.toLowerCase().includes(term)) ||
      f.owasp_category.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Page Title & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
            Vulnerability Findings
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Standardized technical evidence, transparent risk scores, and remediation states
          </p>
        </div>

        {/* Search input */}
        <div className="relative w-full md:w-72">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by title, check ID, or URL..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 placeholder-slate-500"
          />
          <div className="absolute left-3 top-2.5 text-slate-500">
            <SearchIcon className="w-3.5 h-3.5" />
          </div>
        </div>
      </div>

      {error && <ErrorAlert title="Findings Retrieval Error" message={error} onRetry={loadData} />}

      {/* Filter Row */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center gap-4 text-xs">
        {/* Select Scan */}
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-semibold uppercase text-[10px]">Session:</span>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.status})
              </option>
            ))}
          </select>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-semibold uppercase text-[10px]">Severity:</span>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Informational</option>
          </select>
        </div>

        {/* OWASP Category Filter */}
        <div className="flex items-center gap-2">
          <span className="text-slate-400 font-semibold uppercase text-[10px]">Category:</span>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All OWASP Top 10</option>
            <option value="A01">A01 – Broken Access Control</option>
            <option value="A02">A02 – Security Misconfiguration</option>
            <option value="A03">A03 – Software Supply Chain Failures</option>
            <option value="A04">A04 – Cryptographic Failures</option>
            <option value="A05">A05 – Injection</option>
            <option value="A06">A06 – Insecure Design</option>
            <option value="A07">A07 – Authentication Failures</option>
            <option value="A08">A08 – Software and Data Integrity</option>
            <option value="A09">A09 – Logging & Alerting Failures</option>
            <option value="A10">A10 – Exceptional Conditions</option>
          </select>
        </div>

        {/* Reset Filters button */}
        {(selectedSeverity || selectedCategory || searchTerm) && (
          <button
            type="button"
            onClick={() => {
              setSelectedSeverity("");
              setSelectedCategory("");
              setSearchTerm("");
            }}
            className="text-slate-400 hover:text-slate-200 underline text-xs ml-auto"
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <LoadingSkeleton count={5} />
        ) : filteredFindings.length === 0 ? (
          <EmptyState
            title="No Matching Findings"
            message={
              findings.length === 0
                ? "No vulnerabilities were recorded for this assessment session."
                : "No findings match your filter criteria. Try adjusting your search or category."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-[10px] font-semibold tracking-wider uppercase text-slate-400 font-mono">
                <tr>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3">Category</th>
                  <th className="px-5 py-3">Vulnerability Title</th>
                  <th className="px-5 py-3">Affected URL / Path</th>
                  <th className="px-5 py-3">Risk Score</th>
                  <th className="px-5 py-3">Workflow State</th>
                  <th className="px-5 py-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => navigate("finding-detail", { findingId: finding.id })}
                    className="hover:bg-slate-800/40 transition cursor-pointer"
                  >
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-5 py-3.5 font-mono text-emerald-400 font-semibold">
                      {finding.owasp_category}
                    </td>
                    <td className="px-5 py-3.5 font-medium text-slate-100 max-w-xs truncate" title={finding.title}>
                      {finding.title}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-slate-400 max-w-xs truncate" title={finding.affected_url || "Target Scope"}>
                      {finding.affected_url || "General Target Scope"}
                    </td>
                    <td className="px-5 py-3.5">
                      <RiskScoreBadge score={finding.risk_score} />
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={finding.remediation_status || finding.status} />
                    </td>
                    <td className="px-5 py-3.5 text-right font-mono">
                      <span className="text-emerald-400 hover:text-emerald-300 font-medium">
                        Inspect &rarr;
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
