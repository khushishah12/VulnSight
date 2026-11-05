import { useEffect, useState } from "react";
import { fetchScans } from "../api/scans";
import { createReport, fetchScanReports } from "../api/reports";
import { useNavigation } from "../context/NavigationContext";
import {
  DownloadIcon,
  FileTextIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
} from "../components/ui/Icons";
import { ErrorAlert, LoadingSkeleton, EmptyState } from "../components/ui/Feedback";
import type { ReportItem, ScanSession } from "../types";

export function ReportsPage() {
  const { params } = useNavigation();
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>(params.scanId || "");
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [generating, setGenerating] = useState(false);
  const [version, setVersion] = useState("1.0");
  const [reportTitle, setReportTitle] = useState("Vulnerability Assessment Report");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const scansRes = await fetchScans("completed", 30);
      setScans(scansRes.items);

      let targetScanId = selectedScanId;
      if (!targetScanId && scansRes.items.length > 0) {
        targetScanId = scansRes.items[0].id;
        setSelectedScanId(targetScanId);
      }

      if (targetScanId) {
        const reps = await fetchScanReports(targetScanId);
        setReports(reps);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [selectedScanId]);

  async function handleGenerateReport(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedScanId) return;
    setGenerating(true);
    setError(null);
    try {
      const rep = await createReport(selectedScanId, reportTitle, version);
      setReports((prev) => [rep, ...prev]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate report.");
    } finally {
      setGenerating(false);
    }
  }

  function handleDownloadReport(report: ReportItem) {
    // Direct browser download via FastAPI report download endpoint
    const downloadUrl = `/api/v1/reports/${report.id}/download`;
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = `vulnsight-report-${report.id.slice(0, 8)}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
            Security Assessment Reports
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit-ready deliverables, executive posture summaries, and remediation tracking
          </p>
        </div>

        <button
          type="button"
          onClick={loadData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 text-xs font-medium transition cursor-pointer"
        >
          <RefreshCwIcon className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && <ErrorAlert title="Report Center Error" message={error} />}

      {/* Report Generation Form Card */}
      <form onSubmit={handleGenerateReport} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
          <FileTextIcon className="w-4 h-4 text-emerald-400" />
          <span>Compile New Deliverable Report</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Select Assessment Session
            </label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({new Date(s.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Report Title
            </label>
            <input
              type="text"
              required
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              placeholder="e.g. Executive Vulnerability Assessment"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Report Version
            </label>
            <select
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="1.0">v1.0 (Initial Assessment)</option>
              <option value="1.1">v1.1 (Post-Remediation Verification)</option>
              <option value="2.0">v2.0 (Executive Board Presentation)</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-end pt-2">
          <button
            type="submit"
            disabled={generating || !selectedScanId}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-slate-950 font-bold text-xs uppercase tracking-wide transition shadow cursor-pointer"
          >
            {generating ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Compiling Report...</span>
              </>
            ) : (
              <>
                <ShieldCheckIcon className="w-4 h-4" />
                <span>Generate Assessment Deliverable</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Generated Reports List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 bg-slate-950/60 font-semibold text-xs text-slate-300 uppercase tracking-wider font-mono">
          Available Deliverables for Selected Session ({reports.length})
        </div>

        {loading ? (
          <LoadingSkeleton count={3} />
        ) : reports.length === 0 ? (
          <EmptyState
            title="No Reports Generated Yet"
            message="Use the compiler form above to generate your first audit-ready report deliverable."
          />
        ) : (
          <div className="divide-y divide-slate-800/60">
            {reports.map((rep) => (
              <div key={rep.id} className="p-4 hover:bg-slate-800/30 transition flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-slate-300">
                    <FileTextIcon className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                      <span>{rep.title}</span>
                      <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                        v{rep.version}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">
                      Report ID: {rep.id} | Compiled: {new Date(rep.created_at).toLocaleString()}
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => handleDownloadReport(rep)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition cursor-pointer"
                >
                  <DownloadIcon className="w-3.5 h-3.5" />
                  <span>Download Deliverable</span>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
