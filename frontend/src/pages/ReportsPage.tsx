import { useEffect, useState } from "react";
import { fetchScans } from "../api/scans";
import { createReport, fetchScanReports } from "../api/reports";
import { useNavigation } from "../context/NavigationContext";
import {
  CheckCircleIcon,
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
  const [format, setFormat] = useState<"pdf" | "html" | "json">("pdf");
  const [reportTitle, setReportTitle] = useState("Vulnerability Assessment Report");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  useEffect(() => {
    if (params.scanId && params.scanId !== selectedScanId) {
      setSelectedScanId(params.scanId);
    }
  }, [params.scanId]);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const scansRes = await fetchScans(undefined, 50);
      setScans(scansRes.items || []);

      let targetScanId = selectedScanId;
      if (!targetScanId && scansRes.items?.length > 0) {
        targetScanId = scansRes.items[0].id;
        setSelectedScanId(targetScanId);
      }

      if (targetScanId) {
        const reps = await fetchScanReports(targetScanId);
        setReports(Array.isArray(reps) ? reps : []);
      } else {
        setReports([]);
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
    setSuccessMessage(null);
    try {
      const rep = await createReport(selectedScanId, format, reportTitle);
      setReports((prev) => [rep, ...prev.filter((r) => r.id !== rep.id)]);
      setSuccessMessage(
        `Assessment report deliverable (${format.toUpperCase()}) successfully compiled!`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate report deliverable.");
    } finally {
      setGenerating(false);
    }
  }

  async function handleDownloadReport(report: ReportItem) {
    setDownloadingId(report.id);
    setError(null);
    try {
      const downloadUrl = `/api/v1/reports/${report.id}/download`;
      const response = await fetch(downloadUrl);
      if (!response.ok) {
        throw new Error(`Download failed with status ${response.status}`);
      }
      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      const extension = report.format === "html" ? "html" : report.format === "json" ? "json" : "pdf";
      link.download = report.file_name || `vulnsight-report-${report.id.slice(0, 8)}.${extension}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download report file.");
    } finally {
      setDownloadingId(null);
    }
  }

  function formatBytes(bytes?: number | null): string {
    if (!bytes) return "N/A";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
            Security Assessment Reports & Deliverables
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

      {successMessage && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between text-xs text-emerald-300">
          <div className="flex items-center gap-2.5">
            <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setSuccessMessage(null)}
            className="text-slate-400 hover:text-slate-200 text-xs"
          >
            &times;
          </button>
        </div>
      )}

      {/* Report Generation Form Card */}
      <form onSubmit={handleGenerateReport} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
          <FileTextIcon className="w-4 h-4 text-emerald-400" />
          <span>Compile New Deliverable Report</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Assessment Session
            </label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              {scans.length === 0 ? (
                <option value="">No assessment sessions available</option>
              ) : (
                scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.status}) - {new Date(s.created_at).toLocaleDateString()}
                  </option>
                ))
              )}
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Deliverable Format
            </label>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as "pdf" | "html" | "json")}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="pdf">PDF Deliverable (ReportLab Executive Audit)</option>
              <option value="html">Interactive HTML (Standalone Web Report)</option>
              <option value="json">JSON Audit Log (Machine-Readable Snapshot)</option>
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
              placeholder="e.g. Vulnerability Assessment Report"
            />
          </div>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
          <span className="text-[11px] text-slate-400">
            {format === "pdf" && "PDF includes Executive Summary, Posture Score, OWASP Coverage, Redacted Evidence, and Fix Verifications."}
            {format === "html" && "HTML produces a self-contained responsive report view with embedded CSS."}
            {format === "json" && "JSON produces a raw structured audit snapshot for SIEM/CI integration."}
          </span>

          <button
            type="submit"
            disabled={generating || !selectedScanId}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-slate-950 font-bold text-xs uppercase tracking-wide transition shadow cursor-pointer shrink-0"
          >
            {generating ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Compiling Deliverable...</span>
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
        <div className="p-4 border-b border-slate-800 bg-slate-950/60 font-semibold text-xs text-slate-300 uppercase tracking-wider font-mono flex items-center justify-between">
          <span>Available Deliverables for Selected Session ({reports.length})</span>
          {reports.length > 0 && (
            <span className="text-[11px] font-normal text-slate-400">
              Immutable Snapshots (v1..vN)
            </span>
          )}
        </div>

        {loading ? (
          <LoadingSkeleton count={3} />
        ) : reports.length === 0 ? (
          <EmptyState
            title="No Reports Generated Yet"
            message="Use the compiler form above to compile your first audit-ready report deliverable."
          />
        ) : (
          <div className="divide-y divide-slate-800/60">
            {reports.map((rep) => {
              const isPdf = rep.format === "pdf";
              const isHtml = rep.format === "html";
              return (
                <div key={rep.id} className="p-4 hover:bg-slate-800/30 transition flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-start sm:items-center gap-3">
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                      isPdf
                        ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                        : isHtml
                        ? "bg-sky-500/10 text-sky-400 border border-sky-500/20"
                        : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                    }`}>
                      <FileTextIcon className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-slate-100 flex items-center gap-2 flex-wrap">
                        <span>{rep.file_name || rep.title || "Assessment Deliverable"}</span>
                        <span className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider ${
                          isPdf
                            ? "bg-rose-950/70 text-rose-300 border border-rose-800/50"
                            : isHtml
                            ? "bg-sky-950/70 text-sky-300 border border-sky-800/50"
                            : "bg-amber-950/70 text-amber-300 border border-amber-800/50"
                        }`}>
                          {rep.format}
                        </span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          v{rep.version}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 font-mono mt-0.5 flex items-center gap-3 flex-wrap">
                        <span>Size: {formatBytes(rep.size_bytes)}</span>
                        <span>•</span>
                        <span>Compiled: {new Date(rep.created_at).toLocaleString()}</span>
                        {rep.content_sha256 && (
                          <>
                            <span>•</span>
                            <span title={`SHA-256: ${rep.content_sha256}`}>
                              SHA: {rep.content_sha256.slice(0, 8)}...
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <a
                      href={`/api/v1/reports/${rep.id}/download?disposition=inline`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700/80 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-medium transition cursor-pointer"
                    >
                      <span>Open in Browser</span>
                      <span className="text-[10px] text-slate-400">&nearr;</span>
                    </a>

                    <button
                      type="button"
                      onClick={() => handleDownloadReport(rep)}
                      disabled={downloadingId === rep.id}
                      className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold transition cursor-pointer disabled:opacity-50"
                    >
                      <DownloadIcon className={`w-3.5 h-3.5 ${downloadingId === rep.id ? "animate-bounce" : ""}`} />
                      <span>{downloadingId === rep.id ? "Downloading..." : "Download"}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
