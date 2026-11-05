import React, { useState } from "react";
import { createScan, startScan } from "../api/scans";
import { useNavigation } from "../context/NavigationContext";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  LockIcon,
  PlayIcon,
  ShieldCheckIcon,
} from "../components/ui/Icons";
import { ErrorAlert } from "../components/ui/Feedback";

export function NewScanPage() {
  const { navigate } = useNavigation();
  const [scanName, setScanName] = useState(`Scan-${new Date().toISOString().slice(0, 10)}`);
  const [targetUrl, setTargetUrl] = useState("http://localhost:3000/");
  const [profile, setProfile] = useState("lean_mvp");
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Client-side quick target syntax validation
  function isValidUrl(string: string) {
    try {
      const parsed = new URL(string);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
      return false;
    }
  }

  const validUrl = isValidUrl(targetUrl);

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault();
    if (!validUrl) {
      setError("Please enter a valid HTTP or HTTPS target URL.");
      return;
    }
    if (!isAuthorized) {
      setError("You must confirm you have explicit authorization to scan this target.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      // 1. Create scan session with target
      const scan = await createScan(scanName, targetUrl.trim(), profile);

      // 2. Trigger scan execution
      await startScan(scan.id);

      // 3. Navigate to live progress page
      navigate("live-scan", { scanId: scan.id });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to launch security scan.");
      setLoading(false);
    }
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Page Title */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
          New Security Assessment
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Configure an authorized target, declare scope boundaries, and launch detection
        </p>
      </div>

      {error && <ErrorAlert title="Launch Blocked" message={error} />}

      <form onSubmit={handleLaunch} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
        {/* Scan Details */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 pb-2 border-b border-slate-800">
            1. Assessment Session Configuration
          </h3>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
              Assessment Name
            </label>
            <input
              type="text"
              required
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 font-mono"
              placeholder="e.g. Q4 Staging OWASP Scan"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
              Assessment Profile
            </label>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
            >
              <option value="lean_mvp">Lean MVP – Reconnaissance + OWASP Top 10:2025</option>
            </select>
            <p className="text-[11px] text-slate-500 mt-1">
              Executes safe, non-destructive checks across all 10 OWASP categories with rate limiting.
            </p>
          </div>
        </div>

        {/* Target Scope */}
        <div className="space-y-4 pt-2">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300 pb-2 border-b border-slate-800">
            2. Authorized Target Scope
          </h3>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
              Primary Target URL
            </label>
            <div className="relative">
              <input
                type="url"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className={`w-full bg-slate-950 border rounded-lg px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none font-mono ${
                  validUrl
                    ? "border-emerald-500/50 focus:border-emerald-500"
                    : "border-rose-500/50 focus:border-rose-500"
                }`}
                placeholder="http://localhost:3000/ or https://app.example.com/"
              />
              <div className="absolute right-3 top-2.5">
                {validUrl ? (
                  <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
                ) : (
                  <AlertTriangleIcon className="w-4 h-4 text-rose-400" />
                )}
              </div>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              Target hostnames must be in the backend allowlist (e.g. <code className="text-slate-400">localhost</code>, <code className="text-slate-400">127.0.0.1</code>).
            </p>
          </div>

          {/* Scope & Non-Destructive Declarations */}
          <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 space-y-3 text-xs text-slate-400">
            <div className="flex items-start gap-2 text-slate-300">
              <ShieldCheckIcon className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>
                <strong>Non-Destructive Guarantee:</strong> VulnSight never executes denial-of-service,
                payload execution, data destruction, brute forcing, or unauthorized privilege escalation.
              </span>
            </div>
            <div className="flex items-start gap-2 text-slate-300">
              <LockIcon className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
              <span>
                <strong>SSRF & Network Isolation:</strong> Private, link-local, and cloud metadata
                IP ranges (169.254.169.254) are strictly blocked by default.
              </span>
            </div>
          </div>

          {/* Authorization Checkbox */}
          <label className="flex items-start gap-3 p-3 bg-slate-950/80 border border-slate-800 rounded-lg cursor-pointer hover:border-slate-700 transition">
            <input
              type="checkbox"
              checked={isAuthorized}
              onChange={(e) => setIsAuthorized(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 text-emerald-600 focus:ring-0"
            />
            <span className="text-xs text-slate-300 select-none">
              I certify that I am the owner or possess explicit, written legal authorization to perform
              security assessments against this target domain and infrastructure.
            </span>
          </label>
        </div>

        {/* Action Controls */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
          <button
            type="button"
            onClick={() => navigate("dashboard")}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading || !validUrl || !isAuthorized}
            className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 font-bold text-xs tracking-wide uppercase transition shadow-lg cursor-pointer"
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Launching...</span>
              </>
            ) : (
              <>
                <PlayIcon className="w-3.5 h-3.5" />
                <span>Launch Assessment</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
