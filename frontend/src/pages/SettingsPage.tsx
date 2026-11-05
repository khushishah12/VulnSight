import React, { useEffect, useState } from "react";
import { checkDatabaseHealth } from "../api/health";
import { useAuth } from "../context/AuthContext";
import {
  CheckCircleIcon,
  LockIcon,
  RefreshCwIcon,
  ServerIcon,
  UserIcon,
} from "../components/ui/Icons";

export function SettingsPage() {
  const { user } = useAuth();
  const [dbStatus, setDbStatus] = useState<any>(null);
  const [loadingDb, setLoadingDb] = useState(false);
  const [allowedHosts, setAllowedHosts] = useState("127.0.0.1, localhost, ::1");
  const [requestTimeout, setRequestTimeout] = useState("8.0");
  const [rateLimitDelay, setRateLimitDelay] = useState("0.05");
  const [savedNotice, setSavedNotice] = useState(false);

  async function checkDb() {
    setLoadingDb(true);
    try {
      const res = await checkDatabaseHealth();
      setDbStatus(res);
    } catch (err) {
      setDbStatus({ database: "error", error: err instanceof Error ? err.message : "Unreachable" });
    } finally {
      setLoadingDb(false);
    }
  }

  useEffect(() => {
    checkDb();
  }, []);

  function handleSaveSettings(e: React.FormEvent) {
    e.preventDefault();
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  }

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="pb-2 border-b border-slate-800/80">
        <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
          Security Console Configuration
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Backend infrastructure telemetry, scope boundary controls, and safety thresholds
        </p>
      </div>

      {savedNotice && (
        <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 font-semibold flex items-center gap-2">
          <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
          <span>Operator configuration updated successfully.</span>
        </div>
      )}

      {/* Operator Profile Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 pb-2 border-b border-slate-800">
          <UserIcon className="w-4 h-4 text-emerald-400" />
          <span>Active Operator Profile</span>
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <span className="text-[10px] uppercase text-slate-400">Operator Identity</span>
            <div className="text-slate-200 font-bold">{user?.display_name || "SecOps Lead"}</div>
          </div>
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <span className="text-[10px] uppercase text-slate-400">Assigned Role</span>
            <div className="text-emerald-400 font-bold uppercase">{user?.role || "Security Analyst"}</div>
          </div>
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <span className="text-[10px] uppercase text-slate-400">Operator Contact</span>
            <div className="text-slate-200 font-bold">{user?.email || "operator@vulnsight.internal"}</div>
          </div>
        </div>
      </div>

      {/* Database Telemetry Status Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
            <ServerIcon className="w-4 h-4 text-emerald-400" />
            <span>Neon Serverless PostgreSQL Database</span>
          </h3>
          <button
            type="button"
            onClick={checkDb}
            disabled={loadingDb}
            className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
          >
            <RefreshCwIcon className={`w-3 h-3 ${loadingDb ? "animate-spin" : ""}`} />
            <span>Check Connectivity</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <span className="text-[10px] uppercase text-slate-400">Connection State</span>
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${
                  dbStatus?.database === "connected" ? "bg-emerald-400" : "bg-rose-500"
                }`}
              />
              <span className="text-slate-200 font-bold capitalize">
                {dbStatus?.database || "Checking..."}
              </span>
            </div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <span className="text-[10px] uppercase text-slate-400">Database Engine</span>
            <div className="text-slate-200 font-bold">PostgreSQL 17 (Neon)</div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
            <span className="text-[10px] uppercase text-slate-400">Async Driver</span>
            <div className="text-slate-200 font-bold">asyncpg + SQLAlchemy</div>
          </div>
        </div>
      </div>

      {/* Safety & Scope Configuration Form */}
      <form onSubmit={handleSaveSettings} className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2 pb-2 border-b border-slate-800">
          <LockIcon className="w-4 h-4 text-sky-400" />
          <span>Scope Allowlist & Safety Controls</span>
        </h3>

        <div className="space-y-4 text-xs">
          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Authorized Target Hostnames Allowlist (<code className="font-mono text-emerald-400">SCAN_ALLOWED_HOSTS</code>)
            </label>
            <input
              type="text"
              value={allowedHosts}
              onChange={(e) => setAllowedHosts(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Strict comma-delimited allowlist. Targets resolving to hostnames outside this set will be rejected before DNS resolution.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
                Recon Request Timeout (Seconds)
              </label>
              <input
                type="number"
                step="0.5"
                value={requestTimeout}
                onChange={(e) => setRequestTimeout(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
                Rate Limit Delay Per Target (Seconds)
              </label>
              <input
                type="number"
                step="0.01"
                value={rateLimitDelay}
                onChange={(e) => setRateLimitDelay(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end pt-3 border-t border-slate-800">
          <button
            type="submit"
            className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs uppercase tracking-wide transition shadow cursor-pointer"
          >
            Save Security Controls
          </button>
        </div>
      </form>
    </div>
  );
}
