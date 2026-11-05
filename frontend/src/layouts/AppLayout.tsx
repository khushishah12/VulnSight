import { Fragment, type ReactNode, useEffect, useState } from "react";
import { checkDatabaseHealth } from "../api/health";
import { useAuth } from "../context/AuthContext";
import type { AppRoute } from "../context/NavigationContext";
import { useNavigation } from "../context/NavigationContext";
import {
  ActivityIcon,
  ChevronRightIcon,
  CompassIcon,
  FileTextIcon,
  LayersIcon,
  PlayIcon,
  ServerIcon,
  ShieldCheckIcon,
  ShieldIcon,
  SlidersIcon,
  UserIcon,
} from "../components/ui/Icons";

interface NavItem {
  id: AppRoute;
  label: string;
  icon: ReactNode;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: <ActivityIcon className="w-4 h-4" /> },
  { id: "new-scan", label: "New Scan", icon: <PlayIcon className="w-4 h-4 text-emerald-400" /> },
  { id: "scan-history", label: "Scan History", icon: <LayersIcon className="w-4 h-4" /> },
  { id: "findings", label: "Findings", icon: <ShieldIcon className="w-4 h-4 text-amber-400" /> },
  { id: "remediation-center", label: "Remediation", icon: <CompassIcon className="w-4 h-4 text-sky-400" /> },
  { id: "verification-history", label: "Fix Verification", icon: <ShieldCheckIcon className="w-4 h-4 text-teal-400" /> },
  { id: "reports", label: "Reports", icon: <FileTextIcon className="w-4 h-4" /> },
  { id: "settings", label: "Settings", icon: <SlidersIcon className="w-4 h-4" /> },
];

export function AppLayout({ children }: { children: React.ReactNode }) {
  const { currentRoute, navigate, breadcrumbs } = useNavigation();
  const { user } = useAuth();
  const [dbHealthy, setDbHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function checkHealth() {
      try {
        const res = await checkDatabaseHealth();
        if (isMounted) setDbHealthy(res.database === "connected");
      } catch {
        if (isMounted) setDbHealthy(false);
      }
    }
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // For landing and login pages, provide full-width unconstrained view
  if (currentRoute === "landing") {
    return <div className="min-h-screen bg-slate-950 text-slate-100">{children}</div>;
  }

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0">
        <div>
          {/* Brand Header */}
          <div
            onClick={() => navigate("dashboard")}
            className="p-5 border-b border-slate-800 flex items-center gap-3 cursor-pointer hover:bg-slate-800/40 transition"
          >
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-inner">
              <ShieldCheckIcon className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-wider uppercase text-slate-100">
                  VulnSight
                </span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                  v0.1
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Security Engine</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            <div className="px-3 py-2 text-[10px] font-semibold tracking-wider uppercase text-slate-400 font-mono">
              Operations
            </div>
            {NAV_ITEMS.map((item) => {
              const isActive = currentRoute === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigate(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition cursor-pointer ${
                    isActive
                      ? "bg-emerald-500/10 text-emerald-300 font-semibold border border-emerald-500/20"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    {item.icon}
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-slate-800 space-y-3 bg-slate-900/60">
          {/* Neon Database Status */}
          <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-slate-950/60 border border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <ServerIcon className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-300 text-[11px]">Neon DB</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  dbHealthy === true
                    ? "bg-emerald-400 animate-pulse"
                    : dbHealthy === false
                    ? "bg-rose-400"
                    : "bg-amber-400"
                }`}
              />
              <span className="text-[10px] font-mono text-slate-400">
                {dbHealthy === true ? "Online" : dbHealthy === false ? "Offline" : "Checking"}
              </span>
            </div>
          </div>

          {/* Quick links to Landing / Login */}
          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
            <button
              type="button"
              onClick={() => navigate("landing")}
              className="hover:text-slate-200 transition underline underline-offset-2"
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => navigate("login")}
              className="hover:text-slate-200 transition underline underline-offset-2"
            >
              {user ? "Switch User" : "Sign In"}
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 flex items-center justify-between shrink-0">
          {/* Breadcrumbs */}
          <div className="flex items-center gap-2 text-xs">
            {breadcrumbs.map((crumb, idx) => (
              <Fragment key={idx}>
                {idx > 0 && <ChevronRightIcon className="w-3.5 h-3.5 text-slate-400" />}
                {crumb.route ? (
                  <button
                    type="button"
                    onClick={() => navigate(crumb.route!, crumb.params)}
                    className="text-slate-400 hover:text-slate-200 transition font-medium"
                  >
                    {crumb.label}
                  </button>
                ) : (
                  <span className="text-slate-200 font-semibold">{crumb.label}</span>
                )}
              </Fragment>
            ))}
          </div>

          {/* Right Header Actions */}
          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => navigate("new-scan")}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs tracking-wide transition shadow-sm"
            >
              <PlayIcon className="w-3.5 h-3.5" />
              <span>Launch Scan</span>
            </button>

            {/* Operator Menu */}
            <div className="flex items-center gap-2 pl-2 border-l border-slate-800 text-xs">
              <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
                <UserIcon className="w-4 h-4" />
              </div>
              <div className="hidden sm:block text-left leading-tight">
                <div className="font-semibold text-slate-200">{user?.display_name || "Operator"}</div>
                <div className="text-[10px] text-slate-400">{user?.role || "Security Analyst"}</div>
              </div>
            </div>
          </div>
        </header>

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
          <div className="max-w-7xl mx-auto">{children}</div>
        </main>
      </div>
    </div>
  );
}
