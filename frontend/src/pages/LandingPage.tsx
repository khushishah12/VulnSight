import { useNavigation } from "../context/NavigationContext";
import {
  ActivityIcon,
  ArrowRightIcon,
  CompassIcon,
  LockIcon,
  PlayIcon,
  ShieldCheckIcon,
  ShieldIcon,
} from "../components/ui/Icons";

export function LandingPage() {
  const { navigate } = useNavigation();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 px-8 py-4 bg-slate-900/60 backdrop-blur flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <ShieldCheckIcon className="w-5 h-5" />
          </div>
          <div>
            <span className="font-extrabold text-base tracking-wider uppercase">VulnSight</span>
            <span className="ml-2 text-xs font-mono text-emerald-400">OWASP Top 10:2025</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={() => navigate("login")}
            className="text-xs text-slate-400 hover:text-slate-200 transition"
          >
            Operator Sign In
          </button>
          <button
            type="button"
            onClick={() => navigate("dashboard")}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs tracking-wide transition shadow"
          >
            <span>Launch Console</span>
            <ArrowRightIcon className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-6xl mx-auto px-6 py-16 flex-1 flex flex-col justify-center text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300 font-mono mx-auto mb-6">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Enterprise Non-Destructive Vulnerability Assessment & Remediation
        </div>

        <h1 className="text-4xl md:text-6xl font-extrabold text-slate-100 tracking-tight leading-tight max-w-4xl mx-auto">
          Intelligent Web Application Security & Automated Remediation
        </h1>

        <p className="text-slate-400 text-base md:text-lg max-w-2xl mx-auto mt-6 leading-relaxed">
          Comprehensive reconnaissance, full OWASP Top 10:2025 detection, transparent risk scoring,
          and multi-framework remediation guidance powered by Neon Serverless PostgreSQL and FastAPI.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4 mt-8">
          <button
            type="button"
            onClick={() => navigate("new-scan")}
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-sm tracking-wide transition shadow-lg cursor-pointer"
          >
            <PlayIcon className="w-4 h-4" />
            <span>Start Vulnerability Scan</span>
          </button>
          <button
            type="button"
            onClick={() => navigate("dashboard")}
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 font-semibold text-sm tracking-wide transition cursor-pointer"
          >
            <ActivityIcon className="w-4 h-4 text-emerald-400" />
            <span>Open Security Dashboard</span>
          </button>
        </div>

        {/* Feature Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-20 text-left">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mb-4">
              <ShieldIcon className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-100 text-base mb-2">
              OWASP Top 10:2025 Engine
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Modular scanners covering Broken Access Control, Injection, Cryptographic Failures,
              Supply Chain risks, Insecure Design, and Exceptional Conditions.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
            <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 mb-4">
              <CompassIcon className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-100 text-base mb-2">
              Remediation Center
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Multi-framework vulnerable vs. secure code snippets for Node.js, Express, Python FastAPI,
              Django, Java Spring Boot, and SQL with automated fix verification.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 mb-4">
              <LockIcon className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-100 text-base mb-2">
              Strict Non-Destructive Safety
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              SSRF blocking, private IP protection, rate-limiting, and automatic sensitive data
              redaction ensuring chain-of-custody cryptographic evidence integrity.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 px-8 py-6 text-xs text-slate-400 flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          VulnSight Security Operations Platform &copy; 2026. Built with React, FastAPI & Neon PostgreSQL.
        </div>
        <div className="flex items-center gap-6">
          <span className="font-mono text-emerald-400">PostgreSQL Schema Migrated (Head)</span>
          <button
            type="button"
            onClick={() => navigate("remediation-center")}
            className="hover:text-slate-200 transition"
          >
            Remediation Encyclopedia
          </button>
        </div>
      </footer>
    </div>
  );
}
