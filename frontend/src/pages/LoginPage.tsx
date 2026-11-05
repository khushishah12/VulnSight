import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useNavigation } from "../context/NavigationContext";
import { ShieldCheckIcon } from "../components/ui/Icons";

export function LoginPage() {
  const { login, user } = useAuth();
  const { navigate } = useNavigation();
  const [email, setEmail] = useState(user?.email || "secops@vulnsight.internal");
  const [displayName, setDisplayName] = useState(user?.display_name || "Lead Security Engineer");
  const [role, setRole] = useState(user?.role || "Security Analyst");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    login(email, displayName, role);
    navigate("dashboard");
  }

  return (
    <div className="max-w-md mx-auto my-12 bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
          <ShieldCheckIcon className="w-6 h-6" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-slate-100 tracking-wide uppercase">
            Operator Console Access
          </h2>
          <p className="text-xs text-slate-400">Authenticate session or switch analyst profile</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
            Operator Email
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 transition"
            placeholder="analyst@organization.internal"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
            Display Name
          </label>
          <input
            type="text"
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 transition"
            placeholder="Analyst Name"
          />
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">
            Security Role
          </label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500 transition"
          >
            <option value="Lead Security Engineer">Lead Security Engineer</option>
            <option value="Security Analyst">Security Analyst</option>
            <option value="DevSecOps Lead">DevSecOps Lead</option>
            <option value="Read-Only Auditor">Read-Only Auditor</option>
          </select>
        </div>

        <div className="pt-2">
          <button
            type="submit"
            className="w-full py-2.5 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs tracking-wider uppercase transition shadow-md cursor-pointer"
          >
            Authenticate & Open Console
          </button>
        </div>
      </form>

      <div className="mt-6 pt-4 border-t border-slate-800/80 text-center text-xs text-slate-500">
        Local Assessment Mode: Access is logged to PostgreSQL <code className="font-mono text-slate-400">audit_logs</code>.
      </div>
    </div>
  );
}
