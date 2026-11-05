import type { Confidence, FindingStatus, Severity } from "../../types";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const sev = severity.toLowerCase();
  let color = "bg-slate-500/10 text-slate-400 border-slate-700/50";

  if (sev === "critical") {
    color = "bg-rose-500/10 text-rose-400 border-rose-500/30 font-semibold";
  } else if (sev === "high") {
    color = "bg-orange-500/10 text-orange-400 border-orange-500/30 font-semibold";
  } else if (sev === "medium") {
    color = "bg-amber-500/10 text-amber-400 border-amber-500/30";
  } else if (sev === "low") {
    color = "bg-sky-500/10 text-sky-400 border-sky-500/30";
  } else if (sev === "info") {
    color = "bg-slate-500/10 text-slate-400 border-slate-700/50";
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs tracking-wider uppercase border ${color}`}
    >
      {sev}
    </span>
  );
}

export function StatusBadge({ status }: { status: FindingStatus | string }) {
  const st = status.toLowerCase();
  let color = "bg-slate-500/10 text-slate-400 border-slate-700/40";
  let label = st;

  if (st === "open") {
    color = "bg-rose-500/10 text-rose-400 border-rose-500/30";
  } else if (st === "in_progress") {
    color = "bg-amber-500/10 text-amber-400 border-amber-500/30";
    label = "in progress";
  } else if (st === "remediated" || st === "done") {
    color = "bg-teal-500/10 text-teal-400 border-teal-500/30";
    label = "remediated";
  } else if (st === "verified") {
    color = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 font-semibold";
    label = "verified fix";
  } else if (st === "accepted_risk") {
    color = "bg-purple-500/10 text-purple-400 border-purple-500/30";
    label = "accepted risk";
  } else if (st === "completed" || st === "passed") {
    color = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  } else if (st === "running" || st === "pending") {
    color = "bg-sky-500/10 text-sky-400 border-sky-500/30 animate-pulse";
  } else if (st === "failed" || st === "error") {
    color = "bg-rose-500/10 text-rose-400 border-rose-500/30";
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${color}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {label}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence | string }) {
  const conf = confidence.toLowerCase();
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono text-slate-400 bg-slate-800/80 border border-slate-700">
      {conf} confidence
    </span>
  );
}

export function RiskScoreBadge({ score }: { score: number }) {
  let color = "bg-slate-800 text-slate-300 border-slate-700";
  if (score >= 9.0) {
    color = "bg-rose-950/60 text-rose-300 border-rose-500/40";
  } else if (score >= 7.0) {
    color = "bg-orange-950/60 text-orange-300 border-orange-500/40";
  } else if (score >= 4.0) {
    color = "bg-amber-950/60 text-amber-300 border-amber-500/40";
  } else if (score >= 1.0) {
    color = "bg-sky-950/60 text-sky-300 border-sky-500/40";
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded font-mono font-semibold text-xs border ${color}`}
    >
      Risk {score.toFixed(1)}
    </span>
  );
}
