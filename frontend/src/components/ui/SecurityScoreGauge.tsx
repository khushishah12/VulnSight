import { useState } from "react";
import { ShieldCheckIcon, ShieldAlertIcon } from "./Icons";

interface SecurityScoreGaugeProps {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export function calculateSecurityScore(
  critical: number,
  high: number,
  medium: number,
  low: number,
): { score: number; grade: string; rating: string; penalty: number } {
  // Deductions: 15 per Critical, 8 per High, 3 per Medium, 1 per Low
  const penalty = critical * 15 + high * 8 + medium * 3 + low * 1;
  const score = Math.max(0, Math.min(100, 100 - penalty));

  let grade = "A+";
  let rating = "Superior";

  if (score >= 95) {
    grade = "A+";
    rating = "Exceptional Posture";
  } else if (score >= 85) {
    grade = "A";
    rating = "Strong Posture";
  } else if (score >= 70) {
    grade = "B";
    rating = "Acceptable Posture";
  } else if (score >= 55) {
    grade = "C";
    rating = "Elevated Risk";
  } else if (score >= 40) {
    grade = "D";
    rating = "High Exposure";
  } else {
    grade = "F";
    rating = "Critical Exposure";
  }

  return { score, grade, rating, penalty };
}

export function SecurityScoreGauge({
  criticalCount,
  highCount,
  mediumCount,
  lowCount,
}: SecurityScoreGaugeProps) {
  const [showFormula, setShowFormula] = useState(false);
  const { score, grade, rating, penalty } = calculateSecurityScore(
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
  );

  let ringColor = "text-emerald-500";
  let badgeColor = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";

  if (score < 55) {
    ringColor = "text-rose-500";
    badgeColor = "bg-rose-500/10 text-rose-400 border-rose-500/30";
  } else if (score < 75) {
    ringColor = "text-amber-500";
    badgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/30";
  } else if (score < 90) {
    ringColor = "text-sky-500";
    badgeColor = "bg-sky-500/10 text-sky-400 border-sky-500/30";
  }

  // Circular gauge circumference for r=42 is ~264
  const circumference = 2 * Math.PI * 42;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg relative flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          {score >= 80 ? (
            <ShieldCheckIcon className="w-5 h-5 text-emerald-400" />
          ) : (
            <ShieldAlertIcon className="w-5 h-5 text-amber-400" />
          )}
          <h3 className="font-semibold text-slate-100 text-sm tracking-wide uppercase">
            Security Posture Score
          </h3>
        </div>
        <button
          type="button"
          onClick={() => setShowFormula(!showFormula)}
          className="text-xs text-slate-400 hover:text-slate-200 transition underline underline-offset-4"
        >
          {showFormula ? "Hide Model" : "View Model"}
        </button>
      </div>

      <div className="flex items-center justify-around py-2">
        {/* SVG Circular Progress Meter */}
        <div className="relative flex items-center justify-center">
          <svg className="w-28 h-28 transform -rotate-90" viewBox="0 0 100 100">
            {/* Background track */}
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="transparent"
              stroke="#1e293b"
              strokeWidth="9"
            />
            {/* Value stroke */}
            <circle
              cx="50"
              cy="50"
              r="42"
              fill="transparent"
              stroke="currentColor"
              strokeWidth="9"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              className={`transition-all duration-1000 ease-out ${ringColor}`}
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center">
            <span className="text-2xl font-bold font-mono text-slate-100 tracking-tight">
              {score}
            </span>
            <span className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">
              / 100
            </span>
          </div>
        </div>

        {/* Grade and qualitative status */}
        <div className="flex flex-col items-start gap-1.5 pl-4">
          <div className="flex items-center gap-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100">
              Grade {grade}
            </span>
          </div>
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-xs border font-medium ${badgeColor}`}
          >
            {rating}
          </span>
          <p className="text-xs text-slate-400 mt-1">
            Total Penalty: <span className="font-mono text-slate-200 font-semibold">-{penalty} pts</span>
          </p>
        </div>
      </div>

      {/* Transparent formula explanation drawer */}
      {showFormula && (
        <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400 space-y-1.5 bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
          <p className="font-semibold text-slate-300">
            VulnSight Posture Calculation Formula:
          </p>
          <p className="font-mono text-[11px] text-emerald-400">
            Score = max(0, 100 - [15×Crit + 8×High + 3×Med + 1×Low])
          </p>
          <div className="grid grid-cols-2 gap-1 text-[11px] text-slate-300 pt-1">
            <div>Critical (-15): {criticalCount} (-{criticalCount * 15})</div>
            <div>High (-8): {highCount} (-{highCount * 8})</div>
            <div>Medium (-3): {mediumCount} (-{mediumCount * 3})</div>
            <div>Low (-1): {lowCount} (-{lowCount * 1})</div>
          </div>
        </div>
      )}
    </div>
  );
}
