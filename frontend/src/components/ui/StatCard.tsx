import React from "react";

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: string;
  badge?: React.ReactNode;
  highlightColor?: string;
}

export function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  badge,
  highlightColor,
}: StatCardProps) {
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
      {highlightColor && (
        <div
          className="absolute top-0 left-0 right-0 h-[2px]"
          style={{ backgroundColor: highlightColor }}
        />
      )}
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold tracking-wider uppercase text-slate-400">
          {title}
        </span>
        {icon && <div className="text-slate-400">{icon}</div>}
      </div>

      <div className="my-3 flex items-baseline gap-2">
        <span className="text-3xl font-extrabold font-mono tracking-tight text-slate-100">
          {value}
        </span>
        {badge}
      </div>

      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>{subtitle}</span>
        {trend && <span className="font-mono text-emerald-400">{trend}</span>}
      </div>
    </div>
  );
}
