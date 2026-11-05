import type { ReactNode } from "react";

import { StatusBadge } from "./StatusBadge";

type HealthCardProps = {
  title: string;
  description: string;
  tone: "ok" | "warning" | "error" | "checking";
  badge: string;
  children: ReactNode;
};

export function HealthCard({
  title,
  description,
  tone,
  badge,
  children,
}: HealthCardProps) {
  return (
    <article className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-2xl shadow-slate-950/30 backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <p className="mt-1 text-sm text-slate-400">{description}</p>
        </div>
        <StatusBadge tone={tone}>{badge}</StatusBadge>
      </div>
      <div className="mt-6">{children}</div>
    </article>
  );
}
