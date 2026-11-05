type StatusTone = "ok" | "warning" | "error" | "checking";

const tones: Record<StatusTone, string> = {
  ok: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/30",
  warning: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
  error: "bg-rose-400/10 text-rose-300 ring-rose-400/30",
  checking: "bg-sky-400/10 text-sky-300 ring-sky-400/30",
};

type StatusBadgeProps = {
  tone: StatusTone;
  children: string;
};

export function StatusBadge({ tone, children }: StatusBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${tones[tone]}`}
    >
      {children}
    </span>
  );
}
