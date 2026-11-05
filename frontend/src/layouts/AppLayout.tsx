import type { ReactNode } from "react";

type AppLayoutProps = {
  children: ReactNode;
};

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-slate-950">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(16,185,129,0.14),transparent_45%)]" />

      <div className="relative flex min-h-screen flex-col">
        <header className="border-b border-white/5 bg-slate-950/60 backdrop-blur">
          <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-6 py-4">
            <div className="flex items-center gap-3">
              <div className="grid size-10 place-items-center rounded-xl bg-emerald-400/10 ring-1 ring-emerald-400/30">
                <svg
                  aria-hidden="true"
                  viewBox="0 0 24 24"
                  fill="none"
                  className="size-5 text-emerald-300"
                >
                  <path
                    d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6l-7-3Z"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinejoin="round"
                  />
                  <path
                    d="m9 12 2 2 4-4"
                    stroke="currentColor"
                    strokeWidth="1.75"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <div>
                <p className="text-sm font-semibold tracking-wide text-white">
                  VulnSight
                </p>
                <p className="text-xs text-slate-400">
                  Web vulnerability assessment
                </p>
              </div>
            </div>

            <span className="hidden rounded-full border border-slate-700 px-3 py-1 text-xs font-medium text-slate-300 sm:inline">
              Step 3 foundation
            </span>
          </div>
        </header>

        <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-12">
          {children}
        </main>

        <footer className="border-t border-white/5 px-6 py-5 text-center text-xs text-slate-500">
          Lean MVP foundation · React + FastAPI + Neon PostgreSQL
        </footer>
      </div>
    </div>
  );
}
