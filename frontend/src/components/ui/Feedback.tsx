import React from "react";
import { AlertTriangleIcon, SearchIcon } from "./Icons";

export function EmptyState({
  title = "No records found",
  message = "There are no items matching your criteria or no scans have been initiated yet.",
  action,
  icon,
}: {
  title?: string;
  message?: string;
  action?: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center bg-slate-900/40 border border-dashed border-slate-800 rounded-xl my-4">
      <div className="w-12 h-12 rounded-full bg-slate-800/80 flex items-center justify-center text-slate-400 mb-3">
        {icon || <SearchIcon className="w-6 h-6" />}
      </div>
      <h3 className="text-base font-semibold text-slate-200">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mt-1 mb-4 leading-relaxed">
        {message}
      </p>
      {action}
    </div>
  );
}

export function LoadingSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="space-y-3 animate-pulse p-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-16 bg-slate-800/50 rounded-lg w-full border border-slate-800" />
      ))}
    </div>
  );
}

export function ErrorAlert({
  title = "An error occurred",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="bg-rose-950/40 border border-rose-500/30 rounded-xl p-4 flex items-start gap-3 my-4">
      <AlertTriangleIcon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
      <div className="flex-1 text-xs">
        <h4 className="font-semibold text-rose-300">{title}</h4>
        <p className="text-rose-200/80 mt-0.5 leading-relaxed">{message}</p>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="mt-2 text-rose-300 hover:text-rose-100 font-semibold underline underline-offset-4 cursor-pointer"
          >
            Retry Request
          </button>
        )}
      </div>
    </div>
  );
}
