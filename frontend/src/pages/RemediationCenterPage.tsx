import { useEffect, useState } from "react";
import { fetchAllRemediationGuides } from "../api/remediation";
import { useNavigation } from "../context/NavigationContext";
import {
  CheckCircleIcon,
  CheckIcon,
  CopyIcon,
  SearchIcon,
  ShieldCheckIcon,
  TerminalIcon,
} from "../components/ui/Icons";
import { Tabs } from "../components/ui/Tabs";
import { EmptyState, ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import type { RemediationGuide } from "../types";

export function RemediationCenterPage() {
  const { params } = useNavigation();
  const initialCheckId = params.checkId;

  const [guides, setGuides] = useState<RemediationGuide[]>([]);
  const [selectedGuide, setSelectedGuide] = useState<RemediationGuide | null>(null);
  const [activeStack, setActiveStack] = useState<string>("nodejs_express");
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    async function loadGuides() {
      setLoading(true);
      setError(null);
      try {
        const allGuides = await fetchAllRemediationGuides();
        setGuides(allGuides);

        if (initialCheckId) {
          const match = allGuides.find(
            (g) => g.check_id.toLowerCase() === initialCheckId.toLowerCase(),
          );
          if (match) {
            setSelectedGuide(match);
          } else if (allGuides.length > 0) {
            setSelectedGuide(allGuides[0]);
          }
        } else if (allGuides.length > 0) {
          setSelectedGuide(allGuides[0]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load remediation center.");
      } finally {
        setLoading(false);
      }
    }

    loadGuides();
  }, [initialCheckId]);

  function handleCopy(text: string, key: string) {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }

  const filteredGuides = guides.filter((g) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      g.title.toLowerCase().includes(term) ||
      g.check_id.toLowerCase().includes(term) ||
      g.owasp_category.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
              Remediation Center Encyclopedia
            </h1>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-sky-500/10 text-sky-400 border border-sky-500/30">
              Multi-Framework
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Prescriptive root cause analysis, framework-agnostic secure code, and verification rules
          </p>
        </div>

        {/* Search */}
        <div className="relative w-full md:w-64">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search vulnerability guides..."
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
          />
          <div className="absolute left-3 top-2 text-slate-500">
            <SearchIcon className="w-3.5 h-3.5" />
          </div>
        </div>
      </div>

      {error && <ErrorAlert title="Knowledgebase Error" message={error} />}

      {loading ? (
        <LoadingSkeleton count={4} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Guide Navigation Sidebar (4 Cols) */}
          <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="p-4 border-b border-slate-800 bg-slate-950/60 font-semibold text-xs text-slate-300 uppercase tracking-wider font-mono">
              OWASP Top 10:2025 Guides ({filteredGuides.length})
            </div>

            <div className="divide-y divide-slate-800/60 max-h-[75vh] overflow-y-auto">
              {filteredGuides.map((guide) => {
                const isSelected = selectedGuide?.check_id === guide.check_id;
                return (
                  <button
                    key={guide.check_id}
                    type="button"
                    onClick={() => {
                      setSelectedGuide(guide);
                      // default active stack to first available
                      const stackKeys = Object.keys(guide.code_examples);
                      if (stackKeys.length > 0 && !stackKeys.includes(activeStack)) {
                        setActiveStack(stackKeys[0]);
                      }
                    }}
                    className={`w-full text-left p-3.5 transition flex flex-col gap-1 cursor-pointer ${
                      isSelected
                        ? "bg-slate-800/70 border-l-2 border-emerald-500"
                        : "hover:bg-slate-800/30"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-semibold">
                        {guide.owasp_category}
                      </span>
                      <span className="font-mono text-[10px] text-slate-500">
                        {guide.check_id}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-slate-200 line-clamp-1">
                      {guide.title}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Guide Detail & Code Examples (8 Cols) */}
          <div className="lg:col-span-8 space-y-6">
            {!selectedGuide ? (
              <EmptyState title="Select a Guide" message="Choose an OWASP Top 10 check to view remediation guidance." />
            ) : (
              <>
                {/* Guide Header Banner */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold">
                      {selectedGuide.owasp_category}
                    </span>
                    <span className="font-mono text-xs text-slate-400">
                      {selectedGuide.check_id}
                    </span>
                  </div>

                  <h2 className="text-xl font-bold text-slate-100">
                    {selectedGuide.title}
                  </h2>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {selectedGuide.vulnerability_meaning}
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 text-xs">
                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                      <span className="text-[10px] uppercase font-mono font-semibold text-rose-400">
                        Root Cause
                      </span>
                      <p className="text-slate-300 text-[11px] leading-relaxed">
                        {selectedGuide.root_cause}
                      </p>
                    </div>

                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                      <span className="text-[10px] uppercase font-mono font-semibold text-amber-400">
                        Potential Business Impact
                      </span>
                      <p className="text-slate-300 text-[11px] leading-relaxed">
                        {selectedGuide.business_impact}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Step-by-Step Remediation Checklist */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
                    <CheckCircleIcon className="w-4 h-4 text-emerald-400" />
                    <span>Step-by-Step Engineering Remediation</span>
                  </h3>

                  <div className="space-y-2">
                    {selectedGuide.step_by_step_remediation.map((step, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-slate-200 flex items-start gap-3"
                      >
                        <span className="w-5 h-5 rounded-full bg-slate-800 text-emerald-400 flex items-center justify-center text-[10px] font-mono shrink-0 font-bold">
                          {idx + 1}
                        </span>
                        <span className="leading-relaxed">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Multi-Framework Code Examples */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
                      <TerminalIcon className="w-4 h-4 text-emerald-400" />
                      <span>Side-by-Side Code Examples (Technology Stack Agnostic)</span>
                    </h3>
                  </div>

                  {/* Framework Switcher Tabs */}
                  <Tabs
                    tabs={Object.entries(selectedGuide.code_examples).map(([key, val]) => ({
                      id: key,
                      label: val.stack_name,
                    }))}
                    activeTab={activeStack}
                    onChange={setActiveStack}
                  />

                  {/* Code Viewers */}
                  {selectedGuide.code_examples[activeStack] ? (
                    <div className="space-y-4 pt-2">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Vulnerable Snippet */}
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-semibold text-rose-400 flex items-center gap-1.5 text-[11px] font-mono">
                              <span className="w-2 h-2 rounded-full bg-rose-500" />
                              VULNERABLE IMPLEMENTATION
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(
                                  selectedGuide.code_examples[activeStack].vulnerable_code,
                                  "vuln",
                                )
                              }
                              className="text-slate-400 hover:text-slate-200 text-[11px] flex items-center gap-1"
                            >
                              {copiedKey === "vuln" ? (
                                <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <CopyIcon className="w-3.5 h-3.5" />
                              )}
                              <span>Copy</span>
                            </button>
                          </div>
                          <pre className="p-3 bg-slate-950 border border-rose-950/40 rounded-lg font-mono text-[11px] text-rose-200/90 overflow-x-auto whitespace-pre-wrap min-h-36">
                            {selectedGuide.code_examples[activeStack].vulnerable_code}
                          </pre>
                        </div>

                        {/* Secure Snippet */}
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-semibold text-emerald-400 flex items-center gap-1.5 text-[11px] font-mono">
                              <span className="w-2 h-2 rounded-full bg-emerald-500" />
                              SECURE REMEDIATION
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(
                                  selectedGuide.code_examples[activeStack].secure_code,
                                  "sec",
                                )
                              }
                              className="text-slate-400 hover:text-slate-200 text-[11px] flex items-center gap-1"
                            >
                              {copiedKey === "sec" ? (
                                <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <CopyIcon className="w-3.5 h-3.5" />
                              )}
                              <span>Copy</span>
                            </button>
                          </div>
                          <pre className="p-3 bg-slate-950 border border-emerald-950/40 rounded-lg font-mono text-[11px] text-emerald-200/90 overflow-x-auto whitespace-pre-wrap min-h-36">
                            {selectedGuide.code_examples[activeStack].secure_code}
                          </pre>
                        </div>
                      </div>

                      {/* Explanation */}
                      <p className="text-xs text-slate-400 italic pt-1">
                        <strong>Engineering Note:</strong> {selectedGuide.code_examples[activeStack].explanation}
                      </p>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 py-4">No code snippet available for this stack.</p>
                  )}
                </div>

                {/* Fix Verification Criteria Card */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
                    <ShieldCheckIcon className="w-4 h-4 text-teal-400" />
                    <span>Fix Verification Specification</span>
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                      <span className="text-[10px] uppercase font-mono font-semibold text-slate-400">
                        What Should Change
                      </span>
                      <p className="text-slate-200 leading-relaxed text-[11px]">
                        {selectedGuide.fix_verification.what_should_change}
                      </p>
                    </div>

                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                      <span className="text-[10px] uppercase font-mono font-semibold text-slate-400">
                        Safe Re-Test Check
                      </span>
                      <p className="text-slate-200 leading-relaxed text-[11px]">
                        {selectedGuide.fix_verification.check_to_rerun}
                      </p>
                    </div>

                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                      <span className="text-[10px] uppercase font-mono font-semibold text-slate-400">
                        Expected Evidence
                      </span>
                      <p className="text-slate-200 leading-relaxed text-[11px]">
                        {selectedGuide.fix_verification.expected_evidence}
                      </p>
                    </div>

                    <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1">
                      <span className="text-[10px] uppercase font-mono font-semibold text-slate-400">
                        Inconclusive Conditions
                      </span>
                      <p className="text-slate-200 leading-relaxed text-[11px]">
                        {selectedGuide.fix_verification.inconclusive_conditions}
                      </p>
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
