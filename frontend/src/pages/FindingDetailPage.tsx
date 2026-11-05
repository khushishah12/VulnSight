import { useEffect, useState } from "react";
import { fetchFinding, updateFindingRemediation, requestFixVerification } from "../api/findings";
import { useNavigation } from "../context/NavigationContext";
import {
  CompassIcon,
  CopyIcon,
  CheckIcon,
  ExternalLinkIcon,
  LockIcon,
  ShieldCheckIcon,
  TerminalIcon,
} from "../components/ui/Icons";
import { ConfidenceBadge, RiskScoreBadge, SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { ErrorAlert, LoadingSkeleton } from "../components/ui/Feedback";
import { Modal } from "../components/ui/Modal";
import type { FindingDetail, RemediationStatus } from "../types";

export function FindingDetailPage() {
  const { params, navigate } = useNavigation();
  const findingId = params.findingId;

  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Workflow update state
  const [remStatus, setRemStatus] = useState<RemediationStatus>("not_started");
  const [remNotes, setRemNotes] = useState("");
  const [savingStatus, setSavingStatus] = useState(false);

  // Fix verification trigger modal state
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyNote, setVerifyNote] = useState("");
  const [verifyResult, setVerifyResult] = useState<string | null>(null);
  const [copiedEvidence, setCopiedEvidence] = useState<string | null>(null);

  async function loadFinding() {
    if (!findingId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchFinding(findingId);
      setFinding(data);
      setRemStatus(data.remediation?.status || data.remediation_status || "not_started");
      setRemNotes(data.remediation?.notes || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load finding details.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadFinding();
  }, [findingId]);

  async function handleSaveRemediation() {
    if (!findingId) return;
    setSavingStatus(true);
    try {
      await updateFindingRemediation(findingId, remStatus, remNotes);
      await loadFinding();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update remediation status.");
    } finally {
      setSavingStatus(false);
    }
  }

  async function handleExecuteVerification() {
    if (!findingId) return;
    setVerifying(true);
    try {
      const res = await requestFixVerification(findingId, verifyNote, true);
      setVerifyResult(`Verification status: ${res.status.toUpperCase()} – ${res.result_summary || "Completed"}`);
      await loadFinding();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to execute fix verification.");
    } finally {
      setVerifying(false);
    }
  }

  function handleCopy(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedEvidence(id);
    setTimeout(() => setCopiedEvidence(null), 2000);
  }

  if (loading) return <LoadingSkeleton count={5} />;
  if (error || !finding) return <ErrorAlert title="Finding Error" message={error || "Finding not found."} />;

  const risk = finding.risk_assessment;

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="font-mono text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              {finding.owasp_category}
            </span>
            <ConfidenceBadge confidence={finding.confidence} />
            <RiskScoreBadge score={finding.risk_score} />
            <StatusBadge status={finding.remediation_status || finding.status} />
          </div>

          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            {finding.title}
          </h1>

          <div className="text-xs text-slate-400 font-mono flex flex-wrap items-center gap-4">
            <span>Check ID: <strong className="text-slate-300">{finding.check_id}</strong></span>
            <span>Method: <strong className="text-emerald-400">{finding.detection_method}</strong></span>
            <span>Recorded: {new Date(finding.created_at).toLocaleString()}</span>
          </div>
        </div>

        {/* Quick Action Buttons */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => navigate("remediation-center", { checkId: finding.check_id })}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 hover:bg-slate-800 text-xs font-medium transition cursor-pointer"
          >
            <CompassIcon className="w-4 h-4 text-sky-400" />
            <span>Remediation Guide</span>
          </button>

          <button
            type="button"
            onClick={() => setShowVerifyModal(true)}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs tracking-wide transition shadow-sm cursor-pointer"
          >
            <ShieldCheckIcon className="w-4 h-4" />
            <span>Verify Fix</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Description + Risk Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2 Cols): Narrative & Evidence */}
        <div className="lg:col-span-2 space-y-6">
          {/* Affected URL / Path */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
              Affected Resource / Endpoint
            </h3>
            <div className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-200">
              <span>{finding.affected_url || "General Target Scope"}</span>
              {finding.affected_url && (
                <a
                  href={finding.affected_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-slate-400 hover:text-slate-200"
                >
                  <ExternalLinkIcon className="w-4 h-4" />
                </a>
              )}
            </div>
          </div>

          {/* Description */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
              Technical Description & Observation
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">
              {finding.description}
            </p>
          </div>

          {/* Technical Evidence */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
                <TerminalIcon className="w-4 h-4 text-emerald-400" />
                <span>Technical Evidence Artifacts ({finding.evidence.length})</span>
              </h3>
              <span className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                <LockIcon className="w-3 h-3" /> Redacted & Hashed
              </span>
            </div>

            {finding.evidence.length === 0 ? (
              <p className="text-xs text-slate-500">No raw evidentiary requests were stored.</p>
            ) : (
              <div className="space-y-3">
                {finding.evidence.map((ev) => (
                  <div key={ev.id} className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-emerald-400 font-semibold uppercase text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10">
                          {ev.kind}
                        </span>
                        <span className="font-semibold text-slate-200">{ev.label}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleCopy(ev.content, ev.id)}
                        className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[11px]"
                      >
                        {copiedEvidence === ev.id ? (
                          <>
                            <CheckIcon className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400">Copied</span>
                          </>
                        ) : (
                          <>
                            <CopyIcon className="w-3.5 h-3.5" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>

                    <pre className="p-3 bg-slate-900/90 rounded border border-slate-800/80 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                      {ev.content}
                    </pre>

                    <div className="text-[10px] font-mono text-slate-500 truncate" title={ev.content_sha256}>
                      SHA-256: {ev.content_sha256}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column (1 Col): Risk Scoring & Workflow Controls */}
        <div className="space-y-6">
          {/* Transparent Risk Score Breakdown */}
          {risk && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
                  Risk Assessment Breakdown
                </h3>
                <RiskScoreBadge score={risk.score} />
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Technical Impact:</span>
                  <span className="font-mono text-slate-200 font-semibold">{risk.impact_score.toFixed(1)} / 10.0</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Exploit Likelihood:</span>
                  <span className="font-mono text-slate-200 font-semibold">{risk.likelihood_score.toFixed(2)} ({risk.likelihood_level})</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Scanner Confidence:</span>
                  <span className="font-mono text-slate-200 font-semibold">{risk.confidence_weight.toFixed(2)} ({risk.confidence})</span>
                </div>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 break-words">
                {risk.formula}
              </div>

              <p className="text-[10px] text-slate-500 leading-relaxed italic">
                {risk.disclaimer}
              </p>
            </div>
          )}

          {/* Workflow Status Controls */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
              Remediation Workflow
            </h3>

            <div>
              <label className="block text-[11px] font-semibold text-slate-400 uppercase mb-1">
                Remediation Status
              </label>
              <select
                value={remStatus}
                onChange={(e) => setRemStatus(e.target.value as RemediationStatus)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
              >
                <option value="not_started">Not Started (Open)</option>
                <option value="in_progress">In Progress</option>
                <option value="done">Remediated (Ready for verification)</option>
                <option value="accepted_risk">Accepted Business Risk</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-400 uppercase mb-1">
                Operator Notes
              </label>
              <textarea
                value={remNotes}
                onChange={(e) => setRemNotes(e.target.value)}
                placeholder="Log internal ticket IDs, patch PR links, or mitigation notes..."
                className="w-full h-20 bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <button
              type="button"
              onClick={handleSaveRemediation}
              disabled={savingStatus}
              className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 font-semibold text-xs tracking-wide transition cursor-pointer"
            >
              {savingStatus ? "Saving..." : "Update Workflow Status"}
            </button>
          </div>

          {/* Fix Verification History */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
              Verification Run History
            </h3>

            {finding.verification_runs.length === 0 ? (
              <p className="text-xs text-slate-500">No fix verifications requested yet.</p>
            ) : (
              <div className="space-y-2">
                {finding.verification_runs.map((v) => (
                  <div key={v.id} className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <StatusBadge status={v.status} />
                      <span className="text-[10px] text-slate-500">
                        {new Date(v.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                    {v.result_summary && (
                      <p className="text-[11px] text-slate-300 font-mono pt-1">
                        {v.result_summary}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Fix Verification Trigger Modal */}
      <Modal
        isOpen={showVerifyModal}
        onClose={() => {
          setShowVerifyModal(false);
          setVerifyResult(null);
        }}
        title="Execute Automated Fix Verification"
      >
        <div className="space-y-4 text-xs">
          <p className="text-slate-300 leading-relaxed">
            VulnSight will safely re-probe the affected endpoint to verify whether the identified
            vulnerability has been remediated.
          </p>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1 text-slate-400">
            <div><strong>Target:</strong> <code className="text-slate-200">{finding.affected_url}</code></div>
            <div><strong>Check:</strong> <code className="text-emerald-400">{finding.check_id}</code></div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-300 uppercase mb-1">
              Verification Notes (Optional)
            </label>
            <input
              type="text"
              value={verifyNote}
              onChange={(e) => setVerifyNote(e.target.value)}
              placeholder="e.g. Patch deployed in staging container"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {verifyResult && (
            <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-emerald-300 font-mono text-xs">
              {verifyResult}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setShowVerifyModal(false)}
              className="px-4 py-2 rounded-lg text-slate-400 hover:text-slate-200 transition text-xs font-semibold"
            >
              Close
            </button>
            <button
              type="button"
              onClick={handleExecuteVerification}
              disabled={verifying}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs uppercase tracking-wide transition shadow cursor-pointer"
            >
              {verifying ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  <span>Probing Target...</span>
                </>
              ) : (
                <>
                  <ShieldCheckIcon className="w-3.5 h-3.5" />
                  <span>Run Verification</span>
                </>
              )}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
