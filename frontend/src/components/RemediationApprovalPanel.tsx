'use client';

import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, ExternalLink, GitPullRequest, ShieldCheck, XCircle } from 'lucide-react';
import { aegisApi, ApprovalDecisionResult } from '@/lib/api';
import { Finding } from '@/lib/types';

interface RemediationApprovalPanelProps {
  finding: Finding;
  onBackToFindings: () => void;
}

type DecisionAction = 'APPROVE' | 'REJECT';

export default function RemediationApprovalPanel({
  finding,
  onBackToFindings,
}: RemediationApprovalPanelProps) {
  const [repository, setRepository] = useState('');
  const [pendingAction, setPendingAction] = useState<DecisionAction | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ApprovalDecisionResult | null>(null);

  const patch = finding.remediation_patch?.trim() || '';
  const alreadyDecided = finding.status === 'REMEDIATION_PR_DISPATCHED'
    || finding.status === 'REMEDIATION_REJECTED';
  const canApprove = Boolean(patch && repository.trim() && !alreadyDecided && !result);

  const submitDecision = async (action: DecisionAction) => {
    if (action === 'APPROVE' && !canApprove) return;
    if (action === 'REJECT' && (alreadyDecided || result)) return;

    setIsSubmitting(true);
    setError(null);
    try {
      const decision = await aegisApi.submitApprovalDecision(
        finding.id,
        action,
        action === 'APPROVE' ? repository.trim() : undefined
      );
      setResult(decision);
      setPendingAction(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The decision could not be submitted.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const returnedPrUrl = result?.action === 'APPROVED' && result.pr_url
    ? (() => {
        try {
          const url = new URL(result.pr_url);
          return url.protocol === 'https:' ? url.toString() : null;
        } catch {
          return null;
        }
      })()
    : null;

  return (
    <div className="space-y-6">
      <header>
        <h3 className="flex items-center gap-2 text-base font-bold text-white">
          <GitPullRequest className="h-5 w-5 text-amber-400" />
          Human review required
        </h3>
        <p className="mt-1 text-xs text-slate-400">
          Review the backend-provided patch and explicitly approve or reject it.
        </p>
      </header>

      <section className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-mono text-slate-300">
            {finding.severity}
          </span>
          {finding.cve_id && (
            <span className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-mono text-slate-300">
              {finding.cve_id}
            </span>
          )}
          <span className="text-[10px] font-mono text-slate-500">Finding {finding.id}</span>
        </div>
        <h4 className="text-sm font-semibold text-white">{finding.title}</h4>
        {patch ? (
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-[#05080f] p-4 text-xs font-mono text-slate-200">
            {patch}
          </pre>
        ) : (
          <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200">
            The backend did not return a remediation patch. Approval is unavailable; rejection remains a human decision.
          </p>
        )}
      </section>

      {alreadyDecided && (
        <div className="rounded-xl border border-slate-700 bg-slate-900/70 p-4 text-sm text-slate-300" role="status">
          The backend reports this finding as <strong>{finding.status}</strong>. No additional decision is offered.
          A prior PR URL is not available from the finding response.
        </div>
      )}

      {result && (
        <div
          className={`rounded-xl border p-4 ${
            result.action === 'APPROVED'
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100'
              : 'border-slate-700 bg-slate-900/70 text-slate-200'
          }`}
          role="status"
          aria-live="polite"
        >
          <div className="flex items-start gap-2">
            {result.action === 'APPROVED'
              ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />}
            <div className="space-y-2 text-xs">
              <p>{result.message || `The backend confirmed the ${result.action.toLowerCase()} decision.`}</p>
              {result.approver && <p>Recorded approver: {result.approver}</p>}
              {result.auto_merge_disabled === true && <p>Backend reports auto-merge is disabled.</p>}
              {result.action === 'APPROVED' && result.pr_url && !returnedPrUrl && (
                <p className="text-amber-200">The backend returned a PR URL that is not a valid HTTPS link.</p>
              )}
              {returnedPrUrl && (
                <a
                  href={returnedPrUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 font-semibold underline underline-offset-2"
                >
                  Open pull request
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              )}
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-200" role="alert">
          <AlertTriangle className="mr-2 inline h-4 w-4 align-text-bottom" />
          {error}
        </div>
      )}

      {!alreadyDecided && !result && (
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-start gap-2 text-xs text-slate-300">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-blue-400" />
            <p>
              Approval calls the backend decision endpoint, which may dispatch a pull request as part of that same request.
              No separate PR-creation action or auto-merge option is provided here.
            </p>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="approval-repository" className="block text-xs font-semibold text-slate-200">
              Repository name for approval
            </label>
            <input
              id="approval-repository"
              type="text"
              value={repository}
              onChange={(event) => setRepository(event.target.value)}
              placeholder="Enter the repository configured for your GitHub integration"
              disabled={isSubmitting}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
            />
            <p className="text-[11px] text-slate-500">
              Required to approve. The UI does not assume a repository name.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => { setError(null); setPendingAction('APPROVE'); }}
              disabled={!canApprove || isSubmitting}
              className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Approve remediation
            </button>
            <button
              type="button"
              onClick={() => { setError(null); setPendingAction('REJECT'); }}
              disabled={alreadyDecided || isSubmitting}
              className="rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Reject remediation
            </button>
            <button
              type="button"
              onClick={onBackToFindings}
              className="rounded-lg px-4 py-2 text-xs font-medium text-slate-400 hover:text-white"
            >
              Back to findings
            </button>
          </div>
        </div>
      )}

      {pendingAction && (
        <div
          className="rounded-xl border border-amber-500/40 bg-amber-950/30 p-5 space-y-3"
          role="group"
          aria-live="assertive"
          aria-labelledby="decision-confirm-title"
        >
          <h4 id="decision-confirm-title" className="text-sm font-semibold text-amber-100">
            Confirm {pendingAction === 'APPROVE' ? 'approval' : 'rejection'}
          </h4>
          <p className="text-xs leading-relaxed text-slate-300">
            {pendingAction === 'APPROVE'
              ? `You are approving this patch for ${repository.trim()}. The backend decision endpoint may dispatch a pull request.`
              : 'You are rejecting this remediation proposal. The backend will record the rejection.'}
            {' '}This action will be submitted only after you confirm below.
          </p>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => setPendingAction(null)}
              disabled={isSubmitting}
              className="rounded-lg border border-slate-700 px-4 py-2 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void submitDecision(pendingAction)}
              disabled={isSubmitting || (pendingAction === 'APPROVE' && !canApprove)}
              className="rounded-lg bg-amber-500 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-amber-400 disabled:opacity-50"
            >
              {isSubmitting ? 'Submitting decision…' : 'Confirm decision'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
