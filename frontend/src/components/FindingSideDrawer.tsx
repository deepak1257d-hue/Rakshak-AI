'use client';

import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Code,
  Terminal,
  GitPullRequest,
  Copy,
  Check,
  X,
  ExternalLink,
  Globe,
  ArrowRight
} from 'lucide-react';
import { Finding } from '@/lib/types';

interface FindingSideDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onProceedToRemediation: (finding: Finding) => void;
}

export default function FindingSideDrawer({
  finding,
  onClose,
  onProceedToRemediation,
}: FindingSideDrawerProps) {
  const [copiedEvidence, setCopiedEvidence] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  const findingId = finding?.id;

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!findingId) return;

    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    closeButtonRef.current?.focus();

    const handleDialogKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab') return;

      const focusable = panelRef.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (!focusable?.length) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!panelRef.current?.contains(document.activeElement)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      document.removeEventListener('keydown', handleDialogKeyDown);
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [findingId]);

  if (!finding) return null;

  const getSeverityStyle = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/15 border-red-500/30 text-red-400';
      case 'HIGH':
        return 'bg-orange-500/15 border-orange-500/30 text-orange-400';
      case 'MEDIUM':
        return 'bg-amber-500/15 border-amber-500/30 text-amber-400';
      case 'LOW':
        return 'bg-blue-500/15 border-blue-500/30 text-blue-400';
      default:
        return 'bg-slate-800 border-slate-700 text-slate-300';
    }
  };

  const copyText = (text: string, type: 'evidence' | 'patch') => {
    navigator.clipboard.writeText(text);
    if (type === 'evidence') {
      setCopiedEvidence(true);
      setTimeout(() => setCopiedEvidence(false), 2000);
    } else {
      setCopiedPatch(true);
      setTimeout(() => setCopiedPatch(false), 2000);
    }
  };

  const evidenceText = finding.reachability_proof || finding.sanitized_output || finding.evidence || '';
  const patchText = finding.remediation_patch || '';

  return (
    <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true" aria-labelledby="finding-drawer-title">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="absolute inset-0 bg-black/75 backdrop-blur-sm transition-opacity"
      />

      {/* Slide-In Drawer Panel */}
      <div
        ref={panelRef}
        className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl bg-[#090d16] border-l border-slate-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-200"
      >
        
        {/* Drawer Sticky Header */}
        <div className="p-6 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-10 flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2.5 py-1 rounded-md border text-xs font-bold font-mono ${getSeverityStyle(finding.severity)}`}>
                {finding.severity}
              </span>

              {finding.cve_id && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-blue-500/50 text-slate-300 hover:text-blue-300 text-xs font-mono flex items-center gap-1.5 transition-colors"
                >
                  <span>{finding.cve_id}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}

              {finding.finding_type && (
                <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 text-[10px] font-mono">
                  {finding.finding_type}
                </span>
              )}

              <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10px] font-mono">
                Status: {finding.status}
              </span>
            </div>

            <h2 id="finding-drawer-title" className="text-lg font-bold text-white tracking-tight leading-snug">
              {finding.title}
            </h2>

            <p className="text-xs text-slate-400 font-mono flex items-center gap-2">
              <span>Affected:</span>
              <span className="text-blue-400 font-bold">{finding.affected_asset || 'Not provided by backend'}</span>
              {finding.port && <span>(Port: {finding.port})</span>}
            </p>
          </div>

          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close finding details"
            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Drawer Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 gap-3 p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs font-mono">
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Detection Source</span>
              <span className="text-slate-200 font-bold flex items-center gap-1.5 mt-0.5">
                <Terminal className="w-3.5 h-3.5 text-blue-400" />
                {finding.detection_method || 'Not provided by backend'}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Reachability Evidence</span>
              <span className="text-slate-200 font-bold flex items-center gap-1.5 mt-0.5">
                <Globe className="w-3.5 h-3.5 text-blue-400" />
                {finding.reachability_proof ? 'Provided by backend' : 'Not provided'}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Confidence Level</span>
              <span className="text-slate-200 font-bold mt-0.5 block">
                {finding.confidence || 'Not provided by backend'}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase block">Backend score</span>
              <span className="text-amber-400 font-bold mt-0.5 block">
                {typeof finding.score === 'number' ? `${finding.score}/100` : 'Not calculated'}
              </span>
            </div>
          </div>

          {/* Technical Description */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Code className="w-4 h-4 text-blue-400" />
              Technical Vulnerability Analysis
            </h4>
            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800 text-xs text-slate-300 leading-relaxed">
              {finding.technical_description || 'The backend did not provide a technical description for this finding.'}
            </div>
          </div>

          {/* Security Impact */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              Business & Security Impact
            </h4>
            <div className={`p-4 rounded-xl border text-xs leading-relaxed ${
              finding.security_impact
                ? 'bg-rose-950/10 border-rose-500/20 text-rose-200'
                : 'bg-slate-950/40 border-slate-800 text-slate-400'
            }`}>
              {finding.security_impact || 'The backend did not provide a security impact description for this finding.'}
            </div>
          </div>

          {finding.remediation_explanation && (
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-cyan-400" />
                Remediation Explanation
              </h4>
              <div className="p-4 rounded-xl bg-cyan-950/15 border border-cyan-500/20 text-xs text-cyan-200 leading-relaxed space-y-2">
                <p>{finding.remediation_explanation}</p>
              </div>
            </div>
          )}

          {/* Raw Evidence Monospace Box */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-slate-400" />
                Evidence returned by backend
              </h4>
              {evidenceText && (
                <button
                  type="button"
                  onClick={() => copyText(evidenceText, 'evidence')}
                  className="text-[11px] font-mono text-slate-400 hover:text-white flex items-center gap-1"
                >
                  {copiedEvidence ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Evidence</span>
                    </>
                  )}
                </button>
              )}
            </div>
            {evidenceText ? (
              <pre className="p-4 rounded-xl bg-[#05080f] border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-48 whitespace-pre-wrap break-all select-all">
                {evidenceText}
              </pre>
            ) : (
              <p className="p-4 rounded-xl bg-[#05080f] border border-slate-800 text-xs text-slate-400">
                The backend did not return evidence for this finding.
              </p>
            )}
          </div>

          {/* Recommended Fix / Proposed Patch */}
          {patchText && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <GitPullRequest className="w-4 h-4 text-emerald-400" />
                  Proposed Code Remediation Patch
                </h4>
                <button
                  type="button"
                  onClick={() => copyText(patchText, 'patch')}
                  className="text-[11px] font-mono text-slate-400 hover:text-white flex items-center gap-1"
                >
                  {copiedPatch ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Patch</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-4 rounded-xl bg-[#05080f] border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-48 whitespace-pre-wrap select-all">
                {patchText}
              </pre>
            </div>
          )}

        </div>

        {/* Drawer Footer CTA */}
        <div className="p-5 border-t border-slate-800/80 bg-slate-950/80 backdrop-blur-md flex items-center justify-between gap-4">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
          >
            Close Details
          </button>

          <button
            onClick={() => onProceedToRemediation(finding)}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-bold shadow-lg shadow-blue-600/20 flex items-center gap-2 transition-all"
          >
            <span>Proceed to Remediation (Step 5)</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

      </div>
    </div>
  );
}
