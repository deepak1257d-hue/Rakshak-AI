'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ExternalLink, FileText, RefreshCw } from 'lucide-react';
import { aegisApi } from '@/lib/api';
import { ExecutiveSummary } from '@/lib/types';

interface ExecutiveReportPanelProps {
  scanId: string;
}

export default function ExecutiveReportPanel({ scanId }: ExecutiveReportPanelProps) {
  const [summary, setSummary] = useState<ExecutiveSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSummary(null);
    try {
      const result = await aegisApi.getExecutiveSummary(scanId);
      if (result.scan_id !== scanId) {
        throw new Error('The backend returned a report for a different scan.');
      }
      setSummary(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load the executive summary.');
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  const traceUrl = summary?.trace_url && /^https?:\/\//i.test(summary.trace_url)
    ? summary.trace_url
    : null;

  return (
    <div className="space-y-6">
      <header>
        <h3 className="flex items-center gap-2 text-base font-bold text-white">
          <FileText className="h-5 w-5 text-emerald-400" />
          Executive summary from backend
        </h3>
        <p className="mt-1 text-xs text-slate-400">Scan ID: {scanId}</p>
      </header>

      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-100">
        <strong>AI narrative: NOT IMPLEMENTED.</strong> The current report API returns structured scan fields, not analyst-written narrative.
        <br />
        <strong>PDF export: NOT IMPLEMENTED.</strong> No PDF report endpoint is available to this frontend flow.
      </div>

      {loading && (
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-8 text-center text-sm text-slate-300" role="status" aria-live="polite">
          <RefreshCw className="mx-auto mb-3 h-5 w-5 animate-spin text-blue-400" />
          Loading report data…
        </div>
      )}

      {!loading && error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 space-y-3">
          <p className="text-sm text-rose-200" role="alert">
            <AlertTriangle className="mr-2 inline h-4 w-4 align-text-bottom" />
            {error}
          </p>
          <button
            type="button"
            onClick={() => void loadSummary()}
            className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-700"
          >
            Retry loading report
          </button>
        </div>
      )}

      {!loading && summary && (
        <div className="space-y-5">
          {(summary.is_partial || summary.scan_status === 'PARTIAL') && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-100">
              The backend reports PARTIAL results. This summary may not cover all checks.
            </div>
          )}

          {(summary.is_lab_target || summary.target_verification_method === 'LAB') && (
            <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-xs font-semibold text-amber-200">
              LAB - NOT PROVEN OWNERSHIP
            </div>
          )}

          <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {[
              { label: 'Target', value: summary.target_domain },
              { label: 'Scan status', value: summary.scan_status || 'Not provided' },
              { label: 'Verification method', value: summary.target_verification_method || 'Not provided' },
              { label: 'Mean scaled CVSS base score', value: typeof summary.average_risk_score === 'number' ? `${summary.average_risk_score}/100` : 'Not calculated' },
              { label: 'Findings returned', value: String(summary.total_findings) },
              { label: 'Critical / High', value: `${summary.critical_count} / ${summary.high_count}` },
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                <div className="text-[10px] font-mono uppercase tracking-wide text-slate-500">{item.label}</div>
                <div className="mt-2 break-words text-sm font-semibold text-slate-100">{item.value}</div>
              </div>
            ))}
          </section>

          <p className="text-xs text-slate-400">
            {summary.risk_score_scope || 'Risk score scope was not provided by the backend.'}
          </p>

          {summary.ownership_warning && (
            <p className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-4 text-xs text-amber-100">
              {summary.ownership_warning}
            </p>
          )}

          {(summary.trace_id || traceUrl) && (
            <section className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 text-xs">
              <h4 className="font-semibold text-slate-200">Trace returned by backend</h4>
              {summary.trace_id && <p className="mt-2 break-all font-mono text-slate-400">Trace ID: {summary.trace_id}</p>}
              {traceUrl && (
                <a
                  href={traceUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-2 inline-flex items-center gap-1.5 text-blue-300 underline underline-offset-2"
                >
                  Open trace
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              )}
            </section>
          )}

          <section className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">
            <h4 className="text-sm font-semibold text-white">Finding records in report response</h4>
            {summary.findings.length > 0 ? (
              <ul className="mt-4 divide-y divide-slate-800">
                {summary.findings.map((finding) => (
                  <li key={finding.id} className="flex flex-wrap items-start justify-between gap-2 py-3 first:pt-0 last:pb-0">
                    <div>
                      <p className="text-xs font-semibold text-slate-100">{finding.title}</p>
                      {finding.cve_id && <p className="mt-1 font-mono text-[11px] text-slate-400">{finding.cve_id}</p>}
                    </div>
                    <div className="text-right text-[11px] text-slate-300">
                      <span>{finding.severity}</span>
                      {typeof finding.score === 'number' && <span className="ml-2">Scaled CVSS base score {finding.score}/100</span>}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-xs text-slate-400">No finding records were included in the report response.</p>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
