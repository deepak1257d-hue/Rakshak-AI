'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  Search,
  ChevronRight,
  ArrowUpDown,
  Download
} from 'lucide-react';
import { Finding, SeverityLevel, ExecutiveSummary } from '@/lib/types';
import FindingSideDrawer from './FindingSideDrawer';

interface VulnerabilitiesViewProps {
  findings: Finding[];
  executiveSummary?: ExecutiveSummary | null;
  summaryError?: string | null;
  onSelectFindingForRemediation: (finding: Finding) => void;
}

export default function VulnerabilitiesView({
  findings,
  executiveSummary,
  summaryError,
  onSelectFindingForRemediation,
}: VulnerabilitiesViewProps) {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | SeverityLevel>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'OPEN' | 'RESOLVED'>('ALL');
  const [sortBy, setSortBy] = useState<'SEVERITY_DESC' | 'DATE_DESC'>('SEVERITY_DESC');

  // Export visible findings as CSV
  const exportCSV = () => {
    const headers = ['Severity', 'Title', 'CVE ID', 'Affected Asset', 'Port', 'Category', 'Tool', 'Status', 'Created'];
    const rows = filteredFindings.map((f) => [
      f.severity,
      `"${(f.title || '').replace(/"/g, '""')}"`,
      f.cve_id || '',
      f.affected_asset || '',
      f.port || '',
      f.category || '',
      f.detection_method || '',
      f.status || 'OPEN',
      f.created_at ? new Date(f.created_at).toISOString() : '',
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rakshak-ai-findings-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Compute stats
  const totalFindings = findings.length;
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW').length;
  const infoCount = findings.filter(f => f.severity === 'INFORMATIONAL').length;

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

  const severityWeight: Record<string, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFORMATIONAL: 0,
  };

  // Filter & sort
  const filteredFindings = findings
    .filter(f => {
      const matchesSearch =
        f.title.toLowerCase().includes(searchQuery.toLowerCase().trim()) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(searchQuery.toLowerCase().trim())) ||
        (f.affected_asset && f.affected_asset.toLowerCase().includes(searchQuery.toLowerCase().trim())) ||
        (f.category && f.category.toLowerCase().includes(searchQuery.toLowerCase().trim()));

      const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
      const matchesStatus =
        statusFilter === 'ALL' ||
        (statusFilter === 'RESOLVED' ? f.status === 'RESOLVED' : f.status !== 'RESOLVED');

      return matchesSearch && matchesSeverity && matchesStatus;
    })
    .sort((a, b) => {
      if (sortBy === 'SEVERITY_DESC') {
        const diff = (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
        if (diff !== 0) return diff;
      }
      return (new Date(b.created_at || 0).getTime()) - (new Date(a.created_at || 0).getTime());
    });

  return (
    <div className="space-y-6">
      
      {/* Lab Target Warning Banner */}
      {(executiveSummary?.is_lab_target || executiveSummary?.target_verification_method === 'LAB') && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start justify-between gap-3 shadow-sm">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-bold text-amber-200">
                  {executiveSummary.ownership_badge || 'LAB - not proven ownership'}
                </span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  DEVELOPMENT LAB
                </span>
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {executiveSummary.ownership_warning ||
                  'This target used server-authorized lab verification. Domain ownership is not proven.'}
              </p>
            </div>
          </div>
        </div>
      )}

      {summaryError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-200 text-xs" role="alert">
          Scan summary could not be loaded: {summaryError}. Findings below are still from the scan findings endpoint.
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* RISK SCORECARD & SEVERITY CHIPS                               */}
      {/* ------------------------------------------------------------- */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Composite Risk Score Gauge */}
        <div className="p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800 relative flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-blue-400" />
              <h3 className="text-sm font-bold text-white tracking-tight">Mean scaled CVSS base score</h3>
            </div>
          </div>

          {typeof executiveSummary?.average_risk_score === 'number' ? (
            <div className="my-5 flex items-baseline gap-3">
              <span className="text-5xl font-black font-mono tracking-tight text-slate-100">{executiveSummary.average_risk_score}</span>
              <span className="text-slate-500 font-mono text-base">/100</span>
            </div>
          ) : (
            <div className="my-5">
              <span className="text-base font-semibold text-slate-300">Not calculated</span>
            </div>
          )}

          <p className="text-xs text-slate-400 leading-relaxed">
            {executiveSummary?.risk_score_scope ||
              'No numeric score is available because no finding has a CVE in the curated CVSS catalog.'}
          </p>
        </div>

        {/* Severity Breakdown Counter Chips */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-tight">Severity Breakdown</h3>
            <span className="text-xs text-slate-400 font-mono">
              Total {totalFindings} Findings
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { label: 'Critical', severity: 'CRITICAL' as const, count: criticalCount, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
              { label: 'High', severity: 'HIGH' as const, count: highCount, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
              { label: 'Medium', severity: 'MEDIUM' as const, count: mediumCount, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
              { label: 'Low', severity: 'LOW' as const, count: lowCount, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
              { label: 'Info', severity: 'INFORMATIONAL' as const, count: infoCount, color: 'text-slate-300', bg: 'bg-slate-800/60 border-slate-700/50' },
            ].map((chip) => (
              <button
                type="button"
                key={chip.label}
                aria-pressed={severityFilter === chip.severity}
                onClick={() => setSeverityFilter(severityFilter === chip.severity ? 'ALL' : chip.severity)}
                className={`p-3.5 rounded-xl border text-left ${chip.bg} hover:scale-[1.02] transition-transform focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400`}
              >
                <span className="text-[10px] font-mono text-slate-400 uppercase block">{chip.label}</span>
                <span className={`text-2xl font-bold font-mono ${chip.color} block mt-0.5`}>
                  {chip.count}
                </span>
              </button>
            ))}
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
            <span>Counts are based on the findings returned for this scan.</span>
          </div>
        </div>

      </div>

      {/* ------------------------------------------------------------- */}
      {/* SEARCH, FILTERS & SORT BAR                                    */}
      {/* ------------------------------------------------------------- */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search findings by title, CVE, asset, or category..."
            aria-label="Search findings by title, CVE, affected asset, or category"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/60"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
          {/* Severity filter pills */}
          <div className="flex items-center gap-1 p-1 bg-slate-900/80 border border-slate-800 rounded-xl text-xs">
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded-lg font-medium transition-all ${
                  severityFilter === sev
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev === 'ALL' ? 'All' : sev.charAt(0) + sev.slice(1).toLowerCase()}
              </button>
            ))}
          </div>

          {/* Sort toggle */}
          <button
            onClick={() => setSortBy(sortBy === 'SEVERITY_DESC' ? 'DATE_DESC' : 'SEVERITY_DESC')}
            aria-label={`Sort findings: ${sortBy === 'SEVERITY_DESC' ? 'severity first' : 'newest first'}`}
            className="px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 hover:text-white text-xs font-medium flex items-center gap-1.5 transition-all"
          >
            <ArrowUpDown className="w-3.5 h-3.5 text-blue-400" />
            <span>{sortBy === 'SEVERITY_DESC' ? 'Severity First' : 'Newest First'}</span>
          </button>

          {/* Export CSV */}
          <button
            onClick={exportCSV}
            disabled={filteredFindings.length === 0}
            className="px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 hover:text-white hover:border-cyan-700 text-xs font-medium flex items-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            title="Export visible findings as CSV"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------- */}
      {/* INTERACTIVE FINDINGS TABLE                                    */}
      {/* ------------------------------------------------------------- */}
      <div className="rounded-2xl border border-slate-800/90 bg-slate-900/40 overflow-hidden shadow-xl">
        {filteredFindings.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Info className="w-10 h-10 text-slate-400 mx-auto" />
            <h4 className="text-base font-bold text-white">
              {findings.length === 0 ? 'No findings returned for this scan' : 'No findings match these filters'}
            </h4>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              {searchQuery || severityFilter !== 'ALL'
                ? 'Try clearing the search query or adjusting severity filters.'
                : 'This is the finding data returned by the backend. It does not imply that the target is free of vulnerabilities.'}
            </p>
            {(searchQuery || severityFilter !== 'ALL') && (
              <button
                onClick={() => { setSearchQuery(''); setSeverityFilter('ALL'); }}
                className="px-3.5 py-1.5 rounded-xl bg-slate-800 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-all"
              >
                Clear Filters
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800/80 bg-slate-950/60 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-3.5 px-4 font-semibold">Severity</th>
                  <th className="py-3.5 px-4 font-semibold">Vulnerability Title</th>
                  <th className="py-3.5 px-4 font-semibold">Affected Asset</th>
                  <th className="py-3.5 px-4 font-semibold">Tool Source</th>
                  <th className="py-3.5 px-4 font-semibold">Status</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="hover:bg-slate-800/40 transition-colors group"
                  >
                    {/* Severity Badge */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className={`inline-block px-2.5 py-1 rounded-md border text-[11px] font-bold font-mono ${getSeverityStyle(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>

                    {/* Title & CVE */}
                    <td className="py-4 px-4">
                      <div className="space-y-0.5">
                        <span className="font-bold text-white group-hover:text-blue-400 transition-colors block leading-snug">
                          {finding.title}
                        </span>
                        <div className="flex items-center gap-2 text-[11px] text-slate-400">
                          {finding.cve_id ? (
                            <span className="font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.2 rounded border border-cyan-800/30">
                              {finding.cve_id}
                            </span>
                          ) : null}
                          {finding.category && <span>· {finding.category}</span>}
                        </div>
                      </div>
                    </td>

                    {/* Affected Asset */}
                    <td className="py-4 px-4 whitespace-nowrap font-mono text-slate-300">
                      {finding.affected_asset || 'Not provided'}
                      {finding.port && <span className="text-slate-500">:{finding.port}</span>}
                    </td>

                    {/* Detection Source Tool */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[11px]">
                        {finding.detection_method || 'Not provided'}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 text-[10px] font-mono">
                        {finding.status || 'OPEN'}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-4 px-4 whitespace-nowrap text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(finding);
                        }}
                        aria-label={`View details for ${finding.title}`}
                        className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 text-xs font-medium inline-flex items-center gap-1.5 transition-all"
                      >
                        <span>Details</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SLIDE-IN FINDINGS SIDE DRAWER                                 */}
      {/* ------------------------------------------------------------- */}
      <FindingSideDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onProceedToRemediation={(f) => {
          setSelectedFinding(null);
          onSelectFindingForRemediation(f);
        }}
      />

    </div>
  );
}
