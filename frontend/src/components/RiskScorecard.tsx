'use client';
import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle2, Clock, ShieldCheck, HelpCircle } from 'lucide-react';

interface RiskScorecardProps {
  score: number | null;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  timeToRemediate: string | null;
  viewMode?: 'simple' | 'technical';
}

export default function RiskScorecard({
  score,
  totalFindings,
  criticalCount,
  highCount,
  timeToRemediate,
  viewMode = 'simple'
}: RiskScorecardProps) {
  const getScoreColor = (val: number | null) => {
    if (val === null) return 'text-slate-400 border-slate-700 bg-slate-800/50';
    if (val >= 80) return 'text-red-500 border-red-500/30 bg-red-500/10';
    if (val >= 50) return 'text-amber-500 border-amber-500/30 bg-amber-500/10';
    return 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10';
  };

  const getScoreLabel = (val: number | null) => {
    if (val === null) return 'Not calculated';
    if (val >= 90) return 'Critical CVSS';
    if (val >= 70) return 'High CVSS';
    if (val >= 40) return 'Medium CVSS';
    return 'Low CVSS';
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      {/* 1. Security Score */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 flex items-center justify-between relative overflow-hidden group">
        <div className="z-10">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              {viewMode === 'simple' ? 'Scaled CVSS Base Score' : 'Backend CVSS Base Score'}
            </span>
            <div className="relative group/tooltip">
              <HelpCircle className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300 cursor-pointer" />
              <div className="absolute left-0 bottom-full mb-2 hidden group-hover/tooltip:block w-48 p-2 bg-slate-900 text-[11px] text-slate-300 rounded-lg border border-slate-700 shadow-xl z-50">
                {viewMode === 'simple'
                  ? 'A curated CVSS v3.1 base score scaled to 0-100. It is not a complete security posture score.'
                  : 'Scaled CVSS v3.1 base score only; environmental factors are not included.'}
              </div>
            </div>
          </div>
          <div className="flex items-baseline space-x-2 mt-1">
            <span className="text-3xl font-extrabold text-white">{score ?? '—'}</span>
            <span className="text-xs text-slate-400 font-medium">
              {score === null ? getScoreLabel(score) : `/ 100 (${getScoreLabel(score)})`}
            </span>
          </div>
        </div>
        <div className={`p-3.5 rounded-2xl border ${getScoreColor(score)} z-10`}>
          <ShieldAlert className="w-7 h-7" />
        </div>
        <div className="absolute -right-4 -bottom-4 w-24 h-24 bg-blue-500/5 rounded-full blur-xl pointer-events-none" />
      </div>

      {/* 2. Discovered Security Issues */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              {viewMode === 'simple' ? 'Security Issues Found' : 'Verified Findings'}
            </span>
          </div>
          <div className="text-3xl font-extrabold text-white mt-1">{totalFindings}</div>
          <div className="flex items-center space-x-3 text-[11px] mt-2">
            <span className="text-red-400 font-semibold">{criticalCount} Urgent</span>
            <span className="text-amber-400 font-semibold">{highCount} Moderate</span>
          </div>
        </div>
        <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
          <AlertTriangle className="w-7 h-7" />
        </div>
      </div>

      {/* 3. Estimated Time to Fix */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 flex items-center justify-between">
        <div>
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
            {viewMode === 'simple' ? 'Estimated Fix Time' : 'Est. Time-To-Remediate'}
          </span>
          <div className="text-3xl font-extrabold text-emerald-400 mt-1">{timeToRemediate || 'Not calculated'}</div>
        </div>
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
          <Clock className="w-7 h-7" />
        </div>
      </div>

      {/* 4. Verification Shield */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 flex items-center justify-between">
        <div>
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
            {viewMode === 'simple' ? 'Website Protection Shield' : 'Zero-Trust Guardrail'}
          </span>
          <div className="text-lg font-bold text-white mt-1 flex items-center gap-1.5">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            <span>Verification required</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-2">Scanning is restricted to verified sites</p>
        </div>
        <div className="p-3.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
          <CheckCircle2 className="w-7 h-7" />
        </div>
      </div>
    </div>
  );
}
