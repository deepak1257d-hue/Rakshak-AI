'use client';
import React from 'react';
import { ShieldAlert, HelpCircle } from 'lucide-react';

interface SecurityScoreGaugeProps {
  score: number | null;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  onOpenMethodology: () => void;
}

export default function SecurityScoreGauge({
  score,
  criticalCount,
  highCount,
  mediumCount,
  lowCount,
  onOpenMethodology
}: SecurityScoreGaugeProps) {
  // Score status text & color mapping
  const getScoreInfo = (val: number | null) => {
    if (val === null) return { label: 'Not calculated', color: 'text-slate-400', stroke: '#64748b', bg: 'bg-slate-800/50 border-slate-700' };
    if (val >= 90) return { label: 'Critical CVSS', color: 'text-red-400', stroke: '#ef4444', bg: 'bg-red-500/10 border-red-500/30' };
    if (val >= 70) return { label: 'High CVSS', color: 'text-orange-400', stroke: '#f97316', bg: 'bg-orange-500/10 border-orange-500/30' };
    if (val >= 40) return { label: 'Medium CVSS', color: 'text-amber-400', stroke: '#f59e0b', bg: 'bg-amber-500/10 border-amber-500/30' };
    return { label: 'Low CVSS', color: 'text-blue-400', stroke: '#60a5fa', bg: 'bg-blue-500/10 border-blue-500/30' };
  };

  const status = getScoreInfo(score);
  const strokeDashoffset = score === null ? 251.2 : 251.2 - (251.2 * score) / 100;

  return (
    <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col justify-between relative overflow-hidden group">
      
      {/* Top Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Scaled CVSS Base Score</h3>
          <span className={`text-[11px] font-semibold ${status.color}`}>{status.label}</span>
        </div>
        <button
          onClick={onOpenMethodology}
          className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-colors flex items-center gap-1 text-[11px]"
          title="Scoring Methodology"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          <span>Calculation</span>
        </button>
      </div>

      {/* Main Gauge & Score Display */}
      <div className="flex items-center justify-between my-2">
        <div>
          <div className="flex items-baseline space-x-2">
            <span className="text-4xl font-extrabold text-white font-mono tracking-tight">{score ?? '—'}</span>
            {score !== null && <span className="text-sm font-medium text-slate-500">/ 100</span>}
          </div>

          <div className="mt-3 text-xs text-slate-300">
            {score === null
              ? 'No catalogued CVSS base score is available.'
              : 'Based on a curated CVSS v3.1 base score; no environmental modifiers are applied.'}
          </div>
        </div>

        {/* SVG Semi-Circular Security Gauge */}
        <div className="relative w-24 h-24 flex items-center justify-center">
          <svg className="w-24 h-24 transform -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="40"
              className="text-slate-800"
              strokeWidth="8"
              stroke="currentColor"
              fill="transparent"
            />
            <circle
              cx="50"
              cy="50"
              r="40"
              stroke={status.stroke}
              strokeWidth="8"
              strokeDasharray="251.2"
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <ShieldAlert className={`w-8 h-8 ${status.color}`} />
          </div>
        </div>
      </div>

      {/* Bottom Severity Breakdown Badges */}
      <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-4 gap-2 text-center text-xs">
        <div className="p-2 rounded-xl bg-red-500/10 border border-red-500/20">
          <span className="text-[10px] text-red-400 uppercase font-semibold block">Critical</span>
          <span className="text-sm font-bold text-red-400 font-mono">{criticalCount}</span>
        </div>
        <div className="p-2 rounded-xl bg-orange-500/10 border border-orange-500/20">
          <span className="text-[10px] text-orange-400 uppercase font-semibold block">High</span>
          <span className="text-sm font-bold text-orange-400 font-mono">{highCount}</span>
        </div>
        <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20">
          <span className="text-[10px] text-amber-400 uppercase font-semibold block">Medium</span>
          <span className="text-sm font-bold text-amber-400 font-mono">{mediumCount}</span>
        </div>
        <div className="p-2 rounded-xl bg-slate-800/60 border border-slate-700/50">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">Low</span>
          <span className="text-sm font-bold text-slate-300 font-mono">{lowCount}</span>
        </div>
      </div>

    </div>
  );
}
