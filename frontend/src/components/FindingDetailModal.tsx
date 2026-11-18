'use client';
import React, { useState } from 'react';
import { Finding } from '../lib/types';
import {
  ShieldAlert, AlertTriangle, CheckCircle2, Code, Terminal, GitPullRequest, Copy, Check, X,
  ShieldCheck, Wrench, Download, Cpu, Info, Server, Globe
} from 'lucide-react';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onAskAi?: (finding: Finding) => void;
  onMarkResolved?: (findingId: string) => void;
}

export default function FindingDetailModal({
  finding,
  onClose,
  onAskAi,
  onMarkResolved
}: FindingDetailModalProps) {
  const [copied, setCopied] = useState(false);
  const [patchPrepared, setPatchPrepared] = useState(false);

  if (!finding) return null;

  const copyCode = () => {
    if (finding.remediation_patch) {
      navigator.clipboard.writeText(finding.remediation_patch);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const downloadPatchFile = () => {
    if (!finding.remediation_patch) return;
    const blob = new Blob([finding.remediation_patch], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `remediation-${finding.id}.patch`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePreparePatch = () => {
    setPatchPrepared(true);
    setTimeout(() => setPatchPrepared(false), 4000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'MEDIUM': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default: return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl bg-[#0b1120] border-l border-slate-800 shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-300">
      
      {/* Header */}
      <div className="p-6 border-b border-slate-800 sticky top-0 bg-[#0b1120]/95 backdrop-blur-md flex items-start justify-between z-10">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className={`px-3 py-1 rounded-md border font-semibold text-xs ${getSeverityBadge(finding.severity)}`}>
              {finding.severity}
            </span>
            <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 font-mono text-xs">
              {finding.finding_type}
            </span>
            {finding.cve_id && (
              <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 font-mono text-xs">
                {finding.cve_id}
              </span>
            )}
            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-mono">
              Status: {finding.status}
            </span>
          </div>
          <h2 className="text-lg font-bold text-white leading-tight">{finding.title}</h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Affected Asset: <strong className="text-blue-400">{finding.affected_asset}</strong>
            {finding.port && ` | Port: ${finding.port}`}
          </p>
        </div>
        <button onClick={onClose} className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Body */}
      <div className="p-6 space-y-6">
        
        {/* Detection Method & Confidence Metadata */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 grid grid-cols-2 gap-4 text-xs font-mono">
          <div>
            <span className="text-slate-500 block">Detection Method:</span>
            <span className="text-slate-200 font-medium">{finding.detection_method}</span>
          </div>
          <div>
            <span className="text-slate-500 block">Confidence Rating:</span>
            <span className="text-emerald-400 font-bold">{finding.confidence}</span>
          </div>
        </div>

        {/* Technical Description */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <Info className="w-4 h-4 text-blue-400" />
            Technical Description
          </h3>
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 text-xs text-slate-200 leading-relaxed">
            {finding.technical_description}
          </div>
        </div>

        {/* Security Impact */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Security Impact
          </h3>
          <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 text-xs text-amber-200/90 leading-relaxed">
            {finding.security_impact}
          </div>
        </div>

        {/* Observed Scan Evidence */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            Observed Scan Evidence
          </h3>
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed overflow-x-auto">
            {finding.evidence}
          </div>
        </div>

        {/* Recommended Code Remediation */}
        {finding.remediation_patch && (
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Wrench className="w-4 h-4 text-emerald-400" />
                Recommended Remediation Configuration
              </h3>
              <div className="flex items-center space-x-2">
                <button
                  onClick={copyCode}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Fix'}</span>
                </button>
                <button
                  onClick={downloadPatchFile}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Patch</span>
                </button>
              </div>
            </div>

            {finding.remediation_explanation && (
              <p className="text-xs text-slate-300 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
                💡 {finding.remediation_explanation}
              </p>
            )}

            <div className="bg-[#050811] border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-200 overflow-x-auto">
              {finding.remediation_patch.split('\n').map((line, idx) => {
                let colorClass = 'text-slate-300';
                if (line.startsWith('+')) colorClass = 'text-emerald-400 bg-emerald-500/10 px-1 py-0.5 rounded';
                if (line.startsWith('-')) colorClass = 'text-red-400 bg-red-500/10 px-1 py-0.5 rounded';
                if (line.startsWith('#') || line.startsWith('//')) colorClass = 'text-slate-500 italic';
                return (
                  <div key={idx} className={`${colorClass} py-0.5`}>
                    {line}
                  </div>
                );
              })}
            </div>

            {/* Prepare Patch & AI Assistant Buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <button
                onClick={handlePreparePatch}
                className="py-3 px-4 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 transition-all"
              >
                <GitPullRequest className="w-4 h-4" />
                <span>{patchPrepared ? '✅ Patch Bundle Prepared!' : 'Prepare Patch / Pull Request'}</span>
              </button>

              {onAskAi && (
                <button
                  onClick={() => {
                    onAskAi(finding);
                    onClose();
                  }}
                  className="py-3 px-4 rounded-xl bg-indigo-600/20 hover:bg-indigo-600 text-indigo-300 hover:text-white border border-indigo-500/30 font-bold text-xs flex items-center justify-center gap-2 transition-all"
                >
                  <Cpu className="w-4 h-4 text-indigo-400" />
                  <span>Ask AI Analyst About Finding</span>
                </button>
              )}
            </div>

          </div>
        )}

      </div>
    </div>
  );
}
