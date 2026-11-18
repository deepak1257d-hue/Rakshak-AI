'use client';
import React, { useState } from 'react';
import { TargetAsset, ScanRun } from '../lib/types';
import { PlayCircle, ShieldCheck, Loader2, CheckCircle2, AlertTriangle, Play, ShieldAlert, Cpu } from 'lucide-react';

interface ScansViewProps {
  targets: TargetAsset[];
  activeScan: ScanRun | null;
  onLaunchScan: (targetId: string, profile: 'QUICK' | 'STANDARD' | 'DEEP') => Promise<void>;
}

export default function ScansView({
  targets,
  activeScan,
  onLaunchScan
}: ScansViewProps) {
  const verifiedTargets = targets.filter(t => t.verification_status === 'VERIFIED');
  const [selectedTargetId, setSelectedTargetId] = useState<string>(
    verifiedTargets.length > 0 ? verifiedTargets[0].id : ''
  );
  const [selectedProfile, setSelectedProfile] = useState<'QUICK' | 'STANDARD' | 'DEEP'>('STANDARD');
  const [starting, setStarting] = useState(false);

  const handleStart = async () => {
    if (!selectedTargetId) return;
    setStarting(true);
    try {
      await onLaunchScan(selectedTargetId, selectedProfile);
    } finally {
      setStarting(false);
    }
  };

  const isRunning = activeScan?.status === 'RUNNING';

  const scanStages = [
    { id: 1, label: 'Target Verification', pct: 15 },
    { id: 2, label: 'Asset Discovery', pct: 35 },
    { id: 3, label: 'Security Analysis', pct: 60 },
    { id: 4, label: 'Vulnerability Assessment', pct: 80 },
    { id: 5, label: 'Risk Calculation', pct: 90 },
    { id: 6, label: 'Report Generation', pct: 100 }
  ];

  const currentPct = activeScan ? activeScan.progress_pct : 0;

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <PlayCircle className="w-5 h-5 text-blue-400" />
          Security Scan Command Center
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Execute authorized vulnerability scans, configuration audits, and threat exposure assessments.
        </p>
      </div>

      {/* Launcher Panel */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Target Selection */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 block">Select Target Asset:</label>
            {verifiedTargets.length === 0 ? (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>No verified target assets found. Please verify domain ownership first.</span>
              </div>
            ) : (
              <select
                value={selectedTargetId}
                onChange={e => setSelectedTargetId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
              >
                {verifiedTargets.map(t => (
                  <option key={t.id} value={t.id}>
                    {t.domain} (✓ Verified)
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Profile Selection */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 block">Select Scan Profile:</label>
            <div className="grid grid-cols-3 gap-2">
              <button
                onClick={() => setSelectedProfile('QUICK')}
                className={`p-2.5 rounded-xl border text-center font-mono text-xs transition-all ${
                  selectedProfile === 'QUICK' ? 'bg-blue-600/20 border-blue-500 text-white font-bold' : 'bg-slate-900 border-slate-800 text-slate-400'
                }`}
              >
                Quick Scan
              </button>

              <button
                onClick={() => setSelectedProfile('STANDARD')}
                className={`p-2.5 rounded-xl border text-center font-mono text-xs transition-all ${
                  selectedProfile === 'STANDARD' ? 'bg-blue-600/20 border-blue-500 text-white font-bold' : 'bg-slate-900 border-slate-800 text-slate-400'
                }`}
              >
                Standard Scan
              </button>

              <button
                onClick={() => setSelectedProfile('DEEP')}
                className={`p-2.5 rounded-xl border text-center font-mono text-xs transition-all ${
                  selectedProfile === 'DEEP' ? 'bg-blue-600/20 border-blue-500 text-white font-bold' : 'bg-slate-900 border-slate-800 text-slate-400'
                }`}
              >
                Deep Scan
              </button>
            </div>
          </div>

        </div>

        {/* Scan Button */}
        <div className="flex justify-end pt-2 border-t border-slate-800/80">
          <button
            onClick={handleStart}
            disabled={starting || isRunning || verifiedTargets.length === 0}
            className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/25 flex items-center gap-2 transition-all disabled:opacity-50"
          >
            {starting || isRunning ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-white" />
            )}
            <span>{isRunning ? 'Scan Executing...' : 'Start Security Scan'}</span>
          </button>
        </div>

      </div>

      {/* Progress Timeline Stepper */}
      {activeScan && (
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" />
              Scan Progress Timeline
            </h3>
            <span className="text-xs font-mono font-bold text-blue-400">{currentPct}% Completed</span>
          </div>

          {/* Progress Bar */}
          <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-blue-600 via-indigo-500 to-emerald-400 transition-all duration-500"
              style={{ width: `${currentPct}%` }}
            />
          </div>

          {/* Timeline Stages */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 pt-2 text-xs font-mono">
            {scanStages.map(stage => {
              const isCompleted = currentPct >= stage.pct;
              const isCurrent = currentPct < stage.pct && currentPct >= stage.pct - 20;

              return (
                <div
                  key={stage.id}
                  className={`p-2.5 rounded-xl border text-center transition-all ${
                    isCompleted
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                      : isCurrent
                      ? 'bg-blue-500/10 border-blue-500/30 text-blue-400 animate-pulse'
                      : 'bg-slate-900/50 border-slate-800 text-slate-500'
                  }`}
                >
                  <div className="text-[10px] font-bold block">
                    {isCompleted ? '✓' : isCurrent ? '●' : '○'}
                  </div>
                  <span className="text-[11px] truncate block mt-0.5">{stage.label}</span>
                </div>
              );
            })}
          </div>
          {/* Partial Results / Fallback Alert Banner */}
          {activeScan.status === 'PARTIAL' && (
            <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">Partial Assessment State:</span> One or more scanners timed out or failed. Automated fallbacks were triggered, and partial security findings have been preserved.
                <div className="text-[11px] text-amber-400/80 mt-0.5 font-mono">
                  Stage: {activeScan.current_stage}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  );
}
