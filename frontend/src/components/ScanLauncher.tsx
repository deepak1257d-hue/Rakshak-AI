'use client';
import React, { useState, useEffect } from 'react';
import { TargetAsset, ScanRun } from '../lib/types';
import { Play, CheckCircle2, Loader2, AlertTriangle, ShieldCheck, ArrowRight, HelpCircle } from 'lucide-react';

interface ScanLauncherProps {
  targets: TargetAsset[];
  activeScan: ScanRun | null;
  onLaunchScan: (targetId: string) => Promise<void>;
  onOpenVerifyModal: (target: TargetAsset) => void;
  viewMode?: 'simple' | 'technical';
}

export default function ScanLauncher({
  targets,
  activeScan,
  onLaunchScan,
  onOpenVerifyModal,
  viewMode = 'simple'
}: ScanLauncherProps) {
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    if (targets.length === 0) {
      if (selectedTargetId) setSelectedTargetId('');
      return;
    }
    if (!targets.some((target) => target.id === selectedTargetId)) {
      setSelectedTargetId(targets[0].id);
    }
  }, [targets, selectedTargetId]);

  const selectedTarget = targets.find(t => t.id === selectedTargetId);
  const isVerified = selectedTarget?.verification_status === 'VERIFIED';

  const handleLaunch = async () => {
    if (!selectedTargetId || !isVerified) return;
    setLaunching(true);
    try {
      await onLaunchScan(selectedTargetId);
    } finally {
      setLaunching(false);
    }
  };

  const getFriendlyStageText = (rawStage: string) => {
    if (viewMode === 'technical') return rawStage;
    if (rawStage.includes('STAGE 1')) return 'Step 1 of 4: Checking website structure & connected pages...';
    if (rawStage.includes('STAGE 2')) return 'Step 2 of 4: Testing server for open security doors & outdated software...';
    if (rawStage.includes('STAGE 3')) return 'Step 3 of 4: Analyzing findings & generating automated code fixes...';
    if (rawStage.includes('STAGE 4')) return 'Step 4 of 4: Security check complete! View your report below.';
    return rawStage;
  };

  return (
    <div className="glass-panel p-6 rounded-2xl border border-slate-800 mb-8 relative overflow-hidden">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping" />
            <h2 className="text-lg font-bold text-white">
              {viewMode === 'simple' ? 'Start Automated Security Check' : 'Continuous Threat Exposure Audit Launcher'}
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            {viewMode === 'simple'
              ? 'Run an instant safety check on your website to discover vulnerabilities, open ports, and missing security rules.'
              : 'Execute sandboxed multi-agent swarm audits with zero-hallucination exploit verification.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Target Selector */}
          <div className="flex flex-col">
            <label className="text-[10px] text-slate-400 font-medium mb-1">Select Website to Check:</label>
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-2 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
            >
              {targets.map(t => (
                <option key={t.id} value={t.id}>
                  {t.domain} ({t.verification_status === 'VERIFIED' ? 'Verified ✅' : 'Needs Verification ⚠️'})
                </option>
              ))}
            </select>
          </div>

          <div className="self-end">
            {isVerified ? (
              <button
                onClick={handleLaunch}
                disabled={launching || (activeScan?.status === 'RUNNING')}
                className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/30 flex items-center gap-2 transition-all disabled:opacity-50"
              >
                {launching || activeScan?.status === 'RUNNING' ? (
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                ) : (
                  <Play className="w-4 h-4 fill-white" />
                )}
                <span>
                  {activeScan?.status === 'RUNNING'
                    ? 'Security Check Running...'
                    : viewMode === 'simple' ? '🚀 Start Security Check' : 'Launch Multi-Agent Audit'}
                </span>
              </button>
            ) : (
              <button
                onClick={() => selectedTarget && onOpenVerifyModal(selectedTarget)}
                className="px-5 py-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20 font-bold text-xs flex items-center gap-2 transition-all"
              >
                <AlertTriangle className="w-4 h-4" />
                <span>Verify Website Ownership</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Live Stage Stepper when scan is active */}
      {activeScan && (
        <div className="mt-6 pt-6 border-t border-slate-800/80">
          <div className="flex items-center justify-between text-xs mb-2">
            <span className="text-blue-400 font-semibold flex items-center gap-2">
              <Loader2 className={`w-3.5 h-3.5 ${activeScan.status === 'RUNNING' ? 'animate-spin' : ''}`} />
              {getFriendlyStageText(activeScan.current_stage)}
            </span>
            <span className="text-slate-400 font-mono">{activeScan.progress_pct}%</span>
          </div>

          <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-blue-600 via-accent to-emerald-400 transition-all duration-500"
              style={{ width: `${activeScan.progress_pct}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
