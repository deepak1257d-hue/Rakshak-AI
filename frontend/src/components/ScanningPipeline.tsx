'use client';

import React, { useCallback, useEffect, useState, useRef } from 'react';
import {
  Play,
  AlertTriangle,
  RefreshCw,
  Terminal,
  Activity,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Lock
} from 'lucide-react';
import { aegisApi } from '@/lib/api';
import { ScanRun, TargetAsset } from '@/lib/types';

interface ScanningPipelineProps {
  target: TargetAsset;
  activeScan: ScanRun | null;
  onScanComplete: (completedScan: ScanRun) => void;
  onProceedToFindings: () => void;
}

type ScanUpdate = Partial<Pick<
  ScanRun,
  'status' | 'progress_pct' | 'current_stage' | 'trace_id' | 'trace_url'
>>;

export default function ScanningPipeline({
  target,
  activeScan,
  onScanComplete,
  onProceedToFindings,
}: ScanningPipelineProps) {
  const [currentScan, setCurrentScan] = useState<ScanRun | null>(activeScan);
  const [isLaunching, setIsLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);
  const [telemetryNotice, setTelemetryNotice] = useState<string | null>(null);

  const [logs, setLogs] = useState<string[]>([]);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [showTerminal, setShowTerminal] = useState(true);

  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<number | null>(null);
  const currentScanRef = useRef<ScanRun | null>(activeScan);
  const connectedScanIdRef = useRef<string | null>(null);
  const handledTerminalScanIdsRef = useRef(new Set<string>());

  const isVerified = target.verification_status === 'VERIFIED';
  const isRunning = currentScan?.status === 'RUNNING' || currentScan?.status === 'QUEUED';
  const isCompleted = currentScan?.status === 'COMPLETED';
  const isPartial = currentScan?.status === 'PARTIAL';
  const isFailed = currentScan?.status === 'FAILED';

  const formatTime = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const rem = secs % 60;
    return `${mins.toString().padStart(2, '0')}:${rem.toString().padStart(2, '0')}`;
  };

  useEffect(() => {
    if (!isRunning || !currentScan?.started_at) return;
    const startedAt = Date.parse(currentScan.started_at);
    if (!Number.isFinite(startedAt)) return;

    const updateElapsedTime = () => {
      setElapsedSeconds(Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));
    };
    updateElapsedTime();
    const timer = window.setInterval(updateElapsedTime, 1000);
    return () => window.clearInterval(timer);
  }, [currentScan?.started_at, isRunning]);

  const handleScanUpdate = useCallback((scanId: string, data: ScanUpdate) => {
    const previous = currentScanRef.current;
    if (!previous || previous.id !== scanId) return;

    const validStatuses: ScanRun['status'][] = ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIAL'];
    const status = data.status && validStatuses.includes(data.status) ? data.status : previous.status;
    const progress = typeof data.progress_pct === 'number' && Number.isFinite(data.progress_pct)
      ? Math.min(100, Math.max(0, data.progress_pct))
      : previous.progress_pct;
    const updated: ScanRun = {
      ...previous,
      status,
      progress_pct: progress,
      current_stage: data.current_stage ?? previous.current_stage,
      trace_id: data.trace_id ?? previous.trace_id,
      trace_url: data.trace_url ?? previous.trace_url,
    };

    currentScanRef.current = updated;
    setCurrentScan(updated);
    setTelemetryError(null);

    if (updated.current_stage && updated.current_stage !== previous.current_stage) {
      setLogs((items) => [
        ...items,
        `[${new Date().toLocaleTimeString()}] [${updated.progress_pct}%] ${updated.current_stage}`,
      ]);
    }

    const isTerminal = ['COMPLETED', 'PARTIAL', 'FAILED'].includes(updated.status);
    if (!isTerminal || handledTerminalScanIdsRef.current.has(scanId)) return;

    handledTerminalScanIdsRef.current.add(scanId);
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    connectedScanIdRef.current = null;

    if (updated.status === 'COMPLETED' || updated.status === 'PARTIAL') {
      onScanComplete(updated);
    }
  }, [onScanComplete]);

  const startPolling = useCallback((scanId: string) => {
    if (pollRef.current) return;
    setTelemetryNotice('Live updates are unavailable. Scan status is being refreshed over HTTP.');

    const pollScan = async () => {
      try {
        const updated = await aegisApi.getScan(scanId);
        handleScanUpdate(scanId, updated);
      } catch (err) {
        setTelemetryError(err instanceof Error ? err.message : 'Could not refresh scan status.');
      }
    };

    void pollScan();
    pollRef.current = window.setInterval(() => {
      void pollScan();
    }, 3000);
  }, [handleScanUpdate]);

  const connectTelemetry = useCallback((scanId: string) => {
    if (connectedScanIdRef.current === scanId) return;
    connectedScanIdRef.current = scanId;

    if (wsRef.current) wsRef.current.close();
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }

    setTelemetryError(null);
    setTelemetryNotice(null);

    try {
      const ws = aegisApi.connectScanWebSocket(scanId, (data: ScanUpdate) => {
        handleScanUpdate(scanId, data);
      });

      ws.onopen = () => {
        setTelemetryNotice(null);
        setLogs((items) => [
          ...items,
          `[${new Date().toLocaleTimeString()}] Connected to live scan updates.`,
        ]);
      };
      ws.onerror = () => startPolling(scanId);
      ws.onclose = () => {
        const latest = currentScanRef.current;
        if (
          connectedScanIdRef.current === scanId &&
          (latest?.status === 'QUEUED' || latest?.status === 'RUNNING')
        ) {
          startPolling(scanId);
        }
      };

      wsRef.current = ws;
    } catch {
      startPolling(scanId);
    }
  }, [handleScanUpdate, startPolling]);

  const handleStartScan = async () => {
    if (!isVerified) return;
    setIsLaunching(true);
    setLaunchError(null);
    setTelemetryError(null);
    setTelemetryNotice(null);
    setLogs([
      `[${new Date().toLocaleTimeString()}] Sending scan request for ${target.domain}.`,
    ]);
    setElapsedSeconds(0);

    try {
      const scan = await aegisApi.launchScan(target.id);
      currentScanRef.current = scan;
      setCurrentScan(scan);
      handledTerminalScanIdsRef.current.delete(scan.id);
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] Scan ${scan.id} accepted with status ${scan.status}.`,
      ]);
      if (scan.status === 'QUEUED' || scan.status === 'RUNNING') {
        connectTelemetry(scan.id);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start security scan.';
      setLaunchError(message);
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] ERROR: ${message}`,
      ]);
    } finally {
      setIsLaunching(false);
    }
  };

  useEffect(() => {
    currentScanRef.current = activeScan;
    setCurrentScan(activeScan);
    if (activeScan?.status === 'RUNNING' || activeScan?.status === 'QUEUED') {
      connectTelemetry(activeScan.id);
    } else {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      if (pollRef.current) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
      connectedScanIdRef.current = null;
    }
  }, [activeScan, connectTelemetry]);

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  return (
    <div className="space-y-6">
      
      {/* Launch Control Banner */}
      <div className="p-6 md:p-8 rounded-2xl bg-gradient-to-r from-blue-950/40 via-slate-900/60 to-slate-900/60 border border-slate-800 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${isRunning ? 'bg-blue-400 animate-ping' : isCompleted ? 'bg-emerald-400' : 'bg-slate-500'}`} />
            <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
              Website security scan
              {isRunning && (
                <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {formatTime(elapsedSeconds)}
                </span>
              )}
            </h3>
          </div>
          <p className="text-xs text-slate-300 max-w-xl">
            Scan status, progress, and stage details shown here are reported by the backend.
          </p>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-3 self-start md:self-auto">
          {!isVerified ? (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2">
              <Lock className="w-4 h-4 shrink-0 text-amber-400" />
              <span>Verify ownership in Step 2 to unlock scanning</span>
            </div>
          ) : isRunning ? (
            <div className="px-5 py-2.5 rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-300 text-xs font-bold flex items-center gap-2.5 animate-pulse">
              <RefreshCw className="w-4 h-4 animate-spin text-blue-400" />
              <span>Scanning in Progress ({currentScan?.progress_pct || 0}%)</span>
            </div>
          ) : isCompleted || isPartial ? (
            <div className="flex items-center gap-2.5">
              <button
                onClick={handleStartScan}
                disabled={isLaunching}
                className="px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white text-xs font-medium flex items-center gap-2 transition-all"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLaunching ? 'animate-spin' : ''}`} />
                <span>Re-run Scan</span>
              </button>
              <button
                onClick={onProceedToFindings}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold shadow-lg shadow-emerald-600/25 flex items-center gap-2 transition-all"
              >
                <span>View Security Findings</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              onClick={handleStartScan}
              disabled={isLaunching}
              className="px-6 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-bold shadow-lg shadow-blue-600/25 flex items-center gap-2.5 transition-all"
            >
              {isLaunching ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Starting scan...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Start security scan</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {launchError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span role="alert">{launchError}</span>
        </div>
      )}

      {telemetryNotice && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200 text-xs">
          {telemetryNotice}
        </div>
      )}

      {telemetryError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span role="alert">{telemetryError}</span>
        </div>
      )}

      {isPartial && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs space-y-1">
          <div className="flex items-center gap-2 font-bold text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
            <span>Backend reported a partial scan</span>
          </div>
          <p className="text-slate-300">
            Results may be incomplete. Review the backend-reported stage and findings before drawing conclusions.
          </p>
        </div>
      )}

      {isFailed && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-200 text-xs space-y-1">
          <div className="flex items-center gap-2 font-bold text-rose-300">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>Backend reported that the scan failed</span>
          </div>
          <p className="text-slate-300">
            {currentScan.current_stage || 'The backend did not provide a failure stage.'}
          </p>
        </div>
      )}

      {currentScan && (
        <div
          className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3"
          role="status"
          aria-live="polite"
        >
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              Backend scan status: {currentScan.status}
            </span>
            <span className="font-mono font-bold text-blue-400">
              {Math.min(100, Math.max(0, currentScan.progress_pct || 0))}%
            </span>
          </div>
          <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden p-0.5 border border-slate-800">
            <div
              className="h-full bg-gradient-to-r from-blue-600 via-cyan-500 to-emerald-400 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(100, Math.max(0, currentScan.progress_pct || 0))}%` }}
            />
          </div>
          <p className="text-[11px] text-slate-400 font-mono truncate">
            Current stage: <span className="text-slate-200">{currentScan.current_stage || 'Not provided by backend.'}</span>
          </p>
          <p className="text-[11px] text-slate-500 font-mono break-all">Scan ID: {currentScan.id}</p>
        </div>
      )}

      <div className="rounded-2xl border border-slate-800 bg-[#090d16] overflow-hidden">
        <button
          type="button"
          onClick={() => setShowTerminal(!showTerminal)}
          aria-expanded={showTerminal}
          className="w-full px-4 py-3 border-b border-slate-800/80 bg-slate-950/60 flex items-center justify-between text-left hover:bg-slate-900/60 transition-colors"
        >
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300">
            <Terminal className="w-4 h-4 text-blue-400" />
            <span>Scan activity</span>
            <span className="text-[10px] text-slate-500 font-sans font-normal">
              ({logs.length} updates)
            </span>
          </div>

          <span className="text-slate-400" aria-hidden="true">
            {showTerminal ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </span>
        </button>

        {showTerminal && (
          <div className="p-4 max-h-56 overflow-y-auto font-mono text-[11px] text-slate-300 space-y-1.5 select-text">
            {logs.length === 0 ? (
              <p className="text-slate-500 italic">
                Scan activity will appear here when a scan is started.
              </p>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="leading-relaxed flex items-start gap-2">
                  <span className="text-blue-500 shrink-0">›</span>
                  <span className={log.includes('ERROR') ? 'text-rose-400' : log.includes('COMPLETED') ? 'text-emerald-400' : 'text-slate-300'}>
                    {log}
                  </span>
                </div>
              ))
            )}
          </div>
        )}
      </div>

    </div>
  );
}
