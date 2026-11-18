'use client';
import React from 'react';
import { MonitoringLog } from '../lib/types';
import { Activity, Clock, ShieldCheck, RefreshCw, CheckCircle2, AlertOctagon } from 'lucide-react';

interface MonitoringViewProps {
  logs: MonitoringLog[];
}

export default function MonitoringView({ logs }: MonitoringViewProps) {
  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Activity className="w-5 h-5 text-emerald-400" />
            Continuous Security Monitoring
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time automated auditing for DNS drift, TLS certificate expiration, HTTP header changes, and network exposure.
          </p>
        </div>

        <div className="flex items-center space-x-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-2 text-xs text-emerald-400 font-semibold font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span>Monitoring Active</span>
        </div>
      </div>

      {/* Monitoring Controls & Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">Last Security Check</span>
          <span className="text-lg font-bold text-white font-mono mt-1 block">4 minutes ago</span>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">Next Scheduled Audit</span>
          <span className="text-lg font-bold text-blue-400 font-mono mt-1 block">In 56 minutes</span>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">TLS Cert Expiration</span>
          <span className="text-lg font-bold text-emerald-400 font-mono mt-1 block">84 Days Remaining</span>
        </div>

        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">DNS & Header Drift</span>
          <span className="text-lg font-bold text-white font-mono mt-1 block">No Drift Detected</span>
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-400" />
          Real-Time Monitoring Event Stream
        </h3>

        <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {logs.map(log => (
            <div key={log.id} className="relative flex items-start justify-between text-xs font-mono">
              <div className="absolute -left-6 top-0.5 w-2.5 h-2.5 rounded-full bg-blue-500 border-2 border-[#090d16]" />
              
              <div className="space-y-1">
                <span className="text-slate-400 text-[10px] block">{log.timestamp}</span>
                <p className="text-slate-200 font-semibold">{log.message}</p>
              </div>

              <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 shrink-0">
                {log.asset}
              </span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
