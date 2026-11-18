'use client';
import React from 'react';
import { AttackSurfaceItem } from '../lib/types';
import { Layers, Server, Globe, ShieldAlert, Cpu, Lock, Terminal } from 'lucide-react';

interface AttackSurfaceViewProps {
  items: AttackSurfaceItem[];
}

export default function AttackSurfaceView({ items }: AttackSurfaceViewProps) {
  const getExposureBadge = (status: string) => {
    switch (status) {
      case 'HIGH': return 'bg-red-500/15 border-red-500/30 text-red-400';
      case 'MEDIUM': return 'bg-amber-500/15 border-amber-500/30 text-amber-400';
      case 'LOW': return 'bg-blue-500/15 border-blue-500/30 text-blue-400';
      default: return 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400';
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Layers className="w-5 h-5 text-blue-400" />
          External Attack Surface & Exposure Index
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Discovered domains, subdomains, open server ports, services, TLS parameters, and tech stacks.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">Monitored Domains</span>
          <span className="text-2xl font-bold text-white font-mono mt-1 block">2 Domains</span>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">Reachable Public Services</span>
          <span className="text-2xl font-bold text-amber-400 font-mono mt-1 block">1 Service (SSH)</span>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">Detected Stack Tech</span>
          <span className="text-2xl font-bold text-white font-mono mt-1 block">4 Components</span>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold block">TLS Protocol State</span>
          <span className="text-2xl font-bold text-emerald-400 font-mono mt-1 block">TLS 1.3 Valid</span>
        </div>
      </div>

      {/* Discovered Items List */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-400" />
          Discovered Exposure Inventory
        </h3>

        <div className="divide-y divide-slate-800/80">
          {items.map(item => (
            <div key={item.id} className="py-3.5 flex items-center justify-between text-xs font-mono">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getExposureBadge(item.exposure_status)}`}>
                    {item.exposure_status}
                  </span>
                  <span className="text-slate-200 font-bold">{item.label}</span>
                </div>
                <p className="text-[11px] text-slate-400">{item.detail}</p>
              </div>

              <div className="text-right">
                <span className="text-slate-500 text-[10px] block">Asset</span>
                <span className="text-slate-300 font-semibold">{item.asset_domain}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
