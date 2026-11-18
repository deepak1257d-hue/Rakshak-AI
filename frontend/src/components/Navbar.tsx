import React from 'react';
import { Shield, CheckCircle2, HelpCircle } from 'lucide-react';

interface NavbarProps {
  viewMode?: 'simple' | 'technical';
  onToggleViewMode?: () => void;
  onOpenGuide?: () => void;
}

export default function Navbar({ viewMode = 'simple', onToggleViewMode, onOpenGuide }: NavbarProps) {
  return (
    <nav className="h-16 border-b border-slate-800 bg-[#0b1120]/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      <div className="flex items-center space-x-3">
        <div className="p-2 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400">
          <Shield className="w-6 h-6 animate-pulse" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-lg text-white tracking-wider">AEGIS AI</span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
              Website Protection v1.0
            </span>
          </div>
          <p className="text-xs text-slate-400">Simple & Automated Website Security Monitor</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {/* Toggle Mode Button */}
        {onToggleViewMode && (
          <button
            onClick={onToggleViewMode}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:border-slate-700 transition-colors flex items-center gap-1.5"
            title="Switch between Plain English and Technical terminology"
          >
            <span className="text-slate-500">Mode:</span>
            <span className="font-bold text-blue-400">
              {viewMode === 'simple' ? '🌱 Plain English View' : '⚙️ Technical View'}
            </span>
          </button>
        )}

        {/* Quick Help Guide Button */}
        {onOpenGuide && (
          <button
            onClick={onOpenGuide}
            className="px-3 py-1.5 rounded-lg bg-blue-600/10 border border-blue-500/30 text-xs text-blue-300 hover:bg-blue-600/20 transition-colors flex items-center gap-1.5"
          >
            <HelpCircle className="w-4 h-4 text-blue-400" />
            <span>Security Guide</span>
          </button>
        )}

        <div className="hidden md:flex items-center space-x-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-400">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>Automated AI Guard: <strong className="text-emerald-400">Active & Protecting</strong></span>
        </div>

        <div className="flex items-center space-x-3 border-l border-slate-800 pl-4">
          <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-lg shadow-blue-600/30">
            AO
          </div>
          <div className="hidden sm:block">
            <div className="text-xs font-medium text-white">Account Owner</div>
            <div className="text-[10px] text-slate-400">Website Admin</div>
          </div>
        </div>
      </div>
    </nav>
  );
}
