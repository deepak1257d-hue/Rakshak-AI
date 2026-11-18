'use client';
import React, { useState } from 'react';
import {
  Search, Bell, Play, ShieldAlert, CheckCircle2, AlertTriangle, X, Activity, Globe, RefreshCw
} from 'lucide-react';
import { NotificationItem } from '../lib/types';

interface TopNavProps {
  notifications: NotificationItem[];
  onOpenScanModal: () => void;
  onSearch?: (query: string) => void;
}

export default function TopNav({ notifications, onOpenScanModal, onSearch }: TopNavProps) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const unreadCount = notifications.filter(n => !n.read).length;

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
    if (onSearch) onSearch(e.target.value);
  };

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#070b14]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40 select-none">
      
      {/* Left: Environment Indicator */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2.5 bg-slate-900/90 border border-slate-800 rounded-xl px-3.5 py-1.5">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xs font-semibold text-slate-200">Production Environment</span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
            Active
          </span>
        </div>
      </div>

      {/* Center: Global Search Bar */}
      <div className="flex-1 max-w-md mx-6 hidden md:block">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search assets, CVEs, ports, findings..."
            value={searchQuery}
            onChange={handleSearchChange}
            className="w-full bg-slate-900/80 border border-slate-800 rounded-xl pl-10 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-all font-mono"
          />
        </div>
      </div>

      {/* Right: Quick Scan Launcher & Notifications */}
      <div className="flex items-center space-x-4">
        
        {/* Quick Scan Launcher Button */}
        <button
          onClick={onOpenScanModal}
          className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/25 flex items-center gap-2 transition-all active:scale-95"
        >
          <Play className="w-3.5 h-3.5 fill-white" />
          <span>New Security Scan</span>
        </button>

        {/* Notification Bell Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 text-slate-300 relative transition-colors"
            title="Notifications"
          >
            <Bell className="w-4 h-4 text-slate-300" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center font-mono">
                {unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Popover */}
          {showNotifications && (
            <div className="absolute right-0 mt-3 w-80 sm:w-96 bg-[#0f172a] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden z-50 animate-in fade-in zoom-in-95 duration-150">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
                <div className="flex items-center space-x-2">
                  <Bell className="w-4 h-4 text-blue-400" />
                  <h4 className="text-xs font-bold text-white">Security Alerts & Events</h4>
                </div>
                <button
                  onClick={() => setShowNotifications(false)}
                  className="text-slate-400 hover:text-white text-xs"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="divide-y divide-slate-800/60 max-h-80 overflow-y-auto">
                {notifications.map(n => (
                  <div key={n.id} className="p-3.5 hover:bg-slate-900/50 transition-colors flex items-start space-x-3">
                    <div className="mt-0.5 shrink-0">
                      {n.severity === 'CRITICAL' || n.severity === 'HIGH' ? (
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                      ) : n.severity === 'MEDIUM' ? (
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      )}
                    </div>
                    <div className="flex-1 truncate">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-200 truncate">{n.title}</span>
                        <span className="text-[10px] text-slate-400 font-mono shrink-0 ml-2">{n.timestamp}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2 leading-relaxed">
                        {n.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

      </div>
    </header>
  );
}
