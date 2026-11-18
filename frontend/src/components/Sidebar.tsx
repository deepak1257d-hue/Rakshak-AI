'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield, Home, Globe, Clock, LogOut,
  ChevronRight, ChevronLeft, PanelLeftClose, PanelLeftOpen
} from 'lucide-react';
import { aegisApi, AuthUser } from '../lib/api';

interface SidebarProps {
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  isMobile?: boolean;
}

export default function Sidebar({
  isCollapsed = false,
  onToggleCollapse,
  isMobile = false
}: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    setUser(aegisApi.getUser());
  }, [pathname]);

  const navItems = [
    { label: 'Home', href: '/', icon: Home },
    { label: 'My Websites', href: '/websites', icon: Globe },
    { label: 'History', href: '/history', icon: Clock },
  ];

  const handleLogout = () => {
    aegisApi.logout();
    router.push('/');
    router.refresh();
  };

  return (
    <aside
      className={`h-full bg-[#080d1a] border-r border-slate-800/80 flex flex-col justify-between shrink-0 select-none ${
        isCollapsed ? 'w-16' : 'w-60'
      } transition-all duration-300 relative`}
      aria-label="Main Navigation"
    >
      <div>
        {/* Brand Header */}
        <div className={`p-4 border-b border-slate-800/80 flex items-center justify-between ${isCollapsed ? 'justify-center px-2' : ''}`}>
          <Link
            href="/"
            className="flex items-center space-x-3 group transition-colors focus:outline-none"
            title="AEGIS Home"
          >
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-600 via-cyan-500 to-cyan-400 flex items-center justify-center text-white shadow-md shadow-cyan-500/20 border border-cyan-400/40 shrink-0">
              <Shield className="w-4 h-4" />
            </div>
            {!isCollapsed && (
              <div>
                <div className="flex items-center space-x-1.5">
                  <span className="font-extrabold text-sm text-white tracking-tight">AEGIS</span>
                </div>
                <p className="text-[10px] text-slate-400 tracking-tight">Security workspace</p>
              </div>
            )}
          </Link>

          {!isMobile && onToggleCollapse && !isCollapsed && (
            <button
              onClick={onToggleCollapse}
              className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
              title="Collapse sidebar (Ctrl+B)"
              aria-label="Collapse sidebar"
            >
              <PanelLeftClose className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Collapsed expand toggle button */}
        {!isMobile && isCollapsed && onToggleCollapse && (
          <div className="flex justify-center py-2 border-b border-slate-800/60">
            <button
              onClick={onToggleCollapse}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
              title="Expand sidebar (Ctrl+B)"
              aria-label="Expand sidebar"
            >
              <PanelLeftOpen className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Navigation Links */}
        <nav className="p-2 space-y-1" aria-label="Sidebar Menu">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = item.href === '/'
              ? pathname === '/'
              : pathname.startsWith(item.href);

            return (
              <Link
                key={item.href}
                href={item.href}
                title={isCollapsed ? item.label : undefined}
                aria-label={isCollapsed ? item.label : undefined}
                aria-current={isActive ? 'page' : undefined}
                className={`w-full flex items-center ${isCollapsed ? 'justify-center px-2 py-3' : 'justify-between px-3 py-2.5'} rounded-xl text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-blue-600/20 to-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-semibold shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <div className={`flex items-center ${isCollapsed ? '' : 'space-x-3'}`}>
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  {!isCollapsed && <span>{item.label}</span>}
                </div>
                {!isCollapsed && isActive && (
                  <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Footer User Info & Logout */}
      <div className="p-3 border-t border-slate-800/80 space-y-2">
        {user ? (
          <div className={`rounded-xl bg-slate-900/60 border border-slate-800/80 ${isCollapsed ? 'p-2 flex justify-center' : 'p-2.5'}`}>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center space-x-2.5 truncate">
                <div className="w-7 h-7 rounded-lg bg-blue-600/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center font-bold text-xs shrink-0 font-mono">
                  {user.email.substring(0, 2).toUpperCase()}
                </div>
                {!isCollapsed && (
                  <div className="truncate min-w-0">
                    <div className="text-xs font-semibold text-slate-200 truncate">{user.email.split('@')[0]}</div>
                    <div className="text-[10px] text-slate-400 truncate capitalize">{user.role.toLowerCase().replace('_', ' ')}</div>
                  </div>
                )}
              </div>
              {!isCollapsed && (
                <button
                  onClick={handleLogout}
                  title="Sign out"
                  className="text-slate-400 hover:text-rose-400 transition-colors p-1 rounded-lg hover:bg-slate-800/60"
                  aria-label="Logout"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        ) : (
          !isCollapsed && (
            <div className="p-2 rounded-xl bg-slate-900/40 border border-slate-800/50 text-center">
              <span className="text-[11px] text-slate-400 font-mono">Anonymous Session</span>
            </div>
          )
        )}

      </div>
    </aside>
  );
}
