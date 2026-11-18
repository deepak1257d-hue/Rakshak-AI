'use client';

import React, { useState, useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import Sidebar from './Sidebar';
import { Menu, X, Shield } from 'lucide-react';
import { aegisApi } from '@/lib/api';

interface AppShellProps {
  children: React.ReactNode;
}

export default function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [mounted, setMounted] = useState(false);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const mobileNavigationRef = useRef<HTMLDivElement>(null);
  const mobileCloseButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setMounted(true);
    setIsAuthenticated(aegisApi.isAuthenticated());

    // Keyboard shortcut: Ctrl+B or Cmd+B to toggle sidebar collapse
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        setIsSidebarCollapsed(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [pathname]);

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileSidebarOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!mobileSidebarOpen) return;

    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const menuButton = mobileMenuButtonRef.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    mobileCloseButtonRef.current?.focus();

    const handleDialogKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        setMobileSidebarOpen(false);
        return;
      }
      if (event.key !== 'Tab') return;

      const focusable = mobileNavigationRef.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (!focusable?.length) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!mobileNavigationRef.current?.contains(document.activeElement)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      document.removeEventListener('keydown', handleDialogKeyDown);
      document.body.style.overflow = previousOverflow;
      if (previousFocus?.isConnected) previousFocus.focus();
      else if (menuButton?.isConnected) menuButton.focus();
    };
  }, [mobileSidebarOpen]);

  const isLandingPage = pathname === '/';
  const shouldHideSidebar = isLandingPage && !isAuthenticated;

  return (
    <div className="flex h-screen overflow-hidden bg-[#060911] text-slate-100">
      {/* Sidebar for authenticated and dashboard routes */}
      {!shouldHideSidebar && (
        <>
          {/* Desktop Sidebar */}
          <div className={`hidden md:block transition-all duration-300 shrink-0 ${isSidebarCollapsed ? 'w-16' : 'w-60'}`}>
            <Sidebar
              isCollapsed={isSidebarCollapsed}
              onToggleCollapse={() => setIsSidebarCollapsed(prev => !prev)}
            />
          </div>

          {/* Mobile Backdrop & Drawer */}
          {mobileSidebarOpen && (
            <div
              className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm md:hidden animate-in fade-in duration-200"
              onClick={() => setMobileSidebarOpen(false)}
            >
              <div
                id="mobile-navigation"
                ref={mobileNavigationRef}
                role="dialog"
                aria-modal="true"
                aria-label="Mobile navigation"
                className="w-72 h-full bg-[#080d1a] border-r border-slate-800 p-0 shadow-2xl"
                onClick={e => e.stopPropagation()}
              >
                <div className="p-4 flex items-center justify-between border-b border-slate-800">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center text-white shadow-md">
                      <Shield className="w-4 h-4" />
                    </div>
                    <span className="font-extrabold text-white text-sm tracking-tight">AEGIS</span>
                  </div>
                  <button
                    ref={mobileCloseButtonRef}
                    type="button"
                    onClick={() => setMobileSidebarOpen(false)}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                    aria-label="Close Navigation"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <Sidebar
                  isCollapsed={false}
                  onToggleCollapse={() => {}}
                  isMobile
                />
              </div>
            </div>
          )}
        </>
      )}

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col h-full overflow-hidden">
        {/* Mobile Header Bar (shown on non-landing pages on mobile) */}
        {!shouldHideSidebar && (
          <header className="md:hidden flex items-center justify-between px-4 py-3 bg-[#080d1a] border-b border-slate-800 shrink-0 z-20">
            <div className="flex items-center gap-2.5">
              <button
                ref={mobileMenuButtonRef}
                type="button"
                onClick={() => setMobileSidebarOpen(true)}
                className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
                aria-label="Open Navigation"
                aria-haspopup="dialog"
                aria-expanded={mobileSidebarOpen}
                aria-controls={mobileSidebarOpen ? 'mobile-navigation' : undefined}
              >
                <Menu className="w-5 h-5" />
              </button>
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center text-white shadow-sm">
                  <Shield className="w-3.5 h-3.5" />
                </div>
                <span className="font-bold text-white text-xs tracking-tight">AEGIS</span>
              </div>
            </div>
            <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-cyan-400 border border-cyan-500/30">
              Security
            </span>
          </header>
        )}

        <main className="flex-1 min-w-0 overflow-y-auto relative">
          {children}
        </main>
      </div>
    </div>
  );
}

