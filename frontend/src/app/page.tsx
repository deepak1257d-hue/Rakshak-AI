'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield, Globe, ArrowRight, CheckCircle2,
  AlertCircle, Key, Mail, Building, Sparkles, LogOut,
  ArrowUpRight, ShieldCheck
} from 'lucide-react';
import { aegisApi } from '../lib/api';
import { normalizeDomain } from '../lib/domain';

export default function HomePage() {
  const router = useRouter();

  // Authentication State
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [currentUserEmail, setCurrentUserEmail] = useState<string>('');
  const [authMode, setAuthMode] = useState<'LOGIN' | 'REGISTER'>('LOGIN');

  // Auth Form State
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [workspaceName, setWorkspaceName] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [isSubmittingAuth, setIsSubmittingAuth] = useState(false);

  // Target Intake State
  const [rawDomain, setRawDomain] = useState('');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);
  const [isSubmittingTarget, setIsSubmittingTarget] = useState(false);

  useEffect(() => {
    const isAuthed = aegisApi.isAuthenticated();
    setIsAuthenticated(isAuthed);
    if (isAuthed) {
      const u = aegisApi.getUser();
      if (u) setCurrentUserEmail(u.email);
    }
  }, []);

  // Handle Domain input change with real-time normalization preview
  const normalizedPreview = rawDomain.trim() ? normalizeDomain(rawDomain) : null;

  // Handle Login / Registration
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setIsSubmittingAuth(true);

    try {
      if (authMode === 'LOGIN') {
        const data = await aegisApi.login(email.trim(), password);
        setCurrentUserEmail(data.email || email.trim());
      } else {
        if (!workspaceName.trim()) {
          throw new Error('Workspace name is required for registration.');
        }
        const data = await aegisApi.register(email.trim(), password, workspaceName.trim());
        setCurrentUserEmail(data.email || email.trim());
      }
      setIsAuthenticated(true);
    } catch (err: any) {
      setAuthError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  // Instant Demo Login for Evaluators
  const handleDemoLogin = async () => {
    setAuthError(null);
    setIsSubmittingAuth(true);
    try {
      const uid = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
      const passwordBytes = crypto.getRandomValues(new Uint8Array(32));
      const password = Array.from(passwordBytes, byte => byte.toString(16).padStart(2, '0')).join('');
      const data = await aegisApi.register(
        `secops_${uid}@aegis-defense.io`,
        password,
        'Cyber Defense Operations'
      );
      setCurrentUserEmail(data.email);
      setIsAuthenticated(true);
    } catch (err: any) {
      setAuthError(err.message || 'Demo session initialization failed.');
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  // Handle Logout
  const handleLogout = () => {
    aegisApi.logout();
    setIsAuthenticated(false);
    setCurrentUserEmail('');
  };

  // Handle Add Website Submission
  const handleAddWebsite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInputError(null);

    const check = normalizeDomain(rawDomain);
    if (!check.isValid) {
      setInputError(check.error || 'Please enter a valid website domain.');
      return;
    }

    if (!isAuthorized) {
      setInputError('You must confirm audit authorization before adding a target.');
      return;
    }

    setIsSubmittingTarget(true);

    try {
      const newTarget = await aegisApi.createTarget(check.domain, 'DNS_TXT');
      // Redirect to the dedicated per-website workflow page
      router.push(`/websites/${newTarget.id}`);
    } catch (err: any) {
      setInputError(err.message || 'Failed to register website with security backend.');
    } finally {
      setIsSubmittingTarget(false);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center p-4 sm:p-6 overflow-hidden">
      
      {/* ------------------------------------------------------------- */}
      {/* FULL-SCREEN CYBERSECURITY BLURRED BACKGROUND PATTERN           */}
      {/* ------------------------------------------------------------- */}
      <div className="absolute inset-0 z-0 bg-[#060911] overflow-hidden pointer-events-none select-none">
        {/* Deep blue & cyan radial glow gradients */}
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] bg-blue-600/15 rounded-full blur-[140px]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-cyan-500/10 rounded-full blur-[160px]" />
        <div className="absolute -bottom-40 -right-40 w-[600px] h-[600px] bg-indigo-600/15 rounded-full blur-[140px]" />

        {/* High-tech cybersecurity network grid overlay */}
        <svg
          className="absolute inset-0 w-full h-full opacity-[0.14]"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
        >
          <defs>
            <pattern id="cyber-grid" width="48" height="48" patternUnits="userSpaceOnUse">
              <path d="M 48 0 L 0 0 0 48" fill="none" stroke="#38bdf8" strokeWidth="0.8" />
              <circle cx="0" cy="0" r="1.5" fill="#38bdf8" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#cyber-grid)" />
        </svg>

        {/* Ambient floating circuit overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#060911]/70 via-transparent to-[#060911]/90 backdrop-blur-[6px]" />
      </div>

      {/* ------------------------------------------------------------- */}
      {/* SINGLE CENTERED GLASS-STYLE CARD                              */}
      {/* ------------------------------------------------------------- */}
      <div className="relative z-10 w-full max-w-lg transition-all duration-300">
        <div className="glass-card rounded-3xl p-8 sm:p-10 border border-slate-700/60 bg-[#0c1322]/90 shadow-2xl shadow-black/80">
          
          {/* Rakshak AI Header & Shield Logo */}
          <div className="text-center space-y-3 mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 via-cyan-500 to-cyan-400 p-0.5 shadow-lg shadow-cyan-500/20 border border-cyan-400/40">
              <div className="w-full h-full bg-[#080d1a] rounded-[14px] flex items-center justify-center text-cyan-400">
                <Shield className="w-8 h-8" />
              </div>
            </div>
            
            <div>
              <div className="flex items-center justify-center space-x-2">
                <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                  AEGIS
                </h1>
                <span className="text-[11px] px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-mono font-semibold">
                  SECURITY WORKSPACE
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1.5 max-w-sm mx-auto leading-relaxed">
                Verify ownership, scan your websites, and review security findings.
              </p>
            </div>
          </div>

          {/* --------------------------------------------------------- */}
          {/* STATE A: AUTHENTICATED USER -> ENTER WEBSITE INTAKE       */}
          {/* --------------------------------------------------------- */}
          {isAuthenticated ? (
            <div className="space-y-6">
              
              {/* Authenticated user indicator */}
              <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
                <div className="flex items-center gap-2 truncate">
                  <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-slate-400">Signed in as</span>
                  <span className="font-semibold text-slate-200 truncate">{currentUserEmail || 'Security Analyst'}</span>
                </div>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="text-slate-400 hover:text-rose-400 transition-colors flex items-center gap-1 text-[11px]"
                >
                  <LogOut className="w-3 h-3" />
                  <span>Sign out</span>
                </button>
              </div>

              <form onSubmit={handleAddWebsite} className="space-y-5">
                {/* Single Website Input */}
                <div className="space-y-1.5">
                  <label htmlFor="website-domain" className="block text-sm font-semibold text-slate-200">
                    Website domain
                  </label>
                  
                  <div className="relative group">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 group-focus-within:text-cyan-400 transition-colors">
                      <Globe className="w-4 h-4" />
                    </div>
                    
                    <input
                      id="website-domain"
                      type="text"
                      autoComplete="url"
                      value={rawDomain}
                      onChange={(e) => {
                        setRawDomain(e.target.value);
                        if (inputError) setInputError(null);
                      }}
                      placeholder="example.com"
                      aria-invalid={Boolean(inputError)}
                      aria-describedby={inputError ? 'website-input-error' : 'website-domain-help'}
                      className="w-full pl-10 pr-4 py-3.5 bg-slate-900/90 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all shadow-inner font-mono"
                      autoFocus
                    />
                  </div>
                  <p id="website-domain-help" className="text-xs text-slate-400">
                    Add a domain you own or are authorized to assess.
                  </p>

                  {/* Real-time Normalization Feedback */}
                  {normalizedPreview && (
                    <div aria-live="polite" className="pt-1 text-xs font-mono flex items-center justify-between">
                      {normalizedPreview.isValid ? (
                        <span className="text-emerald-400 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                          <span>Canonical Target: <strong>{normalizedPreview.domain}</strong></span>
                        </span>
                      ) : (
                        <span className="text-amber-400 flex items-center gap-1.5">
                          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                          <span>{normalizedPreview.error}</span>
                        </span>
                      )}
                    </div>
                  )}

                  {inputError && (
                    <p id="website-input-error" role="alert" className="text-sm text-rose-300 flex items-center gap-1 pt-1">
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>{inputError}</span>
                    </p>
                  )}
                </div>

                {/* Scope & Authorization Checkbox */}
                <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800 space-y-2">
                  <label className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300 select-none">
                    <input
                      type="checkbox"
                      checked={isAuthorized}
                      onChange={(e) => setIsAuthorized(e.target.checked)}
                      className="mt-0.5 rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-cyan-400/30"
                    />
                    <span className="leading-relaxed">
                      I confirm I own or have written authorization to perform exposure assessments against this domain.
                    </span>
                  </label>
                  <p className="text-xs text-slate-400 pl-6 leading-relaxed">
                    Scanning and later steps stay locked until the backend verifies ownership.
                  </p>
                </div>

                {/* Primary CTA */}
                <button
                  type="submit"
                  disabled={isSubmittingTarget || !rawDomain.trim()}
                  className="w-full py-3.5 px-4 rounded-xl bg-gradient-to-r from-blue-600 via-cyan-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 disabled:opacity-50 text-white font-bold text-sm shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2 transition-all transform active:scale-[0.99]"
                >
                  {isSubmittingTarget ? (
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Registering Target Asset...</span>
                    </div>
                  ) : (
                    <>
                      <span>Add website and verify ownership</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              {/* Navigation shortcut to existing websites */}
              <div className="pt-2 text-center">
                <Link
                  href="/websites"
                  className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 transition-colors"
                >
                  <span>Go to My Websites inventory</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </Link>
              </div>

            </div>
          ) : (
            /* ------------------------------------------------------- */
            /* STATE B: UNAUTHENTICATED -> SIGN IN / REGISTER / DEMO   */
            /* ------------------------------------------------------- */
            <div className="space-y-6">
              
              {/* Auth Mode Toggle Tabs */}
              <div className="grid grid-cols-2 gap-1 p-1 bg-slate-900 border border-slate-800 rounded-xl text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => { setAuthMode('LOGIN'); setAuthError(null); }}
                  className={`py-2 rounded-lg transition-all ${
                    authMode === 'LOGIN'
                      ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => { setAuthMode('REGISTER'); setAuthError(null); }}
                  className={`py-2 rounded-lg transition-all ${
                    authMode === 'REGISTER'
                      ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Create Account
                </button>
              </div>

              {authError && (
                <div role="alert" className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-sm flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{authError}</span>
                </div>
              )}

              <form onSubmit={handleAuthSubmit} className="space-y-4">
                {authMode === 'REGISTER' && (
                  <div className="space-y-1">
                    <label htmlFor="workspace-name" className="block text-sm font-semibold text-slate-200">
                      Organization / Workspace Name
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                        <Building className="w-4 h-4" />
                      </div>
                      <input
                        id="workspace-name"
                        type="text"
                        value={workspaceName}
                        onChange={(e) => setWorkspaceName(e.target.value)}
                        placeholder="Cyber Defense Operations"
                        autoComplete="organization"
                        required
                        className="w-full pl-9 pr-3 py-2.5 bg-slate-900/90 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                      />
                    </div>
                  </div>
                )}

                <div className="space-y-1">
                  <label htmlFor="analyst-email" className="block text-sm font-semibold text-slate-200">
                    Analyst Email
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                      <Mail className="w-4 h-4" />
                    </div>
                    <input
                      id="analyst-email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@example.com"
                      autoComplete="email"
                      required
                      className="w-full pl-9 pr-3 py-2.5 bg-slate-900/90 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <label htmlFor="analyst-password" className="block text-sm font-semibold text-slate-200">
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                      <Key className="w-4 h-4" />
                    </div>
                    <input
                      id="analyst-password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      autoComplete={authMode === 'LOGIN' ? 'current-password' : 'new-password'}
                      required
                      className="w-full pl-9 pr-3 py-2.5 bg-slate-900/90 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isSubmittingAuth}
                  className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 text-white font-bold text-xs shadow-md shadow-blue-500/20 flex items-center justify-center gap-2 transition-all"
                >
                  {isSubmittingAuth ? (
                    <div className="flex items-center gap-2">
                      <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Authenticating...</span>
                    </div>
                  ) : (
                    <span>{authMode === 'LOGIN' ? 'Sign In to Workspace' : 'Create Security Workspace'}</span>
                  )}
                </button>
              </form>

              {/* 1-Click Demo Evaluation Button */}
              <div className="pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={handleDemoLogin}
                  disabled={isSubmittingAuth}
                  className="w-full py-2.5 px-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-cyan-300 text-xs font-medium flex items-center justify-center gap-2 transition-all hover:border-cyan-500/60 shadow-sm"
                >
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span>Create evaluation workspace</span>
                </button>
                <p className="text-xs text-slate-500 text-center mt-2">
                  Creates a real account and workspace. No scan starts automatically.
                </p>
              </div>

            </div>
          )}

        </div>
      </div>

    </div>
  );
}
