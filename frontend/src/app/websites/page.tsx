'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  Clock,
  ArrowRight,
  Plus,
  RefreshCw,
  Search,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Sparkles,
  Server,
  Layers,
  FileText,
  ChevronRight
} from 'lucide-react';
import { aegisApi } from '@/lib/api';
import { TargetAsset } from '@/lib/types';
import { normalizeDomain } from '@/lib/domain';

export default function WebsitesPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<TargetAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'VERIFIED' | 'PENDING' | 'FAILED'>('ALL');

  // Modal for adding a new website directly from this screen
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomainInput, setNewDomainInput] = useState('');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [addMethod, setAddMethod] = useState<'DNS_TXT' | 'HTML_META' | 'HTTP_FILE'>('DNS_TXT');
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  const loadTargets = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      if (!aegisApi.isAuthenticated()) {
        // Redirect to home if unauthenticated
        router.push('/');
        return;
      }
      const data = await aegisApi.listTargets();
      setTargets(data);
    } catch (err: any) {
      console.error('Failed to load targets:', err);
      setTargets([]);
      setError(err.message || 'Unable to connect to security backend.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [router]);

  useEffect(() => {
    void loadTargets();
  }, [loadTargets]);

  const handleAddWebsite = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddError(null);

    const check = normalizeDomain(newDomainInput);
    if (!check.isValid) {
      setAddError(check.error || 'Please enter a valid website domain.');
      return;
    }

    if (!isAuthorized) {
      setAddError('You must confirm authorization before scanning this website.');
      return;
    }

    setAddLoading(true);
    try {
      const created = await aegisApi.createTarget(check.domain, addMethod);
      setShowAddModal(false);
      setNewDomainInput('');
      setIsAuthorized(false);
      // Navigate straight to the new website's dedicated workflow
      router.push(`/websites/${created.id}`);
    } catch (err: any) {
      setAddError(err.message || 'Failed to add target website.');
    } finally {
      setAddLoading(false);
    }
  };

  const filteredTargets = targets.filter(t => {
    const matchesSearch = t.domain.toLowerCase().includes(searchQuery.toLowerCase().trim());
    const matchesStatus = statusFilter === 'ALL' || t.verification_status === statusFilter;
    return matchesSearch && matchesStatus;
  });
  const hasFilters = Boolean(searchQuery.trim()) || statusFilter !== 'ALL';

  const verifiedCount = targets.filter(
    t => t.verification_status === 'VERIFIED' && t.verification_method !== 'LAB' && !t.is_lab
  ).length;
  const pendingCount = targets.filter(t => t.verification_status === 'PENDING').length;

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 p-6 md:p-10">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
                <Globe className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
                  AEGIS — My Websites
                  <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                    {targets.length} {targets.length === 1 ? 'Target' : 'Targets'}
                  </span>
                </h1>
                <p className="text-sm text-slate-400 mt-0.5">
                  Register websites, complete ownership verification, and review their workflow status.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 self-start md:self-auto">
            <button
              onClick={() => loadTargets(true)}
              disabled={refreshing || loading}
              className="px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white text-xs font-medium flex items-center gap-2 transition-all disabled:opacity-50"
              title="Refresh targets list"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-blue-400' : ''}`} />
              <span>Refresh</span>
            </button>

            <button
              onClick={() => setShowAddModal(true)}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/20 flex items-center gap-2 transition-all"
            >
              <Plus className="w-4 h-4" />
              <span>Add Website</span>
            </button>
          </div>
        </div>

        {/* Metric Summary Badges */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs font-medium text-slate-400">Registered Websites</p>
              <p className="text-2xl font-bold text-white">{targets.length}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Layers className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs font-medium text-slate-400">Ownership Verified (Non-Lab)</p>
              <p className="text-2xl font-bold text-emerald-400">{verifiedCount}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs font-medium text-slate-400">Pending Ownership Proof</p>
              <p className="text-2xl font-bold text-amber-400">{pendingCount}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <Clock className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              aria-label="Filter websites by domain"
              placeholder="Filter by domain name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/60"
            />
          </div>

          <div className="flex items-center gap-1.5 p-1 bg-slate-900/80 border border-slate-800 rounded-xl text-xs self-start sm:self-auto">
            {(['ALL', 'VERIFIED', 'PENDING', 'FAILED'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setStatusFilter(tab)}
                aria-pressed={statusFilter === tab}
                className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                  statusFilter === tab
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tab === 'ALL' ? 'All' : tab.charAt(0) + tab.slice(1).toLowerCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div role="alert" className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => loadTargets(true)}
              className="underline text-rose-300 hover:text-white font-medium"
            >
              Retry
            </button>
          </div>
        )}

        {/* Target Cards Grid */}
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {[1, 2, 3].map(i => (
              <div
                key={i}
                className="h-52 rounded-2xl bg-slate-900/40 border border-slate-800/50 animate-pulse p-6 space-y-4"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-slate-800" />
                  <div className="space-y-2 flex-1">
                    <div className="h-4 bg-slate-800 rounded w-3/4" />
                    <div className="h-3 bg-slate-800/60 rounded w-1/2" />
                  </div>
                </div>
                <div className="h-10 bg-slate-800/40 rounded-xl" />
                <div className="h-8 bg-slate-800/30 rounded-xl" />
              </div>
            ))}
          </div>
        ) : error ? null : filteredTargets.length === 0 ? (
          <div className="rounded-2xl border border-slate-800/80 bg-slate-900/30 p-12 text-center max-w-xl mx-auto space-y-5">
            <div className="w-16 h-16 rounded-2xl bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center justify-center mx-auto shadow-inner">
              <Globe className="w-8 h-8" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-bold text-white">
                {hasFilters ? 'No websites match these filters' : 'No Monitored Websites Yet'}
              </h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                {hasFilters
                  ? 'Try adjusting your search or verification-status filter.'
                  : 'Register a website first. Ownership verification is next; scanning remains locked until the backend confirms verification.'}
              </p>
            </div>
            {hasFilters ? (
              <button
                onClick={() => { setSearchQuery(''); setStatusFilter('ALL'); }}
                className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-all"
              >
                Clear Filters
              </button>
            ) : (
              <button
                onClick={() => setShowAddModal(true)}
                className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/25 inline-flex items-center gap-2 transition-all"
              >
                <Plus className="w-4 h-4" />
                <span>Add Your First Website</span>
              </button>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filteredTargets.map(target => {
              const isVerified = target.verification_status === 'VERIFIED';
              const isFailed = target.verification_status === 'FAILED';
              const isLab = target.verification_method === 'LAB' || target.is_lab === true;

              const currentStepLabel = isVerified
                ? 'Ownership verified'
                : isFailed
                ? 'Verification needs attention'
                : 'Ownership proof needed';
              const ctaLabel = isVerified
                ? 'Open workflow'
                : isFailed
                ? 'Retry verification'
                : 'Verify ownership';
              const ctaColor = isVerified
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/20'
                : isFailed
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-300 hover:bg-rose-500/25'
                : 'bg-amber-500/15 border-amber-500/30 text-amber-300 hover:bg-amber-500/25';

              return (
                <Link
                  key={target.id}
                  href={`/websites/${target.id}`}
                  aria-label={`Open workflow for ${target.domain}`}
                  className="group relative rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-slate-800/80 hover:border-blue-500/50 p-6 flex flex-col justify-between transition-all duration-200 hover:shadow-xl hover:shadow-blue-500/5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
                >
                  {/* Top row: Globe/Favicon + Status Pill */}
                  <div className="space-y-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-10 h-10 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-blue-400 shrink-0 group-hover:border-blue-500/40 group-hover:text-blue-300 transition-colors">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div className="min-w-0">
                          <h3 className="text-base font-bold text-white truncate group-hover:text-blue-400 transition-colors">
                            {target.domain}
                          </h3>
                          <p className="text-[11px] text-slate-400 truncate">
                            Added {new Date(target.created_at).toLocaleDateString()} · {
                              target.verification_method === 'DNS_TXT' ? 'DNS TXT'
                                : target.verification_method === 'HTML_META' ? 'HTML meta tag'
                                : target.verification_method === 'HTTP_FILE' ? 'Well-known file'
                                : 'Lab authorization'
                            }
                          </p>
                        </div>
                      </div>

                      {/* Status Badge */}
                      <div className="flex flex-col items-end gap-1 shrink-0">
                        {isVerified ? (
                          isLab ? (
                            <span className="shrink-0 inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-500/15 border border-amber-500/30 text-amber-300">
                              LAB - not proven ownership
                            </span>
                          ) : (
                            <span className="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                              <CheckCircle2 className="w-3 h-3" />
                              OWNERSHIP VERIFIED
                            </span>
                          )
                        ) : isFailed ? (
                          <span className="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold bg-rose-500/10 border border-rose-500/30 text-rose-400">
                            <AlertTriangle className="w-3 h-3" />
                            FAILED
                          </span>
                        ) : (
                          <span className="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-500/10 border border-amber-500/30 text-amber-400">
                            <Clock className="w-3 h-3" />
                            PENDING
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Current Workflow Step */}
                    <div className="flex items-center gap-2 text-xs text-slate-300 pt-1">
                      <div className={`w-1.5 h-1.5 rounded-full ${isVerified ? 'bg-emerald-400' : isFailed ? 'bg-rose-400' : 'bg-amber-400'}`} />
                      <span className="font-medium text-slate-300 text-[11px] truncate">
                        {currentStepLabel}
                      </span>
                    </div>
                    {isVerified && target.last_verified_at && (
                      <p className="text-[11px] text-slate-400">
                        {isLab ? 'Lab authorized' : 'Verified'} {new Date(target.last_verified_at).toLocaleDateString()}
                      </p>
                    )}
                  </div>

                  {/* Card Bottom CTA */}
                  <div className="pt-4 border-t border-slate-800/60 mt-4">
                    <span className={`w-full py-2 px-3 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 border transition-all ${ctaColor}`}>
                      <span>{ctaLabel}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  </div>
                </Link>
              );
            })}
          </div>
        )}

      </div>

      {/* ------------------------------------------------------------- */}
      {/* ADD TARGET MODAL                                              */}
      {/* ------------------------------------------------------------- */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
                  <Globe className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Add Website for Protection</h3>
                  <p className="text-xs text-slate-400">Start continuous threat exposure monitoring</p>
                </div>
              </div>
              <button
                onClick={() => { setShowAddModal(false); setAddError(null); }}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 text-sm"
              >
                ✕
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleAddWebsite} className="p-6 space-y-4">
              {addError && (
                <div role="alert" className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{addError}</span>
                </div>
              )}

              <div className="space-y-1.5">
                <label htmlFor="new-website-domain" className="text-xs font-semibold text-slate-200">
                  Target Domain or URL
                </label>
                <input
                  id="new-website-domain"
                  type="text"
                  placeholder="e.g. example.com or https://app.example.com"
                  autoComplete="url"
                  value={newDomainInput}
                  onChange={(e) => {
                    setNewDomainInput(e.target.value);
                    if (addError) setAddError(null);
                  }}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-800 focus:border-blue-500 text-sm text-white placeholder-slate-500 focus:outline-none"
                  autoFocus
                />
                <p className="text-[11px] text-slate-400">
                  Protocols, paths, and www will be automatically normalized.
                </p>
              </div>

              {/* Verification method pre-selection */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-200">
                  Preferred Verification Method
                </label>
                <div role="group" aria-label="Preferred verification method" className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setAddMethod('DNS_TXT')}
                    aria-pressed={addMethod === 'DNS_TXT'}
                    className={`py-2 px-3 rounded-xl text-xs font-medium border text-left transition-all ${
                      addMethod === 'DNS_TXT'
                        ? 'bg-blue-600/15 border-blue-500 text-blue-300'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    <span className="font-bold block">DNS TXT Record</span>
                    <span className="text-[10px] text-slate-400">Recommended for domains</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setAddMethod('HTML_META')}
                    aria-pressed={addMethod === 'HTML_META'}
                    className={`py-2 px-3 rounded-xl text-xs font-medium border text-left transition-all ${
                      addMethod === 'HTML_META'
                        ? 'bg-blue-600/15 border-blue-500 text-blue-300'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    <span className="font-bold block">HTML Meta Tag</span>
                    <span className="text-[10px] text-slate-400">Add to &lt;head&gt; tag</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setAddMethod('HTTP_FILE')}
                    aria-pressed={addMethod === 'HTTP_FILE'}
                    className={`py-2 px-3 rounded-xl text-xs font-medium border text-left transition-all ${
                      addMethod === 'HTTP_FILE'
                        ? 'bg-blue-600/15 border-blue-500 text-blue-300'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                    }`}
                  >
                    <span className="font-bold block">Well-known File</span>
                    <span className="text-[10px] text-slate-400">Publish the exact file path</span>
                  </button>
                </div>
              </div>

              {/* Authorization Checkbox */}
              <div className="pt-2">
                <div className="flex items-start gap-2.5">
                  <input
                    id="website-authorization"
                    type="checkbox"
                    checked={isAuthorized}
                    onChange={(e) => setIsAuthorized(e.target.checked)}
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0 focus:ring-offset-0"
                  />
                  <label htmlFor="website-authorization" className="text-xs text-slate-300 leading-snug">
                    I own this website or am authorized to request ownership verification and security testing for it.
                  </label>
                </div>
              </div>

              {/* Buttons */}
              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addLoading || !isAuthorized}
                  className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-bold shadow-lg shadow-blue-600/20 flex items-center gap-2 transition-all"
                >
                  {addLoading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Registering...</span>
                    </>
                  ) : (
                    <>
                      <span>Continue to Verification</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </div>
            </form>

          </div>
        </div>
      )}

    </div>
  );
}
