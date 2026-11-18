'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Clock, RefreshCw, SlidersHorizontal } from 'lucide-react';
import { aegisApi } from '@/lib/api';
import { ScanRun, TargetAsset } from '@/lib/types';

type ScanStatusFilter = 'ALL' | ScanRun['status'];

export default function HistoryPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [targetNames, setTargetNames] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [targetFilter, setTargetFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState<ScanStatusFilter>('ALL');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');

  const loadHistory = useCallback(async () => {
    if (!aegisApi.isAuthenticated()) {
      router.replace('/');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const [scanRuns, targets] = await Promise.all([
        aegisApi.listScans(),
        aegisApi.listTargets()
      ]);
      setScans(scanRuns);
      setTargetNames(
        Object.fromEntries(targets.map((target: TargetAsset) => [target.id, target.domain]))
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load scan history.');
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const targetIds = [
    ...Object.keys(targetNames),
    ...scans.map((scan) => scan.target_id)
  ].filter((id, index, ids) => ids.indexOf(id) === index);
  const targetOptions = targetIds
    .map((id) => ({
      id,
      label: targetNames[id] || `Website unavailable (${id})`
    }))
    .sort((a, b) => a.label.localeCompare(b.label));

  const dateRangeInvalid = Boolean(fromDate && toDate && fromDate > toDate);
  const fromTimestamp = fromDate ? new Date(`${fromDate}T00:00:00`).getTime() : null;
  const toTimestamp = toDate ? new Date(`${toDate}T23:59:59.999`).getTime() : null;

  const filteredScans = [...scans]
    .sort((a, b) => {
      const aTime = Date.parse(a.started_at);
      const bTime = Date.parse(b.started_at);
      if (!Number.isFinite(aTime)) return Number.isFinite(bTime) ? 1 : 0;
      if (!Number.isFinite(bTime)) return -1;
      return bTime - aTime;
    })
    .filter((scan) => {
      if (dateRangeInvalid) return false;
      if (targetFilter !== 'ALL' && scan.target_id !== targetFilter) return false;
      if (statusFilter !== 'ALL' && scan.status !== statusFilter) return false;

      const startedAt = Date.parse(scan.started_at);
      if (fromTimestamp !== null && (!Number.isFinite(startedAt) || startedAt < fromTimestamp)) return false;
      if (toTimestamp !== null && (!Number.isFinite(startedAt) || startedAt > toTimestamp)) return false;
      return true;
    });

  const hasFilters = targetFilter !== 'ALL' || statusFilter !== 'ALL' || Boolean(fromDate || toDate);
  const clearFilters = () => {
    setTargetFilter('ALL');
    setStatusFilter('ALL');
    setFromDate('');
    setToDate('');
  };

  const statusStyles: Record<ScanRun['status'], string> = {
    QUEUED: 'border-slate-700 bg-slate-800/70 text-slate-300',
    RUNNING: 'border-blue-500/30 bg-blue-500/10 text-blue-300',
    COMPLETED: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    PARTIAL: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    FAILED: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  };

  return (
    <main className="min-h-screen bg-[#070b14] p-6 text-slate-100 md:p-10">
      <div className="mx-auto max-w-5xl space-y-6">
        <header className="flex items-center justify-between border-b border-slate-800 pb-5">
          <div className="flex items-center gap-3">
            <Clock className="h-6 w-6 text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">Scan History</h1>
              <p className="mt-1 text-sm text-slate-400">Previous scan runs for your workspace.</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void loadHistory()}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-300 hover:text-white disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </header>

        {loading ? (
          <p className="text-sm text-slate-400" role="status" aria-live="polite">Loading scan history…</p>
        ) : error ? (
          <section className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-6">
            <p role="alert" className="text-sm text-rose-200">{error}</p>
            <button
              type="button"
              onClick={() => void loadHistory()}
              className="mt-4 rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-700"
            >
              Retry loading history
            </button>
          </section>
        ) : scans.length === 0 ? (
          <section className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 text-center">
            <h2 className="text-lg font-semibold text-white">No scan runs yet</h2>
            <p className="mt-2 text-sm text-slate-400">
              Scan runs will appear here after an authorized assessment has been started.
            </p>
            <Link href="/websites" className="mt-5 inline-block text-sm font-medium text-cyan-400 hover:text-cyan-300">
              View your websites
            </Link>
          </section>
        ) : (
          <>
            <section className="rounded-2xl border border-slate-800 bg-slate-900/50 p-5">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
                <h2 className="flex items-center gap-2 text-sm font-semibold text-white">
                  <SlidersHorizontal className="h-4 w-4 text-cyan-400" />
                  Filter scan history
                </h2>
                <p className="text-xs text-slate-400" role="status" aria-live="polite">
                  {filteredScans.length} of {scans.length} runs
                </p>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1.5">
                  <label htmlFor="history-website" className="text-xs font-medium text-slate-300">Website</label>
                  <select
                    id="history-website"
                    value={targetFilter}
                    onChange={(event) => setTargetFilter(event.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="ALL">All websites</option>
                    {targetOptions.map((target) => (
                      <option key={target.id} value={target.id}>{target.label}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="history-status" className="text-xs font-medium text-slate-300">Status</label>
                  <select
                    id="history-status"
                    value={statusFilter}
                    onChange={(event) => setStatusFilter(event.target.value as ScanStatusFilter)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="ALL">All statuses</option>
                    <option value="QUEUED">Queued</option>
                    <option value="RUNNING">Running</option>
                    <option value="COMPLETED">Completed</option>
                    <option value="PARTIAL">Partial</option>
                    <option value="FAILED">Failed</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="history-from" className="text-xs font-medium text-slate-300">Started from</label>
                  <input
                    id="history-from"
                    type="date"
                    value={fromDate}
                    max={toDate || undefined}
                    onChange={(event) => setFromDate(event.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="history-to" className="text-xs font-medium text-slate-300">Started through</label>
                  <input
                    id="history-to"
                    type="date"
                    value={toDate}
                    min={fromDate || undefined}
                    onChange={(event) => setToDate(event.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
                  />
                </div>
              </div>

              {hasFilters && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className="mt-4 text-xs font-medium text-cyan-300 hover:text-cyan-200"
                >
                  Clear filters
                </button>
              )}
              {dateRangeInvalid && (
                <p className="mt-3 text-xs text-rose-300" role="alert">
                  The start date must be on or before the end date.
                </p>
              )}
            </section>

            {filteredScans.length === 0 ? (
              <section className="rounded-2xl border border-slate-800 bg-slate-900/50 p-8 text-center">
                <h2 className="text-lg font-semibold text-white">No matching scan runs</h2>
                <p className="mt-2 text-sm text-slate-400">No backend scan records match these filters.</p>
                {hasFilters && (
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="mt-4 text-sm font-medium text-cyan-300 hover:text-cyan-200"
                  >
                    Clear filters
                  </button>
                )}
              </section>
            ) : (
              <ul className="divide-y divide-slate-800 rounded-2xl border border-slate-800 bg-slate-900/50">
                {filteredScans.map((scan) => {
                  const startedAt = Date.parse(scan.started_at);
                  const startedLabel = Number.isFinite(startedAt)
                    ? new Date(startedAt).toLocaleString()
                    : 'Date unavailable';

                  return (
                    <li key={scan.id} className="flex flex-wrap items-center justify-between gap-4 p-5">
                      <div className="min-w-0">
                        <Link
                          href={`/websites/${scan.target_id}`}
                          className="font-semibold text-white hover:text-cyan-300"
                        >
                          {targetNames[scan.target_id] || `Website unavailable (${scan.target_id})`}
                        </Link>
                        <p className="mt-1 text-xs text-slate-400">{startedLabel}</p>
                        <p className="mt-1 truncate text-xs text-slate-500">
                          {scan.current_stage || 'Stage not reported'}
                        </p>
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <span className={`rounded-full border px-2.5 py-1 font-mono ${statusStyles[scan.status]}`}>
                          {scan.status}
                        </span>
                        <span className="font-mono text-slate-400">{scan.progress_pct}%</span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </>
        )}
      </div>
    </main>
  );
}
