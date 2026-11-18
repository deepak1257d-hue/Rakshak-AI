'use client';
import React, { useState } from 'react';
import { TargetAsset } from '../lib/types';
import {
  Globe, ShieldCheck, AlertTriangle, Play, Settings, Plus, CheckCircle2, Copy, Check,
  RefreshCw, X, ExternalLink, ShieldAlert
} from 'lucide-react';

interface WebsitesViewProps {
  targets: TargetAsset[];
  onAddTarget: (domain: string) => Promise<TargetAsset>;
  onVerifyTarget: (targetId: string, method: 'DNS_TXT' | 'HTML_META') => Promise<void>;
  onStartScan: (targetId: string) => void;
}

export default function WebsitesView({
  targets,
  onAddTarget,
  onVerifyTarget,
  onStartScan
}: WebsitesViewProps) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [verifyTarget, setVerifyTarget] = useState<TargetAsset | null>(null);

  // New Target Form State
  const [newDomain, setNewDomain] = useState('');

  // Modal Step State (1-5)
  const [step, setStep] = useState<1 | 2 | 3 | 4 | 5>(1);
  const [verifyMethod, setVerifyMethod] = useState<'DNS_TXT' | 'HTML_META'>('DNS_TXT');
  const [copied, setCopied] = useState(false);
  const [verifying, setVerifying] = useState(false);

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;
    const clean = newDomain.trim().replace('https://', '').replace('http://', '').split('/')[0];
    const created = await onAddTarget(clean);
    setNewDomain('');
    setVerifyTarget(created);
    setStep(2);
    setShowAddModal(false);
  };

  const executeVerification = async () => {
    if (!verifyTarget) return;
    setVerifying(true);
    try {
      await onVerifyTarget(verifyTarget.id, verifyMethod);
      setStep(5);
    } catch (err) {
      alert('Verification record check failed. Ensure records are published.');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" />
            Protected Websites & Asset Inventory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage verified domains, web applications, and API targets monitored by AEGIS AI.
          </p>
        </div>

        <button
          onClick={() => {
            setStep(1);
            setShowAddModal(true);
          }}
          className="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/25 flex items-center gap-2 transition-all self-start md:self-center"
        >
          <Plus className="w-4 h-4" />
          <span>Add Protected Asset</span>
        </button>
      </div>

      {/* Asset Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {targets.map(target => {
          const isVerified = target.verification_status === 'VERIFIED';
          return (
            <div
              key={target.id}
              className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <h3 className="text-sm font-bold text-white font-mono">{target.domain}</h3>
                    {isVerified ? (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Verified
                      </span>
                    ) : (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> Verification Required
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Protection: <strong className={isVerified ? 'text-emerald-400' : 'text-slate-500'}>
                      {isVerified ? '● Active Monitoring' : '○ Pending Ownership Check'}
                    </strong>
                  </p>
                </div>

                <div className="text-right font-mono">
                  <span className="text-xs text-slate-500 block">Risk Score</span>
                  <span className="text-sm font-semibold text-slate-400">
                    {typeof target.security_score === 'number' ? `${target.security_score}/100` : 'Not calculated'}
                  </span>
                </div>
              </div>

              {/* Tech Stack Chips if available */}
              {target.tech_stack && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {target.tech_stack.map((t, idx) => (
                    <span key={idx} className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              )}

              {/* Stats Footer */}
              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <div>
                  Last Scan: <span className="text-slate-200 font-mono">
                    {target.last_scan_at ? new Date(target.last_scan_at).toLocaleString() : 'Never'}
                  </span>
                  <span className="mx-2">•</span>
                  Open Findings: <span className="text-amber-400 font-bold font-mono">{target.open_findings_count}</span>
                </div>

                <div className="flex items-center space-x-2">
                  {isVerified ? (
                    <button
                      onClick={() => onStartScan(target.id)}
                      className="px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white border border-blue-500/30 text-xs font-bold transition-all flex items-center gap-1"
                    >
                      <Play className="w-3 h-3 fill-current" />
                      <span>Scan</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => {
                        setVerifyTarget(target);
                        setStep(2);
                      }}
                      className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500 text-amber-300 hover:text-white border border-amber-500/30 text-xs font-bold transition-all flex items-center gap-1"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Verify Domain</span>
                    </button>
                  )}
                </div>
              </div>

            </div>
          );
        })}
      </div>

      {/* 5-Step Domain Verification Modal */}
      {(showAddModal || verifyTarget) && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-200">
            
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Asset Verification Workflow</h3>
                  <p className="text-xs text-slate-400">
                    Prove ownership of <strong className="text-blue-400">{verifyTarget ? verifyTarget.domain : 'New Target'}</strong>
                  </p>
                </div>
              </div>
              <button
                onClick={() => {
                  setShowAddModal(false);
                  setVerifyTarget(null);
                }}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Stepper Progress Indicator */}
            <div className="px-6 py-3 bg-slate-900/80 border-b border-slate-800 flex justify-between items-center text-[11px] font-mono text-slate-400">
              <span className={step >= 1 ? 'text-blue-400 font-bold' : ''}>1. Domain</span> →
              <span className={step >= 2 ? 'text-blue-400 font-bold' : ''}>2. Method</span> →
              <span className={step >= 3 ? 'text-blue-400 font-bold' : ''}>3. Add Record</span> →
              <span className={step >= 4 ? 'text-blue-400 font-bold' : ''}>4. Verify</span> →
              <span className={step >= 5 ? 'text-emerald-400 font-bold' : ''}>5. Enabled</span>
            </div>

            {/* Step Body */}
            <div className="p-6 space-y-4">
              
              {step === 1 && (
                <form onSubmit={handleCreateTarget} className="space-y-4">
                  <label className="text-xs text-slate-300 font-semibold block">Enter Target Website Domain:</label>
                  <input
                    type="text"
                    placeholder="e.g. production-api.yourcompany.com"
                    value={newDomain}
                    onChange={e => setNewDomain(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
                  />
                  <div className="flex justify-end pt-2">
                    <button
                      type="submit"
                      className="px-5 py-2.5 rounded-xl bg-blue-600 text-white font-bold text-xs shadow-md"
                    >
                      Proceed to Verification →
                    </button>
                  </div>
                </form>
              )}

              {step >= 2 && step <= 4 && verifyTarget && (
                <div className="space-y-4 text-xs">
                  <p className="text-slate-300">Select ownership verification method:</p>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => setVerifyMethod('DNS_TXT')}
                      className={`p-3 rounded-xl border text-left font-mono ${
                        verifyMethod === 'DNS_TXT' ? 'bg-blue-600/20 border-blue-500 text-white' : 'bg-slate-900 border-slate-800 text-slate-400'
                      }`}
                    >
                      <strong className="block text-slate-200">DNS TXT Record</strong>
                      <span className="text-[10px] text-slate-400">Add TXT entry in Cloudflare/Route53</span>
                    </button>

                    <button
                      onClick={() => setVerifyMethod('HTML_META')}
                      className={`p-3 rounded-xl border text-left font-mono ${
                        verifyMethod === 'HTML_META' ? 'bg-blue-600/20 border-blue-500 text-white' : 'bg-slate-900 border-slate-800 text-slate-400'
                      }`}
                    >
                      <strong className="block text-slate-200">HTML Meta Tag</strong>
                      <span className="text-[10px] text-slate-400">Place meta tag in website head</span>
                    </button>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono space-y-2">
                    <span className="text-slate-500 text-[10px] uppercase block">Verification Token:</span>
                    <div className="flex items-center justify-between text-blue-400 font-bold truncate gap-2">
                      <span className="truncate">
                        {verifyMethod === 'DNS_TXT'
                          ? `TXT @ ${verifyTarget.verification_token}`
                          : `<meta name="aegis-verify" content="${verifyTarget.verification_token}" />`}
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(verifyTarget.verification_token);
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                        }}
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 shrink-0"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-blue-500/5 border border-blue-500/20 text-slate-300 text-[11px]">
                    🛡️ <strong>Security Guardrail:</strong> AEGIS only scans assets that have been verified by the account owner.
                  </div>

                  <div className="flex justify-end space-x-2 pt-2">
                    <button
                      onClick={executeVerification}
                      disabled={verifying}
                      className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-md flex items-center gap-2 disabled:opacity-50"
                    >
                      {verifying ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                      <span>Check & Verify Ownership</span>
                    </button>
                  </div>
                </div>
              )}

              {step === 5 && (
                <div className="text-center py-6 space-y-3">
                  <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto" />
                  <h4 className="text-base font-bold text-white">Ownership Verified Successfully</h4>
                  <p className="text-xs text-slate-400 max-w-sm mx-auto">
                    Protection enabled for <strong>{verifyTarget?.domain}</strong>. Authorized vulnerability auditing is unlocked.
                  </p>
                  <button
                    onClick={() => {
                      setShowAddModal(false);
                      setVerifyTarget(null);
                    }}
                    className="px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-md"
                  >
                    Done
                  </button>
                </div>
              )}

            </div>

          </div>
        </div>
      )}

    </div>
  );
}
