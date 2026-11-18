'use client';
import React, { useState } from 'react';
import { TargetAsset } from '../lib/types';
import { ShieldCheck, Copy, Check, ExternalLink, Globe, AlertCircle, RefreshCw, X, HelpCircle } from 'lucide-react';

interface TargetVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  target: TargetAsset | null;
  onVerify: (targetId: string, method: 'DNS_TXT' | 'HTML_META') => Promise<void>;
  viewMode?: 'simple' | 'technical';
}

export default function TargetVerificationModal({
  isOpen,
  onClose,
  target,
  onVerify,
  viewMode = 'simple'
}: TargetVerificationModalProps) {
  const [method, setMethod] = useState<'DNS_TXT' | 'HTML_META'>('DNS_TXT');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  if (!isOpen || !target) return null;

  const txtRecord = `antigravity-verification=${target.verification_token}`;
  const metaTag = `<meta name="antigravity-verification" content="${target.verification_token}" />`;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleVerify = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      await onVerify(target.id, method);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.message || 'Verification check failed. Ensure records are published.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-200">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                {viewMode === 'simple' ? 'Verify Website Ownership' : 'Target Ownership Verification'}
              </h3>
              <p className="text-xs text-slate-400">
                Confirm you own <strong className="text-blue-400">{target.domain}</strong> before starting security checks.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5">
          {/* Method selector tabs */}
          <div className="grid grid-cols-2 gap-2 p-1 bg-slate-900 border border-slate-800 rounded-xl">
            <button
              onClick={() => setMethod('DNS_TXT')}
              className={`py-2 px-3 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all ${
                method === 'DNS_TXT' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              {viewMode === 'simple' ? 'Method 1: Domain Provider (DNS)' : 'DNS TXT Record'}
            </button>
            <button
              onClick={() => setMethod('HTML_META')}
              className={`py-2 px-3 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all ${
                method === 'HTML_META' ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-white'
              }`}
            >
              <ExternalLink className="w-3.5 h-3.5" />
              {viewMode === 'simple' ? 'Method 2: Website Header Tag' : 'HTML Meta Tag'}
            </button>
          </div>

          {method === 'DNS_TXT' ? (
            <div className="space-y-3">
              <p className="text-xs text-slate-300">
                Add this verification record to your domain&apos;s DNS manager (Cloudflare, GoDaddy, Namecheap, etc.):
              </p>
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 font-mono text-xs text-slate-200 flex items-center justify-between gap-3">
                <div className="truncate">
                  <span className="text-slate-500">Record Type:</span> TXT | <span className="text-slate-500">Host:</span> @ <br/>
                  <span className="text-slate-500">Value:</span> <span className="text-blue-400">{txtRecord}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(txtRecord)}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors shrink-0"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-slate-300">
                Copy and paste this tag inside the <code className="text-blue-400">&lt;head&gt;</code> section of your website homepage:
              </p>
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 font-mono text-xs text-slate-200 flex items-center justify-between gap-3">
                <code className="text-amber-300 truncate">{metaTag}</code>
                <button
                  onClick={() => copyToClipboard(metaTag)}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors shrink-0"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="p-3.5 rounded-xl bg-blue-500/5 border border-blue-500/10 text-slate-300 text-[11px] leading-relaxed">
            💡 <strong>Privacy & Safety Promise:</strong> AEGIS AI will only run security checks on websites where ownership has been verified.
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-900/50 flex justify-end space-x-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleVerify}
            disabled={loading}
            className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 flex items-center gap-2 transition-all disabled:opacity-50"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            <span>Verify Website Ownership</span>
          </button>
        </div>

      </div>
    </div>
  );
}
