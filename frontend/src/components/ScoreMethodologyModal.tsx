'use client';
import React from 'react';
import { ShieldCheck, X, Info } from 'lucide-react';

interface ScoreMethodologyModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ScoreMethodologyModal({ isOpen, onClose }: ScoreMethodologyModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Security Posture Scoring Methodology</h3>
              <p className="text-xs text-slate-400">How AEGIS AI calculates environment risk metrics</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 text-xs text-slate-300">
          
          <div className="p-3.5 rounded-xl bg-blue-500/5 border border-blue-500/20 text-blue-300 leading-relaxed flex items-start gap-2.5">
            <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <span>
              A numeric score is shown only when a finding&apos;s CVE appears in the project&apos;s curated CVSS v3.1 base-score catalog.
            </span>
          </div>

          <div className="space-y-3 pt-2">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Calculation:</h4>
            
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between font-semibold text-slate-200">
                <span>Curated CVSS v3.1 base score</span>
                <span className="text-blue-300 font-mono">score × 10</span>
              </div>
              <p className="text-[11px] text-slate-400">The result is scaled to 0–100 for display. The source catalog is static and may need updating.</p>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between font-semibold text-slate-200">
                <span>Unknown or uncatalogued CVE</span>
                <span className="text-amber-300 font-mono">No numeric score</span>
              </div>
              <p className="text-[11px] text-slate-400">Severity labels are retained, but a score is not inferred from severity.</p>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between font-semibold text-slate-200">
                <span>Environmental modifiers</span>
                <span className="text-slate-300 font-mono">Not applied</span>
              </div>
              <p className="text-[11px] text-slate-400">Exposure, authentication, exploit availability, and compensating controls are not independently measured.</p>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between font-semibold text-slate-200">
                <span>Remediation time</span>
                <span className="text-slate-300 font-mono">Not calculated</span>
              </div>
              <p className="text-[11px] text-slate-400">No remediation duration estimate is currently derived from observed data.</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] text-slate-400 leading-relaxed italic">
            ⚠️ <strong>Disclaimer:</strong> Security scores are indicators based on available scan evidence and do not guarantee complete security against unknown zero-day vulnerabilities.
          </div>

        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-900/50 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-md"
          >
            Close Explanation
          </button>
        </div>

      </div>
    </div>
  );
}
