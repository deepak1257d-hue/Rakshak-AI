'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  Globe,
  ShieldCheck,
  ShieldAlert,
  Clock,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
  Lock,
  Unlock,
  ExternalLink,
  HelpCircle,
  Play,
  Terminal,
  FileText,
  GitPullRequest,
  Sparkles,
  Info,
  ChevronDown,
  ChevronUp,
  Shield,
  Activity
} from 'lucide-react';
import { aegisApi } from '@/lib/api';
import { TargetAsset, ScanRun, Finding, ExecutiveSummary } from '@/lib/types';
import ScanningPipeline from '@/components/ScanningPipeline';
import VulnerabilitiesView from '@/components/VulnerabilitiesView';
import RemediationApprovalPanel from '@/components/RemediationApprovalPanel';
import ExecutiveReportPanel from '@/components/ExecutiveReportPanel';

export default function WebsiteDetailPage() {
  const params = useParams();
  const router = useRouter();
  const targetId = params?.id as string;

  const [target, setTarget] = useState<TargetAsset | null>(null);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [executiveSummary, setExecutiveSummary] = useState<ExecutiveSummary | null>(null);
  const [selectedRemediationFinding, setSelectedRemediationFinding] = useState<Finding | null>(null);
  const [scanHistoryError, setScanHistoryError] = useState<string | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [targetNotFound, setTargetNotFound] = useState(false);

  // Stepper active step (1 to 6)
  const [activeStep, setActiveStep] = useState<number>(2);

  // Verification state (Step 2)
  const [verificationMethod, setVerificationMethod] = useState<'DNS_TXT' | 'HTML_META' | 'HTTP_FILE'>('DNS_TXT');
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedFileName, setCopiedFileName] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [showFaq, setShowFaq] = useState(false);

  // Delete/Archive modal state
  const [showArchiveModal, setShowArchiveModal] = useState(false);

  const fetchTargetData = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);
    setError(null);
    setTargetNotFound(false);
    setScans([]);
    setFindings([]);
    setExecutiveSummary(null);
    setFindingsLoading(false);
    setScanHistoryError(null);
    setFindingsError(null);
    setSummaryError(null);

    try {
      if (!aegisApi.isAuthenticated()) {
        router.push('/');
        return;
      }

      // Fetch target from backend
      const found = await aegisApi.getTarget(targetId);
      if (!found) {
        setTarget(null);
        setTargetNotFound(true);
        setError('No target with this ID was found in the current workspace.');
        return;
      }
      setTarget(found);
      if (found.verification_method !== 'LAB') {
        setVerificationMethod(found.verification_method);
      }

      // Fetch scans for this target
      let targetScans: ScanRun[] = [];
      try {
        const allScans = await aegisApi.listScans();
        targetScans = allScans
          .filter((scan) => scan.target_id === targetId)
          .sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at));
        setScans(targetScans);
      } catch (scanErr) {
        setScanHistoryError(scanErr instanceof Error ? scanErr.message : 'Could not load scan history.');
      }

      const latestScan = targetScans.length > 0 ? targetScans[0] : null;

      if (latestScan && (latestScan.status === 'COMPLETED' || latestScan.status === 'PARTIAL')) {
        setFindingsLoading(true);
        try {
          const [findingsResult, summaryResult] = await Promise.allSettled([
            aegisApi.listScanFindings(latestScan.id),
            aegisApi.getExecutiveSummary(latestScan.id),
          ]);

          if (findingsResult.status === 'fulfilled') {
            setFindings(findingsResult.value);
          } else {
            setFindingsError(
              findingsResult.reason instanceof Error
                ? findingsResult.reason.message
                : 'Could not load findings for this scan.'
            );
          }

          if (summaryResult.status === 'fulfilled') {
            setExecutiveSummary(summaryResult.value);
          } else {
            setSummaryError(
              summaryResult.reason instanceof Error
                ? summaryResult.reason.message
                : 'Could not load the scan summary.'
            );
          }
        } finally {
          setFindingsLoading(false);
        }
      }

      // Determine initial active step based on state
      if (found.verification_status !== 'VERIFIED') {
        setActiveStep(2); // Needs verification
      } else if (!latestScan) {
        setActiveStep(3); // Ready for scan
      } else if (latestScan.status === 'RUNNING' || latestScan.status === 'QUEUED') {
        setActiveStep(3); // Scan in progress
      } else if (latestScan.status === 'COMPLETED' || latestScan.status === 'PARTIAL') {
        setActiveStep(4); // View findings
      } else {
        setActiveStep(3); // Retry or view a failed scan
      }

    } catch (err: any) {
      console.error('Failed to load target:', err);
      setTargetNotFound(false);
      setError(err.message || 'Error communicating with security backend.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [router, targetId]);

  useEffect(() => {
    if (targetId) {
      void fetchTargetData();
    }
  }, [fetchTargetData, targetId]);

  // Execute verification against real backend
  const handleVerify = async (useLabMethod = false) => {
    if (!target) return;
    setVerifying(true);
    setVerifyError(null);

    try {
      const methodToUse = useLabMethod ? 'LAB' : verificationMethod;
      const updated = await aegisApi.verifyTarget(target.id, methodToUse);
      setTarget(updated);
      if (updated.verification_status !== 'VERIFIED') {
        throw new Error('The backend did not confirm ownership. Steps 3–6 remain locked.');
      }
      // Auto advance to Step 3
      setActiveStep(3);
    } catch (err: any) {
      setVerifyError(err.message || 'Verification check failed. Please verify records are published and propagated.');
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const copyFileName = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFileName(true);
    setTimeout(() => setCopiedFileName(false), 2000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070b14] text-slate-100 flex items-center justify-center p-6">
        <div className="text-center space-y-4">
          <RefreshCw className="w-8 h-8 text-blue-500 animate-spin mx-auto" />
          <p className="text-xs text-slate-400 font-mono">Loading target asset and workflow state...</p>
        </div>
      </div>
    );
  }

  if (error || !target) {
    return (
      <div className="min-h-screen bg-[#070b14] text-slate-100 p-6 md:p-10 flex items-center justify-center">
        <div className="max-w-md w-full rounded-2xl bg-slate-900/80 border border-slate-800 p-8 text-center space-y-5">
          <div className="w-14 h-14 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center mx-auto">
            <AlertTriangle className="w-7 h-7" />
          </div>
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white">
              {targetNotFound ? 'Website not found' : 'Could not load website'}
            </h2>
            <p className="text-xs text-slate-400">{error || 'Unable to load website information.'}</p>
          </div>
          <div className="flex flex-wrap justify-center gap-3">
            {!targetNotFound && (
              <button
                onClick={() => fetchTargetData()}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white transition-all"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Try again</span>
              </button>
            )}
            <Link
              href="/websites"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to My Websites</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const isVerified = target.verification_status === 'VERIFIED';
  const isFailed = target.verification_status === 'FAILED';
  const latestScan = scans.length > 0 ? scans[0] : null;
  const isScanRunning = latestScan?.status === 'RUNNING' || latestScan?.status === 'QUEUED';
  const isScanDone = latestScan?.status === 'COMPLETED' || latestScan?.status === 'PARTIAL';

  const dnsTxtValue = `rakshak-verification=${target.verification_token}`;
  const aegisDnsTxtValue = `aegis-verification=${target.verification_token}`;
  const htmlMetaTag = `<meta name="rakshak-verification" content="${target.verification_token}" />`;
  const wellKnownFileName = '/.well-known/rakshak-verification.txt';
  const aegisWellKnownFileName = '/.well-known/aegis-verification.txt';
  const wellKnownFileContent = `rakshak-verification=${target.verification_token}`;
  const verificationMethodLabels: Record<TargetAsset['verification_method'], string> = {
    DNS_TXT: 'DNS TXT record',
    HTML_META: 'HTML meta tag',
    HTTP_FILE: 'Well-known file',
    LAB: 'Server-authorized lab verification',
  };

  // 6 Steps definition
  const steps = [
    {
      id: 1,
      title: 'Website Added',
      shortTitle: 'Added',
      icon: Globe,
      status: 'completed',
    },
    {
      id: 2,
      title: 'Ownership Proof',
      shortTitle: 'Verification',
      icon: ShieldCheck,
      status: isVerified ? 'completed' : isFailed ? 'failed' : 'active',
    },
    {
      id: 3,
      title: 'Security Scanning',
      shortTitle: 'Scanning',
      icon: Play,
      status: !isVerified ? 'locked' : isScanRunning ? 'active' : isScanDone ? 'completed' : 'unlocked',
    },
    {
      id: 4,
      title: 'Vulnerabilities',
      shortTitle: 'Findings',
      icon: Terminal,
      status: !isVerified || !isScanDone ? 'locked' : findings.length > 0 ? 'completed' : 'unlocked',
    },
    {
      id: 5,
      title: 'Remediation',
      shortTitle: 'Remediation',
      icon: GitPullRequest,
      status: !isVerified || !isScanDone || findings.length === 0 ? 'locked' : 'unlocked',
    },
    {
      id: 6,
      title: 'Executive Summary',
      shortTitle: 'Report',
      icon: FileText,
      status: !isVerified || !isScanDone ? 'locked' : 'unlocked',
    },
  ];

  const handleStepClick = (stepId: number, status: string) => {
    if (status === 'locked') {
      return;
    }
    setActiveStep(stepId);
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 p-6 md:p-10">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Top Header & Breadcrumb */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div className="space-y-2">
            <Link
              href="/websites"
              className="inline-flex items-center gap-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to My Websites</span>
            </Link>

            <div className="flex flex-wrap items-center gap-3">
              <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
                <Globe className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold tracking-tight text-white">
                    {target.domain}
                  </h1>

                  {/* Verification Status Pill */}
                  {isVerified ? (
                    target.verification_method === 'LAB' ? (
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/15 border border-amber-500/40 text-amber-300">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        LAB - NOT PROVEN OWNERSHIP
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        {isScanDone ? 'VERIFIED & SCANNED' : 'OWNERSHIP VERIFIED'}
                      </span>
                    )
                  ) : isFailed ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-rose-500/10 border border-rose-500/30 text-rose-400">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      VERIFICATION FAILED
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/10 border border-amber-500/30 text-amber-400 animate-pulse">
                      <Clock className="w-3.5 h-3.5" />
                      PENDING VERIFICATION
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Target ID: <code className="text-slate-300 font-mono text-[11px]">{target.id}</code> · Workspace: <code className="text-slate-300 font-mono text-[11px]">{target.workspace_id}</code> · Added {new Date(target.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 self-start md:self-auto">
            <button
              onClick={() => fetchTargetData(true)}
              disabled={refreshing}
              className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white text-xs font-medium flex items-center gap-2 transition-all"
              title="Refresh target"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-blue-400' : ''}`} />
              <span>Refresh</span>
            </button>

            <button
              onClick={() => setShowArchiveModal(true)}
              className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-900/60 hover:text-rose-400 text-slate-400 text-xs font-medium transition-all"
            >
              Archive
            </button>
          </div>
        </div>

        {/* ------------------------------------------------------------- */}
        {/* 6-STEP STEPPER BAR (TOP OF SCREEN)                            */}
        {/* ------------------------------------------------------------- */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 sm:p-5">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {steps.map((s) => {
              const Icon = s.icon;
              const isCurrent = activeStep === s.id;
              const isLocked = s.status === 'locked';
              const isCompleted = s.status === 'completed';
              const isFailedStep = s.status === 'failed';

              let borderColor = 'border-slate-800';
              let bgColor = 'bg-slate-950/60';
              let iconColor = 'text-slate-500';

              if (isCurrent) {
                borderColor = 'border-blue-500 shadow-md shadow-blue-500/10';
                bgColor = 'bg-blue-950/30';
                iconColor = 'text-blue-400';
              } else if (isCompleted) {
                borderColor = 'border-emerald-500/30';
                bgColor = 'bg-emerald-950/15';
                iconColor = 'text-emerald-400';
              } else if (isFailedStep) {
                borderColor = 'border-rose-500/30';
                bgColor = 'bg-rose-950/15';
                iconColor = 'text-rose-400';
              }

              return (
                <button
                  key={s.id}
                  onClick={() => handleStepClick(s.id, s.status)}
                  disabled={isLocked}
                  className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all relative ${borderColor} ${bgColor} ${
                    isLocked ? 'cursor-not-allowed opacity-50' : 'cursor-pointer hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between w-full mb-2">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      Step {s.id}
                    </span>
                    {isCompleted ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : isFailedStep ? (
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    ) : isLocked ? (
                      <Lock className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    ) : (
                      <Unlock className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <Icon className={`w-4 h-4 shrink-0 ${iconColor}`} />
                    <span className={`text-xs font-bold truncate ${isCurrent ? 'text-white' : 'text-slate-300'}`}>
                      {s.shortTitle}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Stepper Guardrail Banner if unverified */}
          {!isVerified && (
            <div className="mt-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 shrink-0 text-amber-400" />
              <span>
                <strong>Pre-Scan Guardrail Active:</strong> Domain ownership must be verified in Step 2 before security scanning (Steps 3–6) can begin.
              </span>
            </div>
          )}
        </div>

        {/* ------------------------------------------------------------- */}
        {/* STEP WORKFLOW CONTENT AREA                                    */}
        {/* ------------------------------------------------------------- */}
        <div className="space-y-6">

          {/* STEP 1: WEBSITE ADDED SUMMARY */}
          {activeStep === 1 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    Step 1: Website Successfully Registered
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Normalized asset properties registered with AEGIS core security database.
                  </p>
                </div>
                <button
                  onClick={() => setActiveStep(2)}
                  className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center gap-2 transition-all"
                >
                  <span>Go to Step 2: Verification</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                  <span className="text-[11px] text-slate-400 uppercase font-mono tracking-wider">Target Domain</span>
                  <p className="text-base font-bold text-white font-mono">{target.domain}</p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                  <span className="text-[11px] text-slate-400 uppercase font-mono tracking-wider">Verification Status</span>
                  <p className="text-base font-bold text-white flex items-center gap-2">
                    {isVerified && target.verification_method !== 'LAB' ? (
                      <span className="text-emerald-400 flex items-center gap-1.5 text-sm">
                        <CheckCircle2 className="w-4 h-4" /> OWNERSHIP VERIFIED
                      </span>
                    ) : isVerified ? (
                      <span className="text-amber-300 flex items-center gap-1.5 text-sm">
                        <AlertTriangle className="w-4 h-4" /> LAB - NOT PROVEN OWNERSHIP
                      </span>
                    ) : isFailed ? (
                      <span className="text-rose-400 flex items-center gap-1.5 text-sm">
                        <AlertTriangle className="w-4 h-4" /> VERIFICATION FAILED
                      </span>
                    ) : (
                      <span className="text-amber-400 flex items-center gap-1.5 text-sm">
                        <Clock className="w-4 h-4" /> PENDING OWNERSHIP PROOF
                      </span>
                    )}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                  <span className="text-[11px] text-slate-400 uppercase font-mono tracking-wider">Preferred Method</span>
                  <p className="text-sm font-semibold text-slate-200">
                    {verificationMethodLabels[target.verification_method]}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                  <span className="text-[11px] text-slate-400 uppercase font-mono tracking-wider">Registration Date</span>
                  <p className="text-sm font-semibold text-slate-200">
                    {new Date(target.created_at).toLocaleString()}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: OWNERSHIP VERIFICATION */}
          {activeStep === 2 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6">
              
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-5">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-blue-400" />
                    Step 2: Ownership Verification
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Prove ownership of <strong className="text-blue-400">{target.domain}</strong> using a verification method supported by the backend.
                  </p>
                </div>

                {isVerified && (
                  <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold self-start sm:self-auto ${
                    target.verification_method === 'LAB'
                      ? 'bg-amber-500/10 border border-amber-500/30 text-amber-300'
                      : 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                  }`}>
                    {target.verification_method === 'LAB' ? (
                      <>
                        <AlertTriangle className="w-4 h-4" />
                        LAB - NOT PROVEN OWNERSHIP
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-4 h-4" />
                        Backend reports ownership verified
                      </>
                    )}
                  </span>
                )}
              </div>

              {isVerified ? (
                target.verification_method === 'LAB' ? (
                  <div className="p-6 rounded-2xl bg-amber-500/10 border border-amber-500/30 space-y-4">
                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 rounded-xl bg-amber-500/20 border border-amber-500/40 text-amber-400 flex items-center justify-center shrink-0">
                        <AlertTriangle className="w-6 h-6" />
                      </div>
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <h3 className="text-base font-bold text-white">Development Lab Override</h3>
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            LAB - NOT PROVEN OWNERSHIP
                          </span>
                        </div>
                        <p className="text-xs text-amber-200">
                          <strong>{target.domain}</strong> was authorized under the server development lab allowlist. Ownership has <strong>NOT</strong> been proven via DNS or HTTP. Scans and reports are marked accordingly.
                        </p>
                        {target.last_verified_at && (
                          <p className="text-[11px] text-amber-300/80 font-mono pt-1">
                            Authorized at: {new Date(target.last_verified_at).toLocaleString()}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-3 pt-2">
                      <button
                        onClick={() => setActiveStep(3)}
                        className="px-5 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold shadow-lg shadow-amber-600/20 flex items-center gap-2 transition-all"
                      >
                        <span>Proceed to Step 3: Security Scanning</span>
                        <ArrowRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="p-6 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 space-y-4">
                    <div className="flex items-start gap-4">
                      <div className="w-12 h-12 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center shrink-0">
                        <ShieldCheck className="w-6 h-6" />
                      </div>
                      <div className="space-y-1">
                        <h3 className="text-base font-bold text-white">Domain Ownership Confirmed</h3>
                        <p className="text-xs text-emerald-200">
                          The backend reports ownership verified for {target.domain} using {verificationMethodLabels[target.verification_method]}. Steps 3–6 are now unlocked.
                        </p>
                        {target.last_verified_at && (
                          <p className="text-[11px] text-emerald-300 font-mono pt-1">
                            Last verified: {new Date(target.last_verified_at).toLocaleString()}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-3 pt-2">
                      <button
                        onClick={() => setActiveStep(3)}
                        className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-600/20 flex items-center gap-2 transition-all"
                      >
                        <span>Proceed to Step 3: Security Scanning</span>
                        <ArrowRight className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleVerify(false)}
                        disabled={verifying}
                        className="px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-white text-xs font-medium flex items-center gap-2 transition-all"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin text-blue-400' : ''}`} />
                        <span>Re-verify Token</span>
                      </button>
                    </div>
                  </div>
                )
              ) : (
                <div className="space-y-6">

                  {verifyError && (
                    <div role="alert" className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs space-y-2">
                      <div className="flex items-start gap-2.5">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                        <div className="space-y-1">
                          <p className="font-bold text-rose-200">Verification check failed</p>
                          <p className="text-slate-300 font-mono text-[11px]">{verifyError}</p>
                        </div>
                      </div>
                      <div className="pt-2 flex flex-wrap items-center gap-3">
                        <button
                          onClick={() => handleVerify(false)}
                          disabled={verifying}
                          className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-[11px] font-bold transition-all"
                        >
                          Try Again
                        </button>
                        {target.lab_mode && (
                          <button
                            onClick={() => handleVerify(true)}
                            disabled={verifying}
                            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-[11px] font-bold flex items-center gap-1.5 transition-all shadow-sm"
                          >
                            <Sparkles className="w-3.5 h-3.5 text-amber-300" />
                            <span>Instant Verify (Lab Mode)</span>
                          </button>
                        )}
                        <button
                          onClick={() => setShowFaq(!showFaq)}
                          className="text-[11px] text-rose-300 underline hover:text-white"
                        >
                          {showFaq ? 'Hide troubleshooting' : 'Why did this fail?'}
                        </button>
                      </div>
                    </div>
                  )}

                  {showFaq && (
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 text-xs space-y-3">
                      <h4 className="font-bold text-white flex items-center gap-2">
                        <HelpCircle className="w-4 h-4 text-blue-400" />
                        Common Verification Issues & Solutions
                      </h4>
                      <ul className="space-y-2 text-slate-300 list-disc list-inside">
                        <li>
                          <strong>DNS TXT:</strong> Publish the exact token value below on the root host for <code className="text-blue-300">{target.domain}</code>. The backend accepts the <code className="text-blue-300">rakshak-verification=</code> and <code className="text-blue-300">aegis-verification=</code> prefixes.
                        </li>
                        <li>
                          <strong>HTML meta:</strong> Add the supplied meta tag to the homepage head. The backend accepts <code className="text-blue-300">rakshak-verification</code> and <code className="text-blue-300">aegis-verification</code>; the legacy <code className="text-blue-300">antigravity-verification</code> name is deprecated.
                        </li>
                        <li>
                          <strong>Well-known file:</strong> Use one of the exact paths shown below and return the exact token line as the file body.
                        </li>
                      </ul>
                    </div>
                  )}

                  <div role="group" aria-label="Ownership verification method" className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-1.5 bg-slate-950/80 border border-slate-800 rounded-xl">
                    <button
                      onClick={() => { setVerificationMethod('DNS_TXT'); setVerifyError(null); }}
                      aria-pressed={verificationMethod === 'DNS_TXT'}
                      className={`py-2.5 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-2 transition-all ${
                        verificationMethod === 'DNS_TXT'
                          ? 'bg-blue-600 text-white shadow-md'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Globe className="w-4 h-4" />
                      <span>DNS TXT Record</span>
                    </button>
                    <button
                      onClick={() => { setVerificationMethod('HTML_META'); setVerifyError(null); }}
                      aria-pressed={verificationMethod === 'HTML_META'}
                      className={`py-2.5 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-2 transition-all ${
                        verificationMethod === 'HTML_META'
                          ? 'bg-blue-600 text-white shadow-md'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <ExternalLink className="w-4 h-4" />
                      <span>HTML Meta Tag</span>
                    </button>
                    <button
                      onClick={() => { setVerificationMethod('HTTP_FILE'); setVerifyError(null); }}
                      aria-pressed={verificationMethod === 'HTTP_FILE'}
                      className={`py-2.5 px-3 rounded-lg text-xs font-bold flex items-center justify-center gap-2 transition-all ${
                        verificationMethod === 'HTTP_FILE'
                          ? 'bg-blue-600 text-white shadow-md'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <FileText className="w-4 h-4" />
                      <span>Well-Known File</span>
                    </button>
                  </div>

                  {verificationMethod === 'DNS_TXT' ? (
                    <div className="space-y-4">
                      <p className="text-xs text-slate-300 leading-relaxed">
                        The backend checks TXT records for <code className="text-blue-300">{target.domain}</code> and accepts an exact line with either the <code className="text-blue-300">rakshak-verification=</code> or <code className="text-blue-300">aegis-verification=</code> prefix. The legacy <code className="text-blue-300">antigravity-verification=</code> prefix is deprecated; use the canonical value below.
                      </p>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-400 uppercase font-mono block">Record Type</span>
                          <span className="text-sm font-bold text-white font-mono">TXT</span>
                        </div>
                        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                          <span className="text-[10px] text-slate-400 uppercase font-mono block">Query Host</span>
                          <span className="text-sm font-bold text-white font-mono">{target.domain}</span>
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                          <span>TXT Record Value</span>
                          <span className="text-[11px] text-slate-400">Unique cryptographic token</span>
                        </label>
                        <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-blue-300 break-all select-all">
                          <span className="flex-1">{dnsTxtValue}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(dnsTxtValue)}
                            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white shrink-0 border border-slate-700/60 transition-all flex items-center gap-1.5 text-xs font-sans font-medium"
                          >
                            {copiedToken ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400 text-[11px]">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span className="text-[11px]">Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        The backend also accepts <code className="text-cyan-300">{aegisDnsTxtValue}</code>; the copied value above uses its canonical <code className="text-cyan-300">rakshak-verification=</code> form.
                      </p>
                    </div>
                  ) : verificationMethod === 'HTML_META' ? (
                    <div className="space-y-4">
                      <p className="text-xs text-slate-300 leading-relaxed">
                        Place the supplied <code className="text-blue-300 font-mono">&lt;meta&gt;</code> tag in the homepage <code className="text-blue-300 font-mono">&lt;head&gt;</code>. The backend accepts <code className="text-blue-300">rakshak-verification</code> and <code className="text-blue-300">aegis-verification</code> names and compares their content with your token; the legacy <code className="text-blue-300">antigravity-verification</code> name is deprecated.
                      </p>

                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                          <span>HTML Meta Tag</span>
                          <span className="text-[11px] text-slate-400">Place inside &lt;head&gt;</span>
                        </label>
                        <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-cyan-300 break-all select-all">
                          <span className="flex-1">{htmlMetaTag}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(htmlMetaTag)}
                            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white shrink-0 border border-slate-700/60 transition-all flex items-center gap-1.5 text-xs font-sans font-medium"
                          >
                            {copiedToken ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400 text-[11px]">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span className="text-[11px]">Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <p className="text-xs text-slate-300 leading-relaxed">
                        Publish a file at either exact path below. The backend tries each path over HTTPS and HTTP and accepts a line containing the matching verification token.
                      </p>
                      <p className="text-[11px] text-slate-400">
                        Accepted paths: <code className="text-blue-300">{wellKnownFileName}</code> and <code className="text-blue-300">{aegisWellKnownFileName}</code>.
                      </p>

                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                          <span>File Path</span>
                          <span className="text-[11px] text-slate-400">Must be served publicly</span>
                        </label>
                        <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-emerald-300 break-all select-all">
                          <span className="flex-1">{wellKnownFileName}</span>
                          <button
                            type="button"
                            onClick={() => copyFileName(wellKnownFileName)}
                            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white shrink-0 border border-slate-700/60 transition-all flex items-center gap-1.5 text-xs font-sans font-medium"
                          >
                            {copiedFileName ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400 text-[11px]">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span className="text-[11px]">Copy Path</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                          <span>File Content</span>
                          <span className="text-[11px] text-slate-400">Exact body</span>
                        </label>
                        <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-blue-300 break-all select-all">
                          <span className="flex-1">{wellKnownFileContent}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(wellKnownFileContent)}
                            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white shrink-0 border border-slate-700/60 transition-all flex items-center gap-1.5 text-xs font-sans font-medium"
                          >
                            {copiedToken ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400 text-[11px]">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span className="text-[11px]">Copy Content</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        The backend accepts the exact line <code className="text-blue-300">rakshak-verification={target.verification_token}</code> or <code className="text-blue-300">aegis-verification={target.verification_token}</code>; the legacy <code className="text-blue-300">antigravity-verification=</code> prefix is deprecated. The copied body above uses the canonical form.
                      </p>
                    </div>
                  )}

                  <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-slate-400 max-w-xl">
                      {target.lab_mode ? (
                        <span className="text-amber-400">
                          🧪 <strong>Development Lab Target:</strong> <code>{target.domain}</code> is configured in the server allowlist. You can perform instant verification without external DNS or HTTP records.
                        </span>
                      ) : (
                        <span>
                          🔒 <strong>Ownership Requirement:</strong> External and production domains must prove ownership via DNS TXT, HTML meta tag, or <code>/.well-known</code> file. Lab bypass is restricted to server allowlisted development hosts.
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                      {target.lab_mode && (
                        <button
                          type="button"
                          onClick={() => handleVerify(true)}
                          disabled={verifying}
                          className="px-4 py-3 rounded-xl bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
                          title="Instantly verify allowlisted development lab target"
                        >
                          <Sparkles className="w-4 h-4 text-amber-400" />
                          <span>Instant Verify (Lab Mode)</span>
                        </button>
                      )}

                      <button
                        onClick={() => handleVerify(false)}
                        disabled={verifying}
                        className="px-6 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:opacity-50 text-white text-xs font-bold shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2.5 transition-all shrink-0"
                      >
                        {verifying ? (
                          <>
                            <RefreshCw className="w-4 h-4 animate-spin" />
                            <span>
                              {verificationMethod === 'DNS_TXT'
                                ? 'Checking DNS TXT records...'
                                : verificationMethod === 'HTML_META'
                                ? 'Checking HTML meta tag...'
                                : 'Checking well-known file...'}
                            </span>
                          </>
                        ) : (
                          <>
                            <ShieldCheck className="w-4 h-4" />
                            <span>Verify Ownership Now</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                </div>
              )}

            </div>
          )}

          {/* STEP 3: SECURITY SCANNING PIPELINE (LIVE 5 PHASES + WS/POLLING) */}
          {activeStep === 3 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6">
              {scanHistoryError ? (
                <div className="p-5 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-3">
                  <p className="text-sm font-semibold text-rose-200" role="alert">{scanHistoryError}</p>
                  <button
                    type="button"
                    onClick={() => void fetchTargetData(true)}
                    disabled={refreshing}
                    className="px-4 py-2 rounded-lg bg-slate-800 text-xs font-semibold text-white hover:bg-slate-700 disabled:opacity-50"
                  >
                    {refreshing ? 'Refreshing…' : 'Retry loading scan history'}
                  </button>
                </div>
              ) : (
                <ScanningPipeline
                  target={target}
                  activeScan={latestScan}
                  onScanComplete={async () => {
                    await fetchTargetData(true);
                    setActiveStep(4);
                  }}
                  onProceedToFindings={() => setActiveStep(4)}
                />
              )}
            </div>
          )}

          {/* STEP 4: VULNERABILITIES & SECURITY (FINDINGS & SIDE DRAWER) */}
          {activeStep === 4 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6">
              {findingsLoading ? (
                <div className="p-10 text-center text-sm text-slate-300" role="status" aria-live="polite">
                  <RefreshCw className="w-5 h-5 text-blue-400 animate-spin mx-auto mb-3" />
                  Loading findings from the backend…
                </div>
              ) : findingsError ? (
                <div className="p-5 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-3">
                  <p className="text-sm font-semibold text-rose-200" role="alert">{findingsError}</p>
                  <button
                    type="button"
                    onClick={() => void fetchTargetData(true)}
                    disabled={refreshing}
                    className="px-4 py-2 rounded-lg bg-slate-800 text-xs font-semibold text-white hover:bg-slate-700 disabled:opacity-50"
                  >
                    {refreshing ? 'Refreshing…' : 'Retry loading findings'}
                  </button>
                </div>
              ) : (
                <VulnerabilitiesView
                  findings={findings}
                  executiveSummary={executiveSummary}
                  summaryError={summaryError}
                  onSelectFindingForRemediation={(f) => {
                    setSelectedRemediationFinding(f);
                    setActiveStep(5);
                  }}
                />
              )}
            </div>
          )}

          {/* STEPS 5 & 6 */}
          {activeStep >= 5 && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 md:p-8 space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    {activeStep === 5 && <GitPullRequest className="w-5 h-5 text-amber-400" />}
                    {activeStep === 6 && <FileText className="w-5 h-5 text-emerald-400" />}
                    Step {activeStep}: {steps.find(s => s.id === activeStep)?.title}
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    {activeStep === 5 && 'Review the selected patch and submit an explicit approval or rejection.'}
                    {activeStep === 6 && 'Review report fields returned for this scan by the backend.'}
                  </p>
                </div>
              </div>

              {activeStep === 5 && selectedRemediationFinding ? (
                <RemediationApprovalPanel
                  finding={selectedRemediationFinding}
                  onBackToFindings={() => setActiveStep(4)}
                />
              ) : activeStep === 5 ? (
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center space-y-3">
                  <p className="text-sm text-slate-200">Select a finding from Step 4 to review its remediation proposal.</p>
                  <button
                    type="button"
                    onClick={() => setActiveStep(4)}
                    className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-700"
                  >
                    Back to findings
                  </button>
                </div>
              ) : latestScan ? (
                <ExecutiveReportPanel scanId={latestScan.id} />
              ) : (
                <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 text-sm text-rose-200" role="alert">
                  No completed scan is available for this report.
                </div>
              )}
            </div>
          )}

        </div>

      </div>

      {/* ------------------------------------------------------------- */}
      {/* ARCHIVE CONFIRMATION MODAL                                    */}
      {/* ------------------------------------------------------------- */}
      {showArchiveModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Archive Target</h3>
                <p className="text-xs text-slate-400">Manage target lifecycle</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to archive <strong>{target.domain}</strong>?
            </p>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
              Note: The backend currently retains audit logs and historical scans. Deletion and archiving endpoints will be wired in future releases.
            </div>

            <div className="flex items-center justify-end gap-3 pt-3">
              <button
                onClick={() => setShowArchiveModal(false)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white"
              >
                Close
              </button>
              <button
                onClick={() => {
                  setShowArchiveModal(false);
                  router.push('/websites');
                }}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
              >
                Return to My Websites
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
