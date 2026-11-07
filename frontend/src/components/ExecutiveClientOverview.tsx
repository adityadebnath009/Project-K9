'use client';

import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';
import { TargetScanResult } from '@/types/api';

interface ExecutiveClientOverviewProps {
  scanResult: TargetScanResult;
  onNavigateTab: (tabId: string) => void;
  onOpenStix: () => void;
}

export const ExecutiveClientOverview: React.FC<ExecutiveClientOverviewProps> = ({
  scanResult,
  onNavigateTab,
}) => {
  const isCritical = scanResult.riskScore > 60;
  const isSuspicious = scanResult.riskScore > 25 && scanResult.riskScore <= 60;

  return (
    <div className="bento-card p-5 space-y-5">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-3 border-b border-border-subtle gap-3">
        <div className="flex items-center gap-3">
          <div
            className={`p-2.5 rounded-lg border ${
              isCritical
                ? 'bg-rose-950/60 border-rose-800 text-rose-400'
                : isSuspicious
                ? 'bg-amber-950/60 border-amber-800 text-amber-400'
                : 'bg-emerald-950/60 border-emerald-800 text-emerald-400'
            }`}
          >
            {isCritical ? (
              <ShieldAlert className="w-6 h-6" />
            ) : isSuspicious ? (
              <AlertTriangle className="w-6 h-6" />
            ) : (
              <ShieldCheck className="w-6 h-6" />
            )}
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs uppercase font-bold tracking-wider text-zinc-400">
                Executive Verdict
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${
                  isCritical
                    ? 'bg-rose-950 text-rose-300 border-rose-800'
                    : isSuspicious
                    ? 'bg-amber-950 text-amber-300 border-amber-800'
                    : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                }`}
              >
                {scanResult.verdict}
              </span>
            </div>
            <h3 className="text-base sm:text-lg font-bold text-zinc-100 font-sans mt-0.5">
              {isCritical
                ? 'High-Risk Threat Identified — Immediate Action Required'
                : isSuspicious
                ? 'Security Anomalies Detected — Proceed with Caution'
                : 'Cryptographically Verified Safe Web Asset'}
            </h3>
          </div>
        </div>
      </div>

      {/* Plain-English Executive Summary */}
      <div className="p-4 rounded-lg bg-ground border border-border-subtle space-y-2">
        <span className="font-mono text-[11px] text-zinc-500 uppercase tracking-wider block">
          Executive Threat Summary:
        </span>
        <p className="font-sans text-sm text-zinc-200 leading-relaxed">
          {scanResult.executiveSummary}
        </p>
      </div>

      {/* 4 Clean Key Business Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-xs">
        {/* Metric 1 */}
        <div className="p-3 rounded-lg bg-ground border border-border-subtle space-y-1">
          <span className="text-zinc-500 text-[10px] uppercase block">Overall Risk Score:</span>
          <div className="flex items-center justify-between">
            <span
              className={`text-lg font-extrabold ${
                isCritical ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
              }`}
            >
              {scanResult.riskScore} / 100
            </span>
            <span className="text-[10px] text-zinc-400 font-sans">
              {isCritical ? 'Critical Threat' : isSuspicious ? 'Moderate' : 'Low Risk'}
            </span>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-3 rounded-lg bg-ground border border-border-subtle space-y-1">
          <span className="text-zinc-500 text-[10px] uppercase block">CA & Key Integrity:</span>
          <div className="flex items-center justify-between">
            <span
              className={`text-sm font-bold ${
                scanResult.emudhraAudit.isVulnerable ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {scanResult.emudhraAudit.isVulnerable ? 'FAIL (d=4 Flaw)' : 'VALID PKI'}
            </span>
            <button
              onClick={() => onNavigateTab('crypto')}
              className="text-[10px] text-zinc-400 hover:text-zinc-200 underline font-sans"
            >
              View Proof
            </button>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-3 rounded-lg bg-ground border border-border-subtle space-y-1">
          <span className="text-zinc-500 text-[10px] uppercase block">Brand Impersonation:</span>
          <div className="flex items-center justify-between">
            <span
              className={`text-sm font-bold ${
                scanResult.typosquatting.isImpersonation ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {scanResult.typosquatting.isImpersonation ? 'SPOOFED BRAND' : 'AUTHENTIC'}
            </span>
            <button
              onClick={() => onNavigateTab('heuristics')}
              className="text-[10px] text-zinc-400 hover:text-zinc-200 underline font-sans"
            >
              View Diff
            </button>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-3 rounded-lg bg-ground border border-border-subtle space-y-1">
          <span className="text-zinc-500 text-[10px] uppercase block">Web Posture Observatory:</span>
          <div className="flex items-center justify-between">
            <span className="text-sm font-bold text-zinc-100">
              Grade {scanResult.securityPosture.overallGrade}
            </span>
            <span className="text-[10px] text-zinc-400 font-sans">
              Score: {scanResult.securityPosture.gradeNumeric}%
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
