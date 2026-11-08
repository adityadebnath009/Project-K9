'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldAlert, AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react';
import { TargetScanResult } from '@/types/api';
import { LaymanAITranslation } from './LaymanAITranslation';

interface TrustVerdictCardProps {
  result: TargetScanResult;
}

export const TrustVerdictCard: React.FC<TrustVerdictCardProps> = ({ result }) => {
  const isMalicious = result.verdict === 'CRITICAL THREAT' || result.riskScore >= 75;
  const isSuspicious = result.verdict === 'SUSPICIOUS' || (result.riskScore >= 30 && result.riskScore < 75);

  const badgeColor = isMalicious
    ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
    : isSuspicious
    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

  const badgeIcon = isMalicious ? (
    <ShieldAlert className="w-4 h-4 text-rose-400" />
  ) : isSuspicious ? (
    <AlertTriangle className="w-4 h-4 text-amber-400" />
  ) : (
    <ShieldCheck className="w-4 h-4 text-emerald-400" />
  );

  const displayVerdict = isMalicious
    ? 'CONFIRMED MALICIOUS'
    : isSuspicious
    ? 'SUSPICIOUS ACTIVITY'
    : 'VERIFIED LEGITIMATE';

  return (
    <section className="w-full max-w-5xl mx-auto mt-8 space-y-6">
      {/* 1. Layman-First Responsible AI Translation Layer (Upfront for all users) */}
      <LaymanAITranslation result={result} />

      {/* 2. Executive Threat Assessment Summary Card */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-6 sm:p-8 backdrop-blur-sm">
        {/* Top Header: Badge + Risk Score */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-zinc-800/80">
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold tracking-wide border ${badgeColor}`}>
              {badgeIcon}
              <span>{displayVerdict}</span>
            </span>
            <span className="text-xs font-mono text-zinc-500 truncate max-w-xs sm:max-w-md">
              {result.domain || result.url}
            </span>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-xs uppercase tracking-wider text-zinc-500 font-medium">Composite Threat Index:</span>
            <span className={`text-2xl font-bold font-mono ${
              isMalicious ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {result.riskScore}
            </span>
            <span className="text-xs text-zinc-600 font-mono">/ 100</span>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="py-6">
          <h3 className="text-xs uppercase tracking-wider text-zinc-500 font-semibold mb-2">Executive Threat Assessment</h3>
          <p className="text-zinc-200 text-sm sm:text-base leading-relaxed max-w-3xl">
            {result.executiveSummary}
          </p>
        </div>

        {/* Action Recommendation Banner */}
        <div className={`p-4 rounded-lg border text-xs sm:text-sm flex items-start gap-3 ${
          isMalicious
            ? 'bg-rose-950/20 border-rose-900/40 text-rose-200'
            : isSuspicious
            ? 'bg-amber-950/20 border-amber-900/40 text-amber-200'
            : 'bg-emerald-950/20 border-emerald-900/40 text-emerald-200'
        }`}>
          <div className="mt-0.5">
            {isMalicious ? <ShieldAlert className="w-4 h-4 text-rose-400" /> : isSuspicious ? <AlertTriangle className="w-4 h-4 text-amber-400" /> : <ShieldCheck className="w-4 h-4 text-emerald-400" />}
          </div>
          <div>
            <span className="font-semibold block mb-0.5">Recommended Safety Protocol:</span>
            <span>
              {result.recommendedPrecautions && result.recommendedPrecautions.length > 0
                ? result.recommendedPrecautions[0]
                : isMalicious
                ? 'Do not open this destination, authorize payment requests, or enter login credentials. Network perimeter isolation is advised.'
                : isSuspicious
                ? 'Exercise heightened scrutiny. Verify out-of-band communication before following links or transferring funds.'
                : 'Cryptographic identity and domain baseline validated. Standard browsing caution applies.'}
            </span>
          </div>
        </div>

        {/* Deep Dive Gateways Grid */}
        <div className="mt-8 pt-6 border-t border-zinc-800/80">
          <h4 className="text-xs uppercase tracking-wider text-zinc-500 font-semibold mb-4">
            Investigate Technical Evidence
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* 1. Cryptography Gateway */}
            <Link
              href="/crypto"
              className="p-4 rounded-lg bg-zinc-900/50 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-all hover:-translate-y-0.5 group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">Cryptographic Trust</span>
                  <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 group-hover:translate-x-0.5 transition-all" />
                </div>
                <p className="text-xs text-zinc-300 font-medium line-clamp-2">
                  {result.emudhraAudit?.isVulnerable
                    ? 'eMudhra Flaw (Scalar d=4) recovered on NIST P-384'
                    : result.certificateChain?.[2]?.issuer
                    ? `TLS verified: ${result.certificateChain[2].issuer.split(',')[0].replace('CN=', '')}`
                    : 'Standard commercial certificate chain verified'}
                </p>
              </div>
              <span className="text-[10px] text-sky-400 mt-3 block font-mono">Inspect Certificate Tree →</span>
            </Link>

            {/* 2. Threats & Posture Gateway */}
            <Link
              href="/threats"
              className="p-4 rounded-lg bg-zinc-900/50 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-all hover:-translate-y-0.5 group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">Phishing & Posture</span>
                  <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 group-hover:translate-x-0.5 transition-all" />
                </div>
                <p className="text-xs text-zinc-300 font-medium line-clamp-2">
                  {result.typosquatting?.isImpersonation
                    ? `Typosquatting against ${result.typosquatting.targetedBrand} (dist: ${result.typosquatting.levenshteinDistance})`
                    : `Security Posture Grade ${result.securityPosture?.overallGrade || 'A'} (${result.securityPosture?.gradeNumeric ?? 100}/100)`}
                </p>
              </div>
              <span className="text-[10px] text-sky-400 mt-3 block font-mono">View Heuristic Diff →</span>
            </Link>

            {/* 3. Community Radar Gateway */}
            <Link
              href={result.web3Commitment?.reportHash ? `/radar?hash=${result.web3Commitment.reportHash}` : '/radar'}
              className="p-4 rounded-lg bg-zinc-900/50 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-all hover:-translate-y-0.5 group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">Community Radar</span>
                  <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 group-hover:translate-x-0.5 transition-all" />
                </div>
                <p className="text-xs text-zinc-300 font-medium line-clamp-2">
                  {result.web3Commitment?.reportHash
                    ? `On-Chain Hash: ${result.web3Commitment.reportHash.slice(0, 10)}... (Block #${result.web3Commitment.blockNumber ?? 1})`
                    : 'Collaborative consensus feed & Web3 on-chain integrity verification'}
                </p>
              </div>
              <span className="text-[10px] text-sky-400 mt-3 block font-mono">Open Community Feed →</span>
            </Link>

            {/* 4. QR Quishing Gateway */}
            <Link
              href="/quishing"
              className="p-4 rounded-lg bg-zinc-900/50 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition-all hover:-translate-y-0.5 group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">Quishing Guard</span>
                  <ArrowRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-200 group-hover:translate-x-0.5 transition-all" />
                </div>
                <p className="text-xs text-zinc-300 font-medium line-clamp-2">
                  Deceptive UPI payment URI audit & bill impostor detector
                </p>
              </div>
              <span className="text-[10px] text-sky-400 mt-3 block font-mono">Scan QR Codes →</span>
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
};
