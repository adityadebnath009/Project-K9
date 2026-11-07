'use client';

import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Cpu, ExternalLink } from 'lucide-react';
import { ThreatVerdict } from '@/types/api';

interface RiskGaugeProps {
  score: number; // 0-100
  verdict: ThreatVerdict;
  executiveSummary: string;
  confidence: number;
  mitreTactic: string;
  mitreId: string;
  targetDomain: string;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  verdict,
  executiveSummary,
  confidence,
  mitreTactic,
  mitreId,
  targetDomain,
}) => {
  // Color tokens based on score
  const isSafe = score <= 25;
  const isSuspicious = score > 25 && score <= 60;
  const isCritical = score > 60;

  const strokeColor = isCritical ? '#e11d48' : isSuspicious ? '#f59e0b' : '#10b981';
  const badgeBg = isCritical
    ? 'bg-rose-950/40 border-rose-800 text-rose-300'
    : isSuspicious
    ? 'bg-amber-950/40 border-amber-800 text-amber-300'
    : 'bg-emerald-950/40 border-emerald-800 text-emerald-300';

  // SVG Circular progress math
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="bento-card p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          {isCritical ? (
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          ) : isSuspicious ? (
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          )}
          <span className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Threat Evaluation Verdict
          </span>
        </div>
        <span className="font-mono text-[11px] text-zinc-500">
          Domain: <span className="text-zinc-300 font-mono">{targetDomain}</span>
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center py-4">
        {/* Radial Gauge */}
        <div className="md:col-span-4 flex flex-col items-center justify-center">
          <div className="relative flex items-center justify-center">
            <svg className="w-36 h-36 -rotate-90 transform" viewBox="0 0 130 130">
              {/* Background circle */}
              <circle
                cx="65"
                cy="65"
                r={radius}
                stroke="#1f1f23"
                strokeWidth="10"
                fill="none"
              />
              {/* Animated Progress circle */}
              <circle
                cx="65"
                cy="65"
                r={radius}
                stroke={strokeColor}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="none"
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="font-mono text-3xl font-extrabold text-zinc-100 tracking-tight">
                {score}
              </span>
              <span className="font-mono text-[10px] tracking-wider text-zinc-500 uppercase">
                / 100 RISK
              </span>
            </div>
          </div>
          <span className="font-mono text-[11px] text-zinc-500 mt-1">
            Confidence: <span className="text-zinc-300">{confidence}%</span>
          </span>
        </div>

        {/* Verdict Details & Executive Summary */}
        <div className="md:col-span-8 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold tracking-wider border ${badgeBg}`}>
              {verdict}
            </span>
            {mitreId && mitreId !== 'N/A' && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-xs">
                <Cpu className="w-3 h-3 text-sky-400" />
                <span>MITRE: {mitreId}</span>
              </span>
            )}
            {mitreTactic && mitreTactic !== 'None' && (
              <span className="px-2 py-0.5 rounded bg-zinc-900/60 text-zinc-400 font-mono text-[11px] border border-zinc-800">
                {mitreTactic}
              </span>
            )}
          </div>

          <div className="p-3.5 rounded-md bg-ground border border-border-subtle">
            <p className="text-xs sm:text-sm text-zinc-200 leading-relaxed font-sans">
              {executiveSummary}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
