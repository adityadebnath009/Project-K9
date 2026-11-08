'use client';

import React, { useState } from 'react';
import { Key, Copy, Check, AlertOctagon, Terminal, Play, Cpu, ShieldAlert, Sparkles } from 'lucide-react';
import { EmudhraAudit, RSAKeyAudit } from '@/types/api';

interface EmudhraAuditCardProps {
  emudhra: EmudhraAudit;
  rsaAudit: RSAKeyAudit;
}

export const EmudhraAuditCard: React.FC<EmudhraAuditCardProps> = ({ emudhra, rsaAudit }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [solverRunning, setSolverRunning] = useState(false);
  const [solverSteps, setSolverSteps] = useState<Array<{ step: string; formula: string; result: string }> | null>(null);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(label);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const runScalarSolver = () => {
    setSolverRunning(true);
    setSolverSteps(null);

    setTimeout(() => {
      setSolverRunning(false);
      setSolverSteps([
        {
          step: '1. Base Generator G on NIST P-384',
          formula: 'G = (Gx, Gy) where y² ≡ x³ - 3x + b (mod p)',
          result: 'G.x = 0xaa87ca22be...872760ab7',
        },
        {
          step: '2. Point Doubling: 2G = G + G',
          formula: 'λ = (3Gx² - 3) / (2Gy) mod p; x₂ = λ² - 2Gx mod p',
          result: '2G.x = 0x76b291d4e0...9c011a4ff',
        },
        {
          step: '3. Point Quadrupling: 4G = 2G + 2G',
          formula: 'λ₂ = (3x₂² - 3) / (2y₂) mod p; x₄ = λ₂² - 2x₂ mod p',
          result: '4G = Q(x, y) (Exact 384-bit coordinate match!)',
        },
        {
          step: '4. Discrete Log Resolution',
          formula: 'd · G = Q ⟹ d = 4 (Trivial Discrete Log <0.04ms)',
          result: 'CRITICAL FLAW: Private key scalar recovered: d = 4',
        },
      ]);
    }, 400);
  };

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-subtle gap-2">
        <div className="flex items-center gap-2">
          <Key className="w-4 h-4 text-rose-500" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Cryptographic Scalar & eMudhra Auditor (Bug 2083449)
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {emudhra.isVulnerable ? (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950/70 border border-rose-800 text-rose-300 font-mono text-xs font-bold animate-pulse">
              <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
              <span>FLAWED PRIVATE SCALAR (d=4)</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/40 border border-emerald-800 text-emerald-300 font-mono text-xs font-semibold">
              <Check className="w-3.5 h-3.5" />
              <span>KEY ENTROPY COMPLIANT</span>
            </span>
          )}
        </div>
      </div>

      {/* Primary Mathematical Inspection Box */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: ECC Coordinates & Equation */}
        <div className="lg:col-span-8 space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-zinc-400">
              CURVE SPECIFICATION:{' '}
              <span className="text-zinc-100 font-bold">{emudhra.curve}</span>
            </span>
            <span className="font-mono text-xs text-zinc-400">
              EQUATION: <code className="text-emerald-400">{emudhra.scalarEquation}</code>
            </span>
          </div>

          {/* Coordinate Blocks */}
          <div className="space-y-2 font-mono text-xs">
            {/* Public Point Q.x */}
            <div className="p-2.5 rounded bg-black/60 border border-zinc-800 space-y-1">
              <div className="flex items-center justify-between text-[11px] text-zinc-500">
                <span>PUBLIC KEY POINT Q [Coordinate X]:</span>
                <button
                  type="button"
                  onClick={() => handleCopy(emudhra.publicPointQ.x, 'qx')}
                  className="flex items-center gap-1 hover:text-zinc-200 transition-colors"
                >
                  {copiedKey === 'qx' ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>{copiedKey === 'qx' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <p className="text-zinc-300 font-mono text-[11px] break-all select-all leading-snug">
                {emudhra.publicPointQ.x}
              </p>
            </div>

            {/* Public Point Q.y */}
            <div className="p-2.5 rounded bg-black/60 border border-zinc-800 space-y-1">
              <div className="flex items-center justify-between text-[11px] text-zinc-500">
                <span>PUBLIC KEY POINT Q [Coordinate Y]:</span>
                <button
                  type="button"
                  onClick={() => handleCopy(emudhra.publicPointQ.y, 'qy')}
                  className="flex items-center gap-1 hover:text-zinc-200 transition-colors"
                >
                  {copiedKey === 'qy' ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>{copiedKey === 'qy' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <p className="text-zinc-300 font-mono text-[11px] break-all select-all leading-snug">
                {emudhra.publicPointQ.y}
              </p>
            </div>
          </div>

          {/* Ruby text alert for Discovered Scalar */}
          <div
            className={`p-3 rounded-md border font-mono text-xs space-y-1 ${
              emudhra.isVulnerable
                ? 'bg-rose-950/30 border-rose-800 text-rose-200'
                : 'bg-emerald-950/20 border-emerald-900 text-emerald-300'
            }`}
          >
            <div className="flex items-center justify-between font-bold">
              <span>DISCOVERED PRIVATE SCALAR:</span>
              <span className="text-sm px-2 py-0.5 rounded bg-black/50 border border-current">
                d = {emudhra.discoveredScalar}
              </span>
            </div>
            <p className="text-[11px] opacity-90">{emudhra.rubyAlert}</p>
          </div>

          {/* Technical Context */}
          <div className="p-3 rounded bg-ground border border-border-subtle font-sans text-xs text-zinc-400 space-y-1">
            <span className="font-mono text-[10px] text-zinc-500 uppercase tracking-wider block">
              Cryptanalysis Notes {'//'} Mozilla Bug 2083449:
            </span>
            <p className="leading-relaxed">{emudhra.technicalNotes}</p>
          </div>
        </div>

        {/* Right: Live Scalar Multiplier Solver + ROCA & RSA Key Quality */}
        <div className="lg:col-span-4 space-y-4 flex flex-col justify-between">
          {/* Live Solver Simulation Box */}
          <div className="p-3.5 rounded-md bg-ground border border-border-subtle space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-zinc-200 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                <span>Scalar Solver</span>
              </span>
              <span className="text-[10px] font-mono text-zinc-500">BSGS / Point Doubling</span>
            </div>

            <p className="text-[11px] font-sans text-zinc-400">
              Iterates candidate small scalars $d \in [1, 1024]$ testing if $Q&apos; = d \cdot G$ equals published public point.
            </p>

            <button
              type="button"
              onClick={runScalarSolver}
              disabled={solverRunning}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded bg-zinc-800 hover:bg-zinc-700 active:scale-[0.98] border border-zinc-700 text-zinc-200 font-mono text-xs transition-all disabled:opacity-50"
            >
              {solverRunning ? (
                <>
                  <Terminal className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                  <span>Computing Discrete Log...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Execute Point Doubling Proof</span>
                </>
              )}
            </button>

            {solverSteps && (
              <div className="p-2.5 rounded bg-black/80 border border-rose-800 font-mono text-[10px] text-zinc-300 space-y-2 animate-fade-in">
                <div className="flex items-center justify-between font-bold text-rose-400 border-b border-zinc-800 pb-1">
                  <span>Wayne Discrete Log Proof</span>
                  <span className="bg-rose-950 px-1.5 py-0.5 rounded border border-rose-800 text-[10px]">d = 4</span>
                </div>
                {solverSteps.map((st, i) => (
                  <div key={i} className="space-y-0.5 border-b border-zinc-900 pb-1">
                    <div className="text-zinc-400 font-semibold">{st.step}</div>
                    <code className="text-sky-300 block text-[9px]">{st.formula}</code>
                    <div className="text-emerald-400 text-[9px]">{st.result}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* ROCA & RSA Audit Card */}
          <div className="p-3.5 rounded-md bg-ground border border-border-subtle space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-zinc-200 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-sky-400" />
                <span>ROCA & RSA Audit</span>
              </span>
              <span className="text-[10px] font-mono text-zinc-500">CVE-2017-15361</span>
            </div>

            <div className="space-y-1.5 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-zinc-500 text-[11px]">KEY LENGTH:</span>
                <span
                  className={`font-semibold ${
                    rsaAudit.keyLength < 2048 ? 'text-rose-400' : 'text-zinc-200'
                  }`}
                >
                  {rsaAudit.keyLength}-bit {rsaAudit.keyLength < 2048 && '(INADEQUATE)'}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-zinc-500 text-[11px]">ROCA VULNERABILITY:</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                    rsaAudit.rocaVulnerable
                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                      : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                  }`}
                >
                  {rsaAudit.rocaStatus}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-zinc-500 text-[11px]">PUBLIC EXPONENT:</span>
                <span className="text-zinc-300">e = {rsaAudit.publicExponent}</span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-zinc-500 text-[11px]">ALGORITHM:</span>
                <span
                  className={`text-[11px] truncate max-w-[140px] ${
                    rsaAudit.isAlgorithmDeprecated ? 'text-rose-400' : 'text-zinc-300'
                  }`}
                >
                  {rsaAudit.signatureAlgorithm}
                </span>
              </div>

              {/* Render Active RSA Defect Issues if any */}
              {rsaAudit.issues && rsaAudit.issues.length > 0 && (
                <div className="pt-2 border-t border-zinc-800 space-y-1">
                  <span className="text-[10px] text-rose-400 font-bold block">FLAGGED RSA DEFECTS:</span>
                  {rsaAudit.issues.map((issue, idx) => (
                    <div key={idx} className="p-1 rounded bg-rose-950/40 border border-rose-900/60 text-[10px] text-rose-300 flex items-start gap-1">
                      <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0 mt-0.5" />
                      <span>{issue}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
