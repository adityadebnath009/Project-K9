'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RotateCw,
  ArrowLeft,
  ArrowRight,
  Lock,
  AlertTriangle,
  Puzzle,
  CornerDownLeft,
  Settings2,
  Check,
  X,
} from 'lucide-react';
import { TargetScanResult } from '@/types/api';

interface BrowserGuardMockupProps {
  scanResult: TargetScanResult;
}

export const BrowserGuardMockup: React.FC<BrowserGuardMockupProps> = ({ scanResult }) => {
  const [browserState, setBrowserState] = useState<'intercepted' | 'bypassed' | 'safe'>('intercepted');
  const [showExtensionPopup, setShowExtensionPopup] = useState(false);
  const [shieldActive, setShieldActive] = useState(true);
  const [emudhraFilterActive, setEmudhraFilterActive] = useState(true);
  const [homographGuardActive, setHomographGuardActive] = useState(true);

  const isMalicious = scanResult.riskScore > 50;

  // Reset to intercepted if target changes
  React.useEffect(() => {
    setBrowserState('intercepted');
  }, [scanResult.url]);

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <Puzzle className="w-4 h-4 text-emerald-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Live Browser Guard & Extension Simulation
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowExtensionPopup(!showExtensionPopup)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 font-mono text-xs transition-colors"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>K9 Shield Extension</span>
          </button>
        </div>
      </div>

      {/* Browser Window Frame */}
      <div className="relative rounded-lg border border-border-active bg-ground overflow-hidden shadow-2xl">
        {/* Browser Top Chrome / Titlebar */}
        <div className="bg-surface-elevated px-4 py-2 border-b border-border-subtle flex items-center justify-between gap-4 select-none">
          {/* Traffic lights */}
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block border border-rose-600/40" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block border border-amber-600/40" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block border border-emerald-600/40" />
          </div>

          {/* Navigation Controls & URL Bar */}
          <div className="flex-1 flex items-center gap-2 max-w-2xl">
            <div className="flex items-center gap-1 text-zinc-500">
              <button
                onClick={() => setBrowserState('safe')}
                className="p-1 rounded hover:bg-zinc-800 hover:text-zinc-300"
                title="Back to Safety"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
              </button>
              <button className="p-1 rounded hover:bg-zinc-800 hover:text-zinc-300 disabled:opacity-30" disabled>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setBrowserState('intercepted')}
                className="p-1 rounded hover:bg-zinc-800 hover:text-zinc-300"
                title="Reload"
              >
                <RotateCw className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* URL input field inside mock browser */}
            <div className="flex-1 flex items-center gap-2 px-3 py-1.5 rounded-md bg-ground border border-border-subtle font-mono text-xs">
              {isMalicious && browserState !== 'safe' ? (
                <ShieldAlert className="w-3.5 h-3.5 text-rose-500 shrink-0" />
              ) : (
                <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              )}
              <span className="truncate text-zinc-200">
                {browserState === 'safe' ? 'about:blank' : scanResult.url}
              </span>
            </div>
          </div>

          {/* Extension icon trigger */}
          <div className="relative">
            <button
              onClick={() => setShowExtensionPopup(!showExtensionPopup)}
              className="p-1.5 rounded hover:bg-zinc-800 text-emerald-400 hover:text-emerald-300 transition-colors"
              title="K9-Sentinel Shield Active"
            >
              <ShieldCheck className="w-4 h-4" />
            </button>

            {/* Extension popup dropdown */}
            {showExtensionPopup && (
              <div className="absolute right-0 top-8 z-30 w-72 p-3.5 rounded-lg bg-surface border border-border-active shadow-2xl font-mono text-xs space-y-3 animate-fade-in">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                  <div className="flex items-center gap-1.5 font-bold text-zinc-100">
                    <ShieldAlert className="w-4 h-4 text-emerald-400" />
                    <span>K9 Guard v1.0.4</span>
                  </div>
                  <button
                    onClick={() => setShowExtensionPopup(false)}
                    className="text-zinc-500 hover:text-zinc-300"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400 text-[11px]">Real-Time Intercept:</span>
                    <button
                      onClick={() => setShieldActive(!shieldActive)}
                      className={`w-9 h-5 rounded-full p-0.5 transition-colors ${
                        shieldActive ? 'bg-emerald-600' : 'bg-zinc-800'
                      }`}
                    >
                      <span
                        className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                          shieldActive ? 'translate-x-4' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400 text-[11px]">eMudhra (d=4) Blocker:</span>
                    <button
                      onClick={() => setEmudhraFilterActive(!emudhraFilterActive)}
                      className={`w-9 h-5 rounded-full p-0.5 transition-colors ${
                        emudhraFilterActive ? 'bg-emerald-600' : 'bg-zinc-800'
                      }`}
                    >
                      <span
                        className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                          emudhraFilterActive ? 'translate-x-4' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-zinc-400 text-[11px]">Homograph / Typosquat:</span>
                    <button
                      onClick={() => setHomographGuardActive(!homographGuardActive)}
                      className={`w-9 h-5 rounded-full p-0.5 transition-colors ${
                        homographGuardActive ? 'bg-emerald-600' : 'bg-zinc-800'
                      }`}
                    >
                      <span
                        className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                          homographGuardActive ? 'translate-x-4' : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                </div>

                <div className="p-2 rounded bg-black/60 border border-zinc-800 text-[10px] text-zinc-400">
                  <span>Engine: Local WebCrypto + crt.sh live revocation telemetry</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Browser Viewport Area */}
        <div className="min-h-[300px] flex flex-col justify-center items-center p-6 bg-ground relative">
          {/* STATE 1: MALICIOUS INTERCEPTED */}
          {isMalicious && browserState === 'intercepted' && (
            <div className="w-full max-w-xl p-6 rounded-lg bg-surface border border-rose-900/60 shadow-2xl space-y-4 font-mono animate-fade-in">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded bg-rose-950/80 border border-rose-800 text-rose-400">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-rose-300">
                    K9-Sentinel Shield: Navigation Intercepted
                  </h4>
                  <p className="text-[11px] text-zinc-400 font-sans">
                    Hazardous site blocked prior to TLS handshake completion.
                  </p>
                </div>
              </div>

              <div className="p-3.5 rounded bg-black/70 border border-rose-950 text-xs text-zinc-300 font-sans space-y-2">
                <p className="font-semibold text-rose-200">
                  Target Host: <code className="font-mono text-zinc-100">{scanResult.domain}</code>
                </p>
                <p className="text-xs text-zinc-300">{scanResult.executiveSummary}</p>
                <ul className="list-disc list-inside text-[11px] text-zinc-400 space-y-1 pt-1 font-mono">
                  <li>Calculated Risk Index: {scanResult.riskScore}/100 ({scanResult.verdict})</li>
                  {scanResult.emudhraAudit.isVulnerable && (
                    <li>Cryptographic Flaw: Derived private scalar d=4 on NIST P-384</li>
                  )}
                  {scanResult.typosquatting.isImpersonation && (
                    <li>Impersonation: Typosquat targeting {scanResult.typosquatting.targetedBrand}</li>
                  )}
                </ul>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setBrowserState('safe')}
                  className="w-full sm:w-auto px-5 py-2 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold active:scale-[0.98] transition-all shadow-md"
                >
                  Go Back to Safety (Recommended)
                </button>

                <button
                  type="button"
                  onClick={() => setBrowserState('bypassed')}
                  className="w-full sm:w-auto text-[11px] text-zinc-500 hover:text-zinc-300 underline font-mono transition-colors"
                >
                  Proceed at Own Risk (Testing Only)
                </button>
              </div>
            </div>
          )}

          {/* STATE 2: PROCEEDED AT OWN RISK */}
          {isMalicious && browserState === 'bypassed' && (
            <div className="w-full space-y-4">
              <div className="p-2.5 rounded bg-rose-950 border border-rose-800 text-rose-200 font-mono text-xs flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>DANGER: Active Phishing / Impersonation Simulator Viewport</span>
                </div>
                <button
                  onClick={() => setBrowserState('intercepted')}
                  className="px-2 py-0.5 rounded bg-rose-900 hover:bg-rose-800 text-white text-[10px] font-bold"
                >
                  Re-arm Shield
                </button>
              </div>

              <div className="p-8 rounded border border-zinc-800 bg-black/40 text-center space-y-3 font-mono text-xs">
                <span className="text-zinc-500 uppercase tracking-wider block">
                  Simulated Malicious Payload Viewport
                </span>
                <p className="text-zinc-300 max-w-md mx-auto font-sans text-xs">
                  The untrusted target <code className="text-rose-400">{scanResult.domain}</code> would harvest user credentials or abuse forged certificates at this step.
                </p>
                <div className="pt-2">
                  <button
                    onClick={() => setBrowserState('safe')}
                    className="px-4 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono"
                  >
                    ← Return to Clean Safety
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* STATE 3: CLEAN / SAFE DOMAIN */}
          {(!isMalicious || browserState === 'safe') && (
            <div className="text-center space-y-3 font-mono text-xs max-w-md animate-fade-in">
              <div className="w-12 h-12 rounded-full bg-emerald-950/60 border border-emerald-800/80 text-emerald-400 flex items-center justify-center mx-auto">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <h4 className="text-sm font-bold text-zinc-100">
                {browserState === 'safe'
                  ? 'Safe Navigation Zone'
                  : 'Verified Authentic Web Asset'}
              </h4>
              <p className="text-zinc-400 font-sans text-xs">
                {browserState === 'safe'
                  ? 'Navigation to malicious target was safely neutralized. No network requests leaked.'
                  : `X.509 certificate authority validated. No scalar defects or typosquatting patterns detected for ${scanResult.domain}.`}
              </p>
              {browserState === 'safe' && (
                <button
                  onClick={() => setBrowserState('intercepted')}
                  className="px-4 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-mono text-xs transition-colors"
                >
                  Reload Target URL
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
