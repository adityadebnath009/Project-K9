'use client';

import React, { useState, useEffect } from 'react';
import { TyposquattingCard } from '@/components/heuristics/TyposquattingCard';
import { FormHarvestingCard } from '@/components/heuristics/FormHarvestingCard';
import { HeaderScorecard } from '@/components/heuristics/HeaderScorecard';
import { ComplianceMatrixCard } from '@/components/heuristics/ComplianceMatrixCard';
import { SCENARIO_PAYPAL_PHISH, SCENARIOS } from '@/lib/mockData';
import { scanTarget } from '@/lib/api';
import { TargetScanResult } from '@/types/api';
import { AlertTriangle, Search, Loader2, ShieldCheck, ShieldAlert, Globe } from 'lucide-react';

export default function ThreatsPage() {
  const [targetInput, setTargetInput] = useState<string>('https://paypa1-security-verification.com/login');
  const [data, setData] = useState<TargetScanResult>(SCENARIO_PAYPAL_PHISH);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeScenarioId, setActiveScenarioId] = useState<string>('paypal_phish');

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const urlParams = new URLSearchParams(window.location.search);
    const targetParam = urlParams.get('target');

    let loadedFromCache = false;
    const cached = localStorage.getItem('k9_active_scan');
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (parsed && (parsed.url || parsed.domain)) {
          if (!targetParam || targetParam === parsed.url || targetParam === parsed.domain) {
            setData(parsed);
            setTargetInput(parsed.url || parsed.domain);
            setActiveScenarioId('custom');
            loadedFromCache = true;
          }
        }
      } catch {}
    }

    if (targetParam && !loadedFromCache) {
      setTargetInput(targetParam);
      setIsLoading(true);
      scanTarget(targetParam)
        .then((res) => {
          setData(res);
          setActiveScenarioId('custom');
          localStorage.setItem('k9_active_scan', JSON.stringify(res));
        })
        .catch(console.error)
        .finally(() => setIsLoading(false));
    }
  }, []);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanTarget = targetInput.trim();
    if (!cleanTarget || isLoading) return;
    setIsLoading(true);
    try {
      const res = await scanTarget(cleanTarget);
      setData(res);
      setActiveScenarioId('custom');
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_scan', JSON.stringify(res));
        window.history.replaceState(null, '', `?target=${encodeURIComponent(cleanTarget)}`);
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectPreset = async (scenarioId: string, url: string) => {
    setActiveScenarioId(scenarioId);
    setTargetInput(url);
    setIsLoading(true);
    try {
      const res = await scanTarget(url, scenarioId);
      setData(res);
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_scan', JSON.stringify(res));
        window.history.replaceState(null, '', `?target=${encodeURIComponent(url)}`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* 1. Page Header */}
      <div className="pb-6 border-b border-zinc-800">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-[11px] font-medium text-amber-400 mb-2">
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Phishing Heuristics & Posture Scanner</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          Impersonation Heuristics & Web Security Posture
        </h1>
        <p className="text-zinc-400 text-xs sm:text-sm mt-1 max-w-3xl leading-relaxed">
          Detects Levenshtein distance typosquats against protected brands, Cyrillic Punycode homographs, DOM form credential harvesting, and 100-point defense-in-depth HTTP security headers.
        </p>

        {/* 2. Interactive Search & Audit Input Bar */}
        <form onSubmit={handleScan} className="mt-6 flex flex-col sm:flex-row gap-2 max-w-2xl">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter any domain or URL to inspect typosquats and headers"
              className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-zinc-900/80 border border-zinc-700 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-amber-500 font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="px-5 py-2.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-zinc-950 font-semibold text-xs tracking-tight transition-all flex items-center justify-center gap-2 shrink-0 disabled:opacity-50"
          >
            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
            <span>Audit Heuristics</span>
          </button>
        </form>

        {/* Quick Test Presets */}
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <span className="text-[11px] text-zinc-500 select-none">Quick Test:</span>
          <button
            type="button"
            onClick={() => handleSelectPreset('paypal_phish', 'https://paypa1-security-verification.com/login')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              activeScenarioId === 'paypal_phish'
                ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-800'
            }`}
          >
            PayPal Typosquat
          </button>
          <button
            type="button"
            onClick={() => handleSelectPreset('insecure_app', 'https://portal.university-grades-check.edu')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              activeScenarioId === 'insecure_app'
                ? 'bg-amber-950/60 text-amber-300 border border-amber-800'
                : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-800'
            }`}
          >
            Exposed Sensitive Files
          </button>
          <button
            type="button"
            onClick={() => handleSelectPreset('clean_google', 'https://google.com')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              activeScenarioId === 'clean_google'
                ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-800'
            }`}
          >
            Google Clean Posture (Grade A+)
          </button>
        </div>
      </div>

      {/* Target Status Banner */}
      <div className="flex items-center justify-between p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 text-xs">
        <div className="flex items-center gap-2">
          {data.typosquatting?.isImpersonation ? (
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          )}
          <span className="font-mono text-zinc-300">Audited Target: <strong className="text-white">{data.domain || targetInput}</strong></span>
        </div>
        <span className={`px-2 py-0.5 rounded font-mono text-[11px] ${
          data.typosquatting?.isImpersonation ? 'bg-rose-950/60 text-rose-300 border border-rose-800' : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
        }`}>
          {data.typosquatting?.isImpersonation ? `SPOOFED (${data.typosquatting.targetedBrand})` : 'DOMAIN CLEAN'}
        </span>
      </div>

      {/* 3. Typosquatting, Homoglyphs & Urgency NLP */}
      <section className="space-y-3">
        <TyposquattingCard typosquatting={data.typosquatting} urgencyNLP={data.urgencyNLP} />
      </section>

      {/* 4. Side-by-side: DOM Form Exfiltration & 100-pt Headers Scorecard */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FormHarvestingCard domHarvesting={data.domHarvesting} targetDomain={data.domain} />
        <HeaderScorecard posture={data.securityPosture} />
      </section>

      {/* 5. Regulatory Compliance & Standards Matrix (Indian IT Act, CERT-In, ISO 27001, NIST CSF) */}
      <section className="space-y-3">
        <ComplianceMatrixCard result={data} />
      </section>
    </div>
  );
}
