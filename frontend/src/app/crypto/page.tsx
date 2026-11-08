'use client';

import React, { useState, useEffect } from 'react';
import { CertificateTree } from '@/components/crypto/CertificateTree';
import { EmudhraAuditCard } from '@/components/crypto/EmudhraAuditCard';
import { CTLogTimeline } from '@/components/crypto/CTLogTimeline';
import { SCENARIO_EMUDHRA, SCENARIOS } from '@/lib/mockData';
import { scanTarget } from '@/lib/api';
import { TargetScanResult } from '@/types/api';
import { Key, Search, ArrowRight, Loader2, Sparkles, CheckCircle2, ShieldAlert } from 'lucide-react';

export default function CryptoPage() {
  const [inputMode, setInputMode] = useState<'url' | 'pem'>('url');
  const [targetInput, setTargetInput] = useState<string>('https://auth.secure-emudhra-gateway.org');
  const [pemInput, setPemInput] = useState<string>('');
  const [data, setData] = useState<TargetScanResult>(SCENARIO_EMUDHRA);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeScenarioId, setActiveScenarioId] = useState<string>('emudhra');

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
    const cleanTarget = (inputMode === 'url' ? targetInput : pemInput).trim();
    if (!cleanTarget || isLoading) return;
    setIsLoading(true);
    try {
      const res = await scanTarget(cleanTarget);
      setData(res);
      setActiveScenarioId('custom');
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_scan', JSON.stringify(res));
        if (inputMode === 'url') {
          window.history.replaceState(null, '', `?target=${encodeURIComponent(cleanTarget)}`);
        }
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectPreset = async (scenarioId: string, url: string) => {
    setInputMode('url');
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
        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-[11px] font-medium text-sky-400 mb-2">
          <Key className="w-3.5 h-3.5" />
          <span>Cybersecurity Pillar (30% Evaluation Weight)</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          Cryptographic Trust & Certificate Authority Audit
        </h1>
        <p className="text-zinc-400 text-xs sm:text-sm mt-1 max-w-3xl leading-relaxed">
          Detects the real-world eMudhra TLS certificate incident (Mozilla Bug 2083449) via Wayne discrete log scalar recovery ($d \le 1000$), Mozilla OneCRL revocation blocklists, and RSA key size verification.
        </p>

        {/* Input Mode Switcher */}
        <div className="flex items-center gap-2 mt-4">
          <button
            type="button"
            onClick={() => setInputMode('url')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              inputMode === 'url' ? 'bg-sky-500 text-zinc-950 font-bold' : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Domain / HTTPS Endpoint
          </button>
          <button
            type="button"
            onClick={() => setInputMode('pem')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              inputMode === 'pem' ? 'bg-sky-500 text-zinc-950 font-bold' : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200'
            }`}
          >
            Raw X.509 PEM Certificate
          </button>
        </div>

        {/* 2. Interactive Search & Audit Input Bar */}
        <form onSubmit={handleScan} className="mt-3 flex flex-col gap-2 max-w-2xl">
          {inputMode === 'url' ? (
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="Enter any domain or URL to audit certificate (e.g. google.com)"
                  className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-zinc-900/80 border border-zinc-700 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500 font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={isLoading}
                className="px-5 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-zinc-950 font-semibold text-xs tracking-tight transition-all flex items-center justify-center gap-2 shrink-0 disabled:opacity-50"
              >
                {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                <span>Audit Certificate</span>
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <textarea
                value={pemInput}
                onChange={(e) => setPemInput(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;Paste X.509 PEM Certificate to audit for Wayne Discrete Log (d <= 1000)...&#10;-----END CERTIFICATE-----"
                rows={5}
                className="w-full p-3 rounded-lg bg-zinc-900/80 border border-zinc-700 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-sky-500 font-mono resize-none"
              />
              <button
                type="submit"
                disabled={isLoading || !pemInput.trim()}
                className="w-full px-5 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-zinc-950 font-semibold text-xs tracking-tight transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                <span>Audit PEM Certificate Discrete Log</span>
              </button>
            </div>
          )}
        </form>

        {/* Quick Test Presets */}
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <span className="text-[11px] text-zinc-500 select-none">Quick Test:</span>
          <button
            type="button"
            onClick={() => handleSelectPreset('emudhra', 'https://auth.secure-emudhra-gateway.org')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              activeScenarioId === 'emudhra'
                ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-800'
            }`}
          >
            eMudhra Flawed CA (d=4)
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
            Google Official CA (Valid)
          </button>
          <button
            type="button"
            onClick={() => handleSelectPreset('paypal_phish', 'https://paypa1-security-verification.com/login')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              activeScenarioId === 'paypal_phish'
                ? 'bg-amber-950/60 text-amber-300 border border-amber-800'
                : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-400 border border-zinc-800'
            }`}
          >
            PayPal Clone Leaf Cert
          </button>
        </div>
      </div>

      {/* Target Status Banner */}
      <div className="flex items-center justify-between p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 text-xs">
        <div className="flex items-center gap-2">
          {data.emudhraAudit?.isVulnerable ? (
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          )}
          <span className="font-mono text-zinc-300">Audited Target: <strong className="text-white">{data.domain || targetInput}</strong></span>
        </div>
        <span className={`px-2 py-0.5 rounded font-mono text-[11px] ${
          data.emudhraAudit?.isVulnerable ? 'bg-rose-950/60 text-rose-300 border border-rose-800' : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
        }`}>
          {data.emudhraAudit?.isVulnerable ? 'CRITICAL FLAW (d=4)' : 'X.509 VALID'}
        </span>
      </div>

      {/* 3. Certificate Hierarchy & Trust Chain */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-400">
            X.509 Trust Hierarchy & Certificate Chain
          </h2>
          <span className="text-zinc-500 font-mono text-xs">
            Chain Depth: {data.certificateChain?.length || 0} Nodes
          </span>
        </div>
        <CertificateTree chain={data.certificateChain || []} tlsDetails={data.tlsDetails} />
      </section>

      {/* 4. eMudhra Mathematical Scalar Proof */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-400">
            Cryptographic Scalar & eMudhra Auditor (Bug 2083449)
          </h2>
          <span className="text-zinc-500 font-mono text-xs">
            NIST Curve P-384
          </span>
        </div>
        <EmudhraAuditCard emudhra={data.emudhraAudit} rsaAudit={data.rsaKeyAudit} />
      </section>

      {/* 5. Certificate Transparency (CT) Log Timeline */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-400">
            Public Certificate Transparency (CT) Logs & Temporal Velocity
          </h2>
        </div>
        <CTLogTimeline timeline={data.ctTimeline || []} targetDomain={data.domain} />
      </section>
    </div>
  );
}
