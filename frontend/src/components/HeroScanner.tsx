'use client';

import React, { useState } from 'react';
import { Search, Globe, MessageSquare, QrCode, ArrowRight, Loader2, Sparkles } from 'lucide-react';

interface HeroScannerProps {
  onScan: (target: string, inputType?: string) => Promise<void>;
  isLoading: boolean;
  onSelectScenario: (scenarioId: string) => void;
  activeScenarioId?: string;
}

export const HeroScanner: React.FC<HeroScannerProps> = ({
  onScan,
  isLoading,
  onSelectScenario,
  activeScenarioId,
}) => {
  const [inputMode, setInputMode] = useState<'url' | 'message' | 'qr'>('url');
  const [inputValue, setInputValue] = useState('https://auth.secure-emudhra-gateway.org');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim() || isLoading) return;
    onScan(inputValue.trim(), inputMode);
  };

  const sampleScenarios = [
    {
      id: 'scenario-1-emudhra-weak-ca',
      label: 'eMudhra CA Flaw (Scalar d=4)',
      url: 'https://auth.secure-emudhra-gateway.org',
      mode: 'url' as const,
    },
    {
      id: 'scenario-2-paypal-typosquat-harvest',
      label: 'PayPal Typosquat + Form Harvest',
      url: 'https://paypa1-secure.com/login',
      mode: 'url' as const,
    },
    {
      id: 'scenario-3-sbi-kyc-sms-scam',
      label: 'SBI 24h Coercive SMS',
      url: 'Dear customer, your SBI NetBanking account will be blocked today within 24h due to pending KYC update. Click http://sbi-kyc-update.in to verify now or call 9876543210.',
      mode: 'message' as const,
    },
    {
      id: 'scenario-7-electricity-quishing-upi',
      label: 'State Discom UPI Quishing',
      url: 'upi://pay?pa=bescom.electricity.bill@okhdfcbank&pn=StateElectricityDiscom&am=4800&cu=INR',
      mode: 'url' as const,
    },
    {
      id: 'scenario-6-google-corporate-official',
      label: 'Google Corporate (Clean)',
      url: 'https://google.com',
      mode: 'url' as const,
    },
  ];

  const handleChipClick = (scenario: typeof sampleScenarios[0]) => {
    setInputMode(scenario.mode);
    setInputValue(scenario.url);
    onSelectScenario(scenario.id);
  };

  return (
    <div className="w-full max-w-3xl mx-auto text-center pt-8 pb-4">
      {/* Motto & Value Proposition */}
      <div className="mb-8">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-[11px] font-medium text-zinc-400 mb-4">
          <Sparkles className="w-3.5 h-3.5 text-sky-400" />
          <span>Cryptographic Digital Trust & Scam Intelligence</span>
        </div>
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-white mb-3">
          Verify before you trust.
        </h1>
        <p className="text-zinc-400 text-sm sm:text-base max-w-xl mx-auto leading-relaxed">
          Instant, evidence-grounded threat detection. Unmask phishing links, compromised digital certificates, and payment scams before they do damage.
        </p>
      </div>

      {/* Input Mode Selector */}
      <div className="flex items-center justify-center gap-1 mb-3">
        <button
          type="button"
          onClick={() => {
            setInputMode('url');
            if (inputMode === 'message') setInputValue('https://auth.secure-emudhra-gateway.org');
          }}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            inputMode === 'url'
              ? 'bg-zinc-800 text-white'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <Globe className="w-3.5 h-3.5 text-sky-400" />
          <span>Link or Domain</span>
        </button>

        <button
          type="button"
          onClick={() => {
            setInputMode('message');
            if (inputMode === 'url') setInputValue('Dear customer, your SBI account will be blocked in 24h. Click http://sbi-kyc.in to verify.');
          }}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            inputMode === 'message'
              ? 'bg-zinc-800 text-white'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          <MessageSquare className="w-3.5 h-3.5 text-sky-400" />
          <span>SMS / Message</span>
        </button>

        <a
          href="/quishing"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 transition-colors"
        >
          <QrCode className="w-3.5 h-3.5 text-sky-400" />
          <span>QR Scanner →</span>
        </a>
      </div>

      {/* Primary Input Pill */}
      <form onSubmit={handleSubmit} className="relative group">
        <div className="relative flex items-center bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden focus-within:border-zinc-700 focus-within:ring-1 focus-within:ring-zinc-700 transition-all shadow-2xl">
          <div className="pl-4 text-zinc-500">
            {inputMode === 'url' ? (
              <Search className="w-5 h-5" />
            ) : (
              <MessageSquare className="w-5 h-5" />
            )}
          </div>

          {inputMode === 'message' ? (
            <textarea
              rows={2}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Paste suspicious SMS, WhatsApp notice, or email text..."
              className="w-full bg-transparent px-3 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none resize-none font-mono"
            />
          ) : (
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Paste target URL, domain, or link (e.g. https://paypa1-secure.com)..."
              className="w-full bg-transparent px-3 py-3.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none font-mono"
            />
          )}

          <div className="pr-2">
            <button
              type="submit"
              disabled={isLoading || !inputValue.trim()}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-zinc-100 hover:bg-white text-zinc-900 text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-all active:scale-[0.98]"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing...</span>
                </>
              ) : (
                <>
                  <span>Scan Target</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Curated Sample Chips */}
      <div className="flex flex-wrap items-center justify-center gap-2 mt-4">
        <span className="text-[11px] text-zinc-500 font-medium">Test evaluation samples:</span>
        {sampleScenarios.map((sc) => {
          const isActive = activeScenarioId === sc.id;
          return (
            <button
              key={sc.id}
              type="button"
              onClick={() => handleChipClick(sc)}
              className={`px-2.5 py-1 rounded-md text-[11px] transition-colors ${
                isActive
                  ? 'bg-zinc-800 text-zinc-200 border border-zinc-700'
                  : 'bg-zinc-900/60 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-800/80'
              }`}
            >
              {sc.label}
            </button>
          );
        })}
      </div>
    </div>
  );
};
