'use client';

import React, { useEffect, useRef } from 'react';
import { Search, Loader2, Sparkles, CornerDownLeft } from 'lucide-react';

interface HeroScannerProps {
  inputUrl: string;
  setInputUrl: (val: string) => void;
  activeScenarioId: string;
  onSelectScenario: (scenarioId: string) => void;
  onScan: (url?: string) => void;
  isLoading: boolean;
}

export const HeroScanner: React.FC<HeroScannerProps> = ({
  inputUrl,
  setInputUrl,
  activeScenarioId,
  onSelectScenario,
  onScan,
  isLoading,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);

  // Global Ctrl+K / Cmd+K hotkey (kept functional, visual hint removed)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputUrl.trim()) {
      onScan(inputUrl.trim());
    }
  };

  const scenarios = [
    {
      id: 'emudhra',
      icon: '🚨',
      label: 'eMudhra Flawed CA (d=4)',
      tooltip: 'NIST P-384 weak scalar d=4 (Bug 2083449)',
      badgeColor: 'border-rose-900/60 bg-rose-950/20 text-rose-300 hover:border-rose-700',
      activeColor: 'border-rose-600 bg-rose-950/40 text-rose-200 ring-1 ring-rose-500/30',
    },
    {
      id: 'paypal_phish',
      icon: '⚠️',
      label: 'PayPal Phishing Clone',
      tooltip: 'Levenshtein distance 1 typosquat with credential harvester',
      badgeColor: 'border-amber-900/60 bg-amber-950/20 text-amber-300 hover:border-amber-700',
      activeColor: 'border-amber-500 bg-amber-950/40 text-amber-200 ring-1 ring-amber-500/30',
    },
    {
      id: 'insecure_app',
      icon: '🔒',
      label: 'Insecure University Portal',
      tooltip: '1024-bit RSA cert, exposed /.git/HEAD, Grade F headers',
      badgeColor: 'border-zinc-700 bg-zinc-900/40 text-zinc-300 hover:border-zinc-500',
      activeColor: 'border-zinc-400 bg-zinc-800 text-zinc-100 ring-1 ring-zinc-400/30',
    },
    {
      id: 'clean_google',
      icon: '✅',
      label: 'Legitimate Domain (google.com)',
      tooltip: 'Google Trust Services root, Grade A+ security posture',
      badgeColor: 'border-emerald-900/60 bg-emerald-950/20 text-emerald-300 hover:border-emerald-700',
      activeColor: 'border-emerald-500 bg-emerald-950/40 text-emerald-200 ring-1 ring-emerald-500/30',
    },
  ];

  return (
    <div className="w-full space-y-4">
      {/* Scanner Input Bar */}
      <form onSubmit={handleSubmit} className="relative w-full">
        <div className="relative flex items-center w-full rounded-lg bg-surface border border-border-subtle focus-within:border-border-active focus-within:ring-1 focus-within:ring-zinc-600 shadow-xl transition-all">
          <div className="pl-4 pr-2 text-zinc-500 flex items-center pointer-events-none">
            {isLoading ? (
              <Loader2 className="w-5 h-5 text-emerald-400 animate-spin" />
            ) : (
              <Search className="w-5 h-5 text-zinc-400" />
            )}
          </div>

          <input
            ref={inputRef}
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            placeholder="Enter target URL or domain to scan..."
            className="w-full bg-transparent py-3.5 px-2 text-sm sm:text-base font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
          />

          {/* Submit button */}
          <div className="pr-2">
            <button
              type="submit"
              disabled={isLoading || !inputUrl.trim()}
              className="flex items-center gap-2 px-4 py-2 rounded-md font-mono text-xs font-semibold text-zinc-100 bg-zinc-800 hover:bg-zinc-700 active:scale-[0.98] disabled:opacity-40 disabled:pointer-events-none border border-zinc-700 hover:border-zinc-600 transition-all shadow-sm"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                  <span>SCANNING...</span>
                </>
              ) : (
                <>
                  <span>DEEP SCAN</span>
                  <CornerDownLeft className="w-3.5 h-3.5 text-zinc-400" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Preset Scenario Pills */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-2 pt-1">
        <div className="flex items-center gap-1.5 text-zinc-500 text-xs font-mono uppercase tracking-wider shrink-0">
          <Sparkles className="w-3.5 h-3.5 text-zinc-400" />
          <span>Demo Scenarios:</span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {scenarios.map((sc) => {
            const isActive = activeScenarioId === sc.id;
            return (
              <button
                key={sc.id}
                type="button"
                onClick={() => onSelectScenario(sc.id)}
                title={sc.tooltip}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md font-mono text-xs border transition-all active:scale-[0.98] ${
                  isActive ? sc.activeColor : `${sc.badgeColor} opacity-75 hover:opacity-100`
                }`}
              >
                <span>{sc.icon}</span>
                <span className="font-medium">{sc.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
