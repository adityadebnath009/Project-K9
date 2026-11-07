'use client';

import React from 'react';
import { ShieldAlert, FileCode, Activity } from 'lucide-react';

interface NavbarProps {
  onOpenStix: () => void;
  backendStatus: { online: boolean; latencyMs?: number; version?: string };
  activeTab: string;
  onSelectTab: (tabId: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenStix,
  backendStatus,
  activeTab,
  onSelectTab,
}) => {
  const navTabs = [
    { id: 'overview', label: '01 // Overview' },
    { id: 'crypto', label: '02 // Crypto & eMudhra' },
    { id: 'heuristics', label: '03 // Heuristics' },
    { id: 'radar', label: '04 // Radar & Guard' },
    { id: 'theory', label: '05 // Knowledge Base' },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-border-subtle bg-ground/90 backdrop-blur-md px-4 lg:px-8 py-2.5">
      <div className="max-w-[1440px] mx-auto flex items-center justify-between gap-4">
        {/* Logo & Version */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => onSelectTab('overview')}
            className="flex items-center gap-2 px-2.5 py-1 rounded bg-surface border border-border-subtle hover:border-border-active transition-colors text-left"
          >
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            <span className="font-mono font-bold tracking-wider text-sm text-zinc-100">
              K9-SENTINEL
            </span>
            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
              v1.0.4-PROD
            </span>
          </button>

          {/* System Status Pill */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-950/30 border border-emerald-900/60 text-emerald-400 text-xs font-mono">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="tracking-wide">SYSTEM: ARMED</span>
          </div>

          {/* Backend connectivity indicator */}
          <div className="hidden md:flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 px-2 py-0.5 rounded bg-surface border border-zinc-800">
            <Activity className="w-3 h-3 text-sky-400" />
            <span>
              {backendStatus.online
                ? `API: ONLINE (${backendStatus.latencyMs}ms)`
                : 'MOCK ENGINE: ARMED'}
            </span>
          </div>
        </div>

        {/* Navigation Tab Links */}
        <nav className="hidden lg:flex items-center gap-1 text-xs text-zinc-400 font-mono">
          {navTabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onSelectTab(tab.id)}
                className={`px-2.5 py-1 rounded transition-colors ${
                  isActive
                    ? 'text-zinc-100 bg-zinc-800 font-semibold border border-zinc-700 shadow-sm'
                    : 'hover:text-zinc-200 hover:bg-zinc-800/40 text-zinc-400'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Single action — Export STIX */}
        <button
          onClick={onOpenStix}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-medium text-emerald-300 bg-emerald-950/40 border border-emerald-800/60 hover:bg-emerald-900/40 hover:border-emerald-700 active:scale-[0.98] transition-all"
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Export STIX 2.1</span>
        </button>
      </div>
    </header>
  );
};
