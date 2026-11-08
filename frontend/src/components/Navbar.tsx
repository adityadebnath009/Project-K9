'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, FileCode, ExternalLink, Activity } from 'lucide-react';
import { checkBackendHealth, API_BASE_URL } from '@/lib/api';
import { STIXExportModal } from '@/components/collaborative/STIXExportModal';

export const Navbar: React.FC = () => {
  const pathname = usePathname();
  const [backendStatus, setBackendStatus] = useState<{ online: boolean; latencyMs?: number; version?: string }>({
    online: false,
  });
  const [stixOpen, setStixOpen] = useState(false);
  const [stixBundle, setStixBundle] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    checkBackendHealth().then(setBackendStatus);
    const interval = setInterval(() => {
      checkBackendHealth().then(setBackendStatus);
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleOpenStix = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/threats/stix`);
      if (res.ok) {
        const data = await res.json();
        setStixBundle(data);
      } else {
        throw new Error('Fallback');
      }
    } catch {
      setStixBundle({
        type: 'bundle',
        id: `bundle--k9-sentinel-${Date.now()}`,
        spec_version: '2.1',
        objects: [
          {
            type: 'indicator',
            spec_version: '2.1',
            id: 'indicator--mock-sample-1',
            name: 'eMudhra Bug 2083449 Compromised Sub-CA',
            pattern: "[x509-certificate:hashes.'SHA-256' = 'EE:43:09:88:...']",
            pattern_type: 'stix',
          },
        ],
      });
    }
    setStixOpen(true);
  };

  const navLinks = [
    { href: '/', label: 'Scanner' },
    { href: '/crypto', label: 'Certificate Trust' },
    { href: '/threats', label: 'Threat Heuristics' },
    { href: '/radar', label: 'Community Radar' },
    { href: '/quishing', label: 'QR Guard' },
  ];

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-zinc-800/80 bg-[#09090b]/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          {/* Logo & Identity */}
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2.5 group">
              <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center group-hover:border-zinc-700 transition-colors">
                <Shield className="w-4 h-4 text-sky-400" />
              </div>
              <div className="flex flex-col">
                <span className="font-semibold text-sm tracking-tight text-zinc-100 flex items-center gap-1.5">
                  K9 Sentinel
                  <span className="text-[10px] font-mono text-zinc-500 font-normal">v1.0</span>
                </span>
                <span className="text-[11px] text-zinc-500 hidden sm:inline">Trust Intelligence</span>
              </div>
            </Link>

            {/* Live Backend Indicator */}
            <div className="ml-2 flex items-center gap-2 px-2.5 py-1 rounded-full bg-zinc-900/80 border border-zinc-800 text-[11px] text-zinc-400 font-mono">
              {backendStatus.online ? (
                <>
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  <span className="text-emerald-400 font-medium">Live API</span>
                  {backendStatus.latencyMs && (
                    <span className="text-zinc-500 hidden md:inline">· {backendStatus.latencyMs}ms</span>
                  )}
                </>
              ) : (
                <>
                  <span className="h-2 w-2 rounded-full bg-amber-500/80"></span>
                  <span className="text-amber-400">Offline / Standalone</span>
                </>
              )}
            </div>
          </div>

          {/* Clean Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navLinks.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`px-3 py-1.5 rounded-md text-xs transition-colors ${
                    isActive
                      ? 'bg-zinc-800 text-zinc-100 font-medium'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* Action Button: STIX 2.1 Export */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleOpenStix}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 text-xs font-medium transition-colors"
            >
              <FileCode className="w-3.5 h-3.5 text-sky-400" />
              <span>STIX 2.1</span>
            </button>
          </div>
        </div>
      </header>

      {/* Standard STIX Modal */}
      <STIXExportModal
        isOpen={stixOpen}
        bundle={stixBundle}
        onClose={() => setStixOpen(false)}
      />
    </>
  );
};
