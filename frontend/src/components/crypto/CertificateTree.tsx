'use client';

import React, { useState } from 'react';
import { Network, ShieldCheck, ShieldAlert, AlertTriangle, Copy, Check, Info } from 'lucide-react';
import { CertificateNode } from '@/types/api';

interface CertificateTreeProps {
  chain: CertificateNode[];
}

export const CertificateTree: React.FC<CertificateTreeProps> = ({ chain }) => {
  const [selectedCertIndex, setSelectedCertIndex] = useState<number>(() => {
    // Default to the first revoked or warning cert, otherwise leaf cert
    const revokedIdx = chain.findIndex((c) => c.status === 'revoked' || c.status === 'invalid');
    return revokedIdx !== -1 ? revokedIdx : chain.length - 1;
  });
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);

  const selectedCert = chain[selectedCertIndex] || chain[0];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFingerprint(true);
    setTimeout(() => setCopiedFingerprint(false), 2000);
  };

  const getNodeIcon = (status: CertificateNode['status']) => {
    switch (status) {
      case 'trusted':
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      case 'revoked':
      case 'invalid':
        return <ShieldAlert className="w-4 h-4 text-rose-500" />;
    }
  };

  const getNodeBorder = (status: CertificateNode['status'], isSelected: boolean) => {
    if (isSelected) {
      if (status === 'revoked' || status === 'invalid') return 'border-rose-500 bg-rose-950/30 ring-1 ring-rose-500/40';
      if (status === 'warning') return 'border-amber-500 bg-amber-950/30 ring-1 ring-amber-500/40';
      return 'border-emerald-500 bg-emerald-950/30 ring-1 ring-emerald-500/40';
    }
    if (status === 'revoked' || status === 'invalid') return 'border-rose-900/60 bg-rose-950/10 hover:border-rose-700';
    if (status === 'warning') return 'border-amber-900/60 bg-amber-950/10 hover:border-amber-700';
    return 'border-border-subtle bg-ground/80 hover:border-border-active';
  };

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-sky-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            X.509 Trust Hierarchy & Certificate Chain
          </h3>
        </div>
        <span className="font-mono text-[11px] text-zinc-500">
          Chain Depth: <span className="text-zinc-200">{chain.length} Nodes</span>
        </span>
      </div>

      {/* Trust Chain Hierarchy Visualizer (Horizontal Node Flow) */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center gap-2 py-2">
        {chain.map((cert, idx) => {
          const isSelected = selectedCertIndex === idx;
          const isLast = idx === chain.length - 1;

          return (
            <React.Fragment key={cert.serialNumber + idx}>
              <button
                type="button"
                onClick={() => setSelectedCertIndex(idx)}
                className={`flex-1 p-3 rounded-md border text-left transition-all active:scale-[0.99] block ${getNodeBorder(
                  cert.status,
                  isSelected
                )}`}
              >
                <span className="flex items-center justify-between pb-1">
                  <span className="font-mono text-[10px] uppercase font-bold text-zinc-500">
                    {cert.level === 'root'
                      ? 'Root Trust Anchor'
                      : cert.level === 'intermediate'
                      ? 'Intermediate Sub-CA'
                      : 'End-Entity Leaf'}
                  </span>
                  {getNodeIcon(cert.status)}
                </span>

                <span className="font-mono text-xs font-semibold text-zinc-100 truncate block" title={cert.subject}>
                  {cert.subject.split(',')[0].replace('CN=', '')}
                </span>

                <span className="flex items-center justify-between pt-2 text-[10px] font-mono text-zinc-400">
                  <span>{cert.keyType}</span>
                  {cert.oneCrlRevoked && (
                    <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 font-bold border border-rose-800">
                      OneCRL
                    </span>
                  )}
                </span>
              </button>

              {!isLast && (
                <div className="hidden md:flex items-center justify-center text-zinc-600 px-1 font-mono text-xs">
                  →
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Selected Certificate Deep Inspector Panel */}
      {selectedCert && (
        <div className="p-4 rounded-md bg-ground border border-border-subtle space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 pb-2">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-zinc-200">
                {selectedCert.level.toUpperCase()} CERTIFICATE INSPECTOR
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                  selectedCert.status === 'revoked' || selectedCert.status === 'invalid'
                    ? 'bg-rose-950 border-rose-800 text-rose-300'
                    : selectedCert.status === 'warning'
                    ? 'bg-amber-950 border-amber-800 text-amber-300'
                    : 'bg-emerald-950 border-emerald-800 text-emerald-300'
                }`}
              >
                {selectedCert.status}
              </span>
            </div>

            {selectedCert.statusReason && (
              <span className="text-[11px] font-mono text-rose-400">
                {selectedCert.statusReason}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            <div>
              <span className="text-zinc-500 block text-[10px]">SUBJECT (DN):</span>
              <span className="text-zinc-200 break-all">{selectedCert.subject}</span>
            </div>

            <div>
              <span className="text-zinc-500 block text-[10px]">ISSUER:</span>
              <span className="text-zinc-200 break-all">{selectedCert.issuer}</span>
            </div>

            <div>
              <span className="text-zinc-500 block text-[10px]">VALIDITY SPAN:</span>
              <span className="text-zinc-300">
                {selectedCert.validFrom.split('T')[0]} — {selectedCert.validTo.split('T')[0]}
              </span>
            </div>

            <div>
              <span className="text-zinc-500 block text-[10px]">SIGNATURE ALGORITHM:</span>
              <span className="text-zinc-300">{selectedCert.signatureAlgorithm}</span>
            </div>
          </div>

          {/* Fingerprint block with copy button */}
          <div className="pt-2 border-t border-zinc-900">
            <div className="flex items-center justify-between pb-1">
              <span className="font-mono text-[10px] text-zinc-500">SHA-256 FINGERPRINT:</span>
              <button
                type="button"
                onClick={() => handleCopy(selectedCert.sha256Fingerprint)}
                className="flex items-center gap-1 text-[10px] font-mono text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                {copiedFingerprint ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <div className="p-2 rounded bg-black/70 border border-zinc-800 font-mono text-[11px] text-zinc-400 break-all select-all">
              {selectedCert.sha256Fingerprint}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
