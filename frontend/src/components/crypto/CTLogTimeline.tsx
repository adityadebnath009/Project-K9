'use client';

import React from 'react';
import { History, ShieldCheck, AlertTriangle, ExternalLink, Zap } from 'lucide-react';
import { CTLogEntry } from '@/types/api';

interface CTLogTimelineProps {
  timeline: CTLogEntry[];
  targetDomain: string;
}

export const CTLogTimeline: React.FC<CTLogTimelineProps> = ({ timeline, targetDomain }) => {
  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-sky-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Certificate Transparency (CT) Timeline & crt.sh Feed
          </h3>
        </div>

        <a
          href={`https://crt.sh/?q=${targetDomain}`}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 font-mono text-[11px] text-zinc-400 hover:text-zinc-200 transition-colors"
        >
          <span>Query crt.sh</span>
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {/* Timeline List */}
      <div className="space-y-3 font-mono text-xs">
        {timeline.length === 0 ? (
          <div className="p-4 text-center text-zinc-500 font-sans">
            No logged certificates discovered in public CT logs.
          </div>
        ) : (
          timeline.map((entry) => {
            const isAnomaly = entry.status === 'revocation_anomaly';
            const isVelocity = entry.status === 'unusual_velocity';

            return (
              <div
                key={entry.id}
                className={`p-3 rounded-md border transition-all ${
                  isAnomaly
                    ? 'bg-rose-950/20 border-rose-900/60'
                    : isVelocity
                    ? 'bg-amber-950/20 border-amber-900/60'
                    : 'bg-ground/70 border-border-subtle'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 pb-1">
                  <div className="flex items-center gap-2">
                    {isAnomaly ? (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-rose-400 bg-rose-950 px-1.5 py-0.5 rounded border border-rose-800">
                        <AlertTriangle className="w-3 h-3" />
                        <span>REVOCATION ANOMALY</span>
                      </span>
                    ) : isVelocity ? (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-amber-400 bg-amber-950 px-1.5 py-0.5 rounded border border-amber-800">
                        <Zap className="w-3 h-3" />
                        <span>HIGH VELOCITY</span>
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-950 px-1.5 py-0.5 rounded border border-emerald-800">
                        <ShieldCheck className="w-3 h-3" />
                        <span>LOGGED</span>
                      </span>
                    )}
                    <span className="text-zinc-200 font-semibold">{entry.certType}</span>
                  </div>

                  <span className="text-zinc-500 text-[11px]">{entry.timestamp}</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 text-[11px] text-zinc-400 border-t border-zinc-900">
                  <div>
                    <span className="text-zinc-600 block text-[10px]">ISSUER:</span>
                    <span className="text-zinc-300 truncate block">{entry.issuer}</span>
                  </div>
                  <div>
                    <span className="text-zinc-600 block text-[10px]">CT LOG OPERATOR:</span>
                    <span className="text-zinc-300">{entry.logOperator}</span>
                  </div>
                  <div>
                    <span className="text-zinc-600 block text-[10px]">SERIAL:</span>
                    <span className="text-zinc-400 font-mono text-[10px] truncate block">{entry.serial}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
