'use client';

import React from 'react';
import { Shield, CheckCircle2, AlertTriangle, XCircle, FileWarning, ExternalLink } from 'lucide-react';
import { SecurityPostureAudit } from '@/types/api';

interface HeaderScorecardProps {
  posture: SecurityPostureAudit;
}

export const HeaderScorecard: React.FC<HeaderScorecardProps> = ({ posture }) => {
  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'text-emerald-400 bg-emerald-950/40 border-emerald-800';
      case 'B':
        return 'text-sky-400 bg-sky-950/40 border-sky-800';
      case 'C':
        return 'text-amber-400 bg-amber-950/40 border-amber-800';
      case 'D':
      case 'F':
      default:
        return 'text-rose-400 bg-rose-950/40 border-rose-800';
    }
  };

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header & Grade Badge */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-sky-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Web Posture & Headers
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-zinc-500">OBSERVATORY GRADE:</span>
          <span
            className={`font-mono text-base font-extrabold px-2.5 py-0.5 rounded border ${getGradeColor(
              posture.overallGrade
            )}`}
          >
            {posture.overallGrade}
          </span>
        </div>
      </div>

      {/* Security Headers Checklist */}
      <div className="space-y-2 font-mono text-xs">
        <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">
          Critical Security Headers:
        </span>

        <div className="space-y-1.5">
          {posture.headers.map((header) => {
            const isPresent = header.status === 'present';
            const isWarn = header.status === 'warning';

            return (
              <div
                key={header.name}
                className="p-2 rounded bg-ground/80 border border-border-subtle flex items-center justify-between gap-2"
              >
                <div className="flex items-center gap-2 truncate">
                  {isPresent ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : isWarn ? (
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                  )}
                  <span className="text-zinc-200 truncate">{header.name}</span>
                </div>

                <div className="text-[10px] shrink-0">
                  {isPresent ? (
                    <span className="text-emerald-400">PRESENT</span>
                  ) : isWarn ? (
                    <span className="text-amber-400">PARTIAL</span>
                  ) : (
                    <span className="text-rose-400">MISSING</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Exposed Sensitive Files Probe */}
      <div className="space-y-2 pt-2 border-t border-border-subtle font-mono text-xs">
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
            <FileWarning className="w-3 h-3 text-zinc-400" />
            <span>Exposed Sensitive Files Probe:</span>
          </span>
          <span className="text-[10px] text-zinc-500">HEAD & GET requests</span>
        </div>

        <div className="grid grid-cols-2 gap-2">
          {posture.sensitiveFilesProbe.map((probe) => {
            const isExposed = probe.status === 'EXPOSED';

            return (
              <div
                key={probe.path}
                className={`p-2 rounded border flex flex-col justify-between ${
                  isExposed
                    ? 'bg-rose-950/30 border-rose-800 text-rose-300'
                    : 'bg-ground/70 border-border-subtle text-zinc-400'
                }`}
              >
                <div className="truncate font-semibold text-[11px]">{probe.path}</div>
                <div className="flex items-center justify-between pt-1 text-[10px]">
                  <span>HTTP {probe.httpCode}</span>
                  <span className={`font-bold ${isExposed ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {probe.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
