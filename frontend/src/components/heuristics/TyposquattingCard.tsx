'use client';

import React from 'react';
import { Type, AlertTriangle, ShieldCheck, Globe, Calendar, MessageSquareWarning } from 'lucide-react';
import { TyposquattingAudit, UrgencyNLPAudit } from '@/types/api';

interface TyposquattingCardProps {
  typosquatting: TyposquattingAudit;
  urgencyNLP: UrgencyNLPAudit;
}

export const TyposquattingCard: React.FC<TyposquattingCardProps> = ({
  typosquatting,
  urgencyNLP,
}) => {
  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <Type className="w-4 h-4 text-amber-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Typosquatting, Homoglyphs & Urgency NLP
          </h3>
        </div>

        {typosquatting.isImpersonation ? (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 font-mono text-xs font-bold">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>BRAND IMPERSONATION</span>
          </span>
        ) : (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-emerald-950/40 border border-emerald-800 text-emerald-300 font-mono text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>ORIGINAL DOMAIN</span>
          </span>
        )}
      </div>

      {/* Side-by-Side Domain Comparison */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* Target Domain */}
        <div className="p-3.5 rounded-md bg-ground border border-border-subtle space-y-1.5 font-mono text-xs">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">
            Target Analyzed Host:
          </span>
          <div className="text-sm font-bold text-zinc-100 flex items-center gap-2 break-all">
            <span className={typosquatting.isImpersonation ? 'text-rose-400' : 'text-zinc-100'}>
              {typosquatting.targetDomain}
            </span>
          </div>
          <div className="flex items-center gap-2 pt-1 text-[11px] text-zinc-400">
            <Globe className="w-3 h-3 text-zinc-500" />
            <span>{typosquatting.registrar}</span>
          </div>
        </div>

        {/* Legitimate Brand Target */}
        <div className="p-3.5 rounded-md bg-ground border border-border-subtle space-y-1.5 font-mono text-xs">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">
            Legitimate Target Brand:
          </span>
          <div className="text-sm font-bold text-emerald-400 flex items-center gap-2 break-all">
            <span>{typosquatting.targetedBrand}</span>
            <span className="text-zinc-500 text-xs font-normal">
              ({typosquatting.legitimateDomain})
            </span>
          </div>
          <div className="flex items-center gap-2 pt-1 text-[11px] text-zinc-400">
            <Calendar className="w-3 h-3 text-zinc-500" />
            <span>Domain Age: {typosquatting.domainAgeDays} days</span>
          </div>
        </div>
      </div>

      {/* Heuristic Metrics & Homograph Flag */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
        <div className="p-2.5 rounded bg-black/50 border border-zinc-800">
          <span className="text-zinc-500 text-[10px] block">LEVENSHTEIN DISTANCE:</span>
          <span className="text-sm font-bold text-zinc-200">
            Distance: {typosquatting.levenshteinDistance}
          </span>
        </div>

        <div className="p-2.5 rounded bg-black/50 border border-zinc-800">
          <span className="text-zinc-500 text-[10px] block">PUNYCODE HOMOGLYPH:</span>
          <span
            className={`text-sm font-bold ${
              typosquatting.punycodeHomoglyph ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {typosquatting.punycodeHomoglyph ? 'FLAGGED (Active)' : 'NONE DETECTED'}
          </span>
        </div>

        <div className="p-2.5 rounded bg-black/50 border border-zinc-800">
          <span className="text-zinc-500 text-[10px] block">RISK LEVEL:</span>
          <span
            className={`text-sm font-bold uppercase ${
              typosquatting.riskLevel === 'critical'
                ? 'text-rose-400'
                : typosquatting.riskLevel === 'high'
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {typosquatting.riskLevel}
          </span>
        </div>
      </div>

      {/* Homoglyph breakdown if present */}
      {typosquatting.homoglyphBreakdown && (
        <div className="p-2.5 rounded bg-rose-950/20 border border-rose-900/50 font-mono text-xs text-rose-300">
          <span className="font-bold">HOMOGLYPH BREAKDOWN: </span>
          <span>{typosquatting.homoglyphBreakdown}</span>
        </div>
      )}

      {/* Deceptive Urgency NLP Heuristics */}
      <div className="p-3.5 rounded-md bg-ground border border-border-subtle space-y-2 font-mono text-xs">
        <div className="flex items-center justify-between">
          <span className="text-zinc-200 font-bold flex items-center gap-1.5">
            <MessageSquareWarning className="w-3.5 h-3.5 text-amber-400" />
            <span>Deceptive Urgency NLP Heuristics</span>
          </span>
          <span className="text-[11px] text-zinc-400">
            Urgency Score: <span className="text-amber-400 font-bold">{urgencyNLP.urgencyScore}/100</span>
          </span>
        </div>

        {urgencyNLP.detected ? (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1.5 pt-1">
              {urgencyNLP.matchedKeywords.map((kw, i) => (
                <span
                  key={i}
                  className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 text-[11px]"
                >
                  &quot;{kw}&quot;
                </span>
              ))}
            </div>

            {urgencyNLP.extractedSnippets.map((snippet, idx) => (
              <p
                key={idx}
                className="text-[11px] font-sans italic text-zinc-400 bg-black/40 p-2 rounded border border-zinc-900"
              >
                {snippet}
              </p>
            ))}
          </div>
        ) : (
          <p className="text-[11px] font-sans text-zinc-500">
            No high-pressure phishing patterns, psychological coercion, or account suspension threats identified in page content.
          </p>
        )}
      </div>
    </div>
  );
};
