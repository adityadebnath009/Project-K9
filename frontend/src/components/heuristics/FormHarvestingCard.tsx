'use client';

import React from 'react';
import { FormInput, Key, CreditCard, Send, AlertTriangle, ShieldCheck, ArrowRight } from 'lucide-react';
import { DOMHarvestingAudit } from '@/types/api';

interface FormHarvestingCardProps {
  domHarvesting: DOMHarvestingAudit;
  targetDomain: string;
}

export const FormHarvestingCard: React.FC<FormHarvestingCardProps> = ({
  domHarvesting,
  targetDomain,
}) => {
  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <div className="flex items-center gap-2">
          <FormInput className="w-4 h-4 text-rose-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            DOM Credential Harvesting & Form Action Audit
          </h3>
        </div>

        {domHarvesting.isCrossOriginExfiltration ? (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 font-mono text-xs font-bold animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>CROSS-ORIGIN EXFILTRATION</span>
          </span>
        ) : (
          <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-emerald-950/40 border border-emerald-800 text-emerald-300 font-mono text-xs font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>SAFE FORM ROUTING</span>
          </span>
        )}
      </div>

      {/* Inputs Detected Badges */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
        <div className="p-3 rounded-md bg-ground border border-border-subtle flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-amber-400" />
            <span className="text-zinc-300">Password Inputs:</span>
          </div>
          <span
            className={`font-bold px-2 py-0.5 rounded border ${
              domHarvesting.passwordFieldsDetected > 0
                ? 'bg-rose-950 text-rose-300 border-rose-800'
                : 'bg-zinc-900 text-zinc-400 border-zinc-800'
            }`}
          >
            {domHarvesting.passwordFieldsDetected} DETECTED
          </span>
        </div>

        <div className="p-3 rounded-md bg-ground border border-border-subtle flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CreditCard className="w-4 h-4 text-rose-400" />
            <span className="text-zinc-300">Payment / Card Fields:</span>
          </div>
          <span
            className={`font-bold px-2 py-0.5 rounded border ${
              domHarvesting.cardFieldsDetected > 0
                ? 'bg-rose-950 text-rose-300 border-rose-800'
                : 'bg-zinc-900 text-zinc-400 border-zinc-800'
            }`}
          >
            {domHarvesting.cardFieldsDetected} DETECTED
          </span>
        </div>
      </div>

      {/* Form Action Routing Inspection */}
      <div className="p-3.5 rounded-md bg-ground border border-border-subtle space-y-2 font-mono text-xs">
        <div className="flex items-center justify-between text-[11px] text-zinc-500">
          <span>EXFILTRATION ROUTING PATH:</span>
          <span
            className={
              domHarvesting.isCrossOriginExfiltration ? 'text-rose-400 font-bold' : 'text-emerald-400'
            }
          >
            {domHarvesting.isCrossOriginExfiltration ? 'MALICIOUS POST TARGET' : 'SAME ORIGIN'}
          </span>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-2 p-2.5 rounded bg-black/60 border border-zinc-800">
          <div className="flex-1 truncate">
            <span className="text-[10px] text-zinc-500 block">SOURCE ORIGIN:</span>
            <span className="text-zinc-300 font-semibold">{targetDomain}</span>
          </div>
          <div className="text-zinc-600 sm:px-1">
            <ArrowRight className="w-4 h-4 text-zinc-500" />
          </div>
          <div className="flex-1 truncate">
            <span className="text-[10px] text-zinc-500 block">ACTION POST URL:</span>
            <span
              className={`font-semibold ${
                domHarvesting.isCrossOriginExfiltration ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {domHarvesting.formActionUrl || 'None (No active form submits)'}
            </span>
          </div>
        </div>

        {domHarvesting.destinationDomain && (
          <div className="text-[11px] text-zinc-400 pt-1">
            Destination Sink: <span className="text-zinc-200 font-bold">{domHarvesting.destinationDomain}</span>
          </div>
        )}
      </div>

      {/* Flagged Field Names */}
      {domHarvesting.flaggedInputNames.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap font-mono text-xs">
          <span className="text-zinc-500 text-[11px]">FLAGGED INPUT NAMES:</span>
          {domHarvesting.flaggedInputNames.map((name, i) => (
            <span
              key={i}
              className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 text-[11px]"
            >
              {name}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};
