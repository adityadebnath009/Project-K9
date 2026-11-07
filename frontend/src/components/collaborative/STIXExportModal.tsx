'use client';

import React, { useState } from 'react';
import { X, Copy, Check, Download, FileCode } from 'lucide-react';

interface STIXExportModalProps {
  bundle: Record<string, unknown> | null;
  isOpen: boolean;
  onClose: () => void;
}

export const STIXExportModal: React.FC<STIXExportModalProps> = ({ bundle, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !bundle) return null;

  const jsonString = JSON.stringify(bundle, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `k9-sentinel-stix2.1-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-3xl bg-surface border border-border-active rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="bento-card-header bg-surface-elevated">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-emerald-400" />
            <h3 className="font-mono text-sm font-semibold text-zinc-100">
              STIX 2.1 Threat Intelligence Bundle Inspector
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-100 p-1 rounded hover:bg-zinc-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 overflow-y-auto space-y-3 flex-1 font-mono text-xs">
          <div className="flex items-center justify-between text-zinc-400 text-[11px]">
            <span>Format: OASIS STIX 2.1 Standard Specification</span>
            <span>SIEM / SOAR / MISP Compliant</span>
          </div>

          <pre className="p-4 rounded-md bg-black/80 border border-zinc-800 text-emerald-400 font-mono text-[11px] overflow-x-auto max-h-[500px]">
            {jsonString}
          </pre>
        </div>

        {/* Footer actions */}
        <div className="p-3 bg-surface-elevated border-t border-border-subtle flex items-center justify-between">
          <span className="text-[11px] font-mono text-zinc-500">
            Cryptographic SHA-256 signatures attached
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 font-mono text-xs active:scale-[0.98] transition-all"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy JSON</span>
                </>
              )}
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold active:scale-[0.98] transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .json</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
