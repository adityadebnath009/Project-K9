'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  QrCode,
  Upload,
  Camera,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  CreditCard,
  ExternalLink,
  ArrowRight,
  Sparkles,
  Check,
  Copy,
  Info,
} from 'lucide-react';
import { scanQrCode } from '@/lib/api';
import { QrScanResult } from '@/types/api';
import { CameraScanner } from '@/components/quishing/CameraScanner';

const SAMPLE_PRESETS: { label: string; risk: string; data: QrScanResult }[] = [
  {
    label: 'Electricity Bill UPI Scam',
    risk: 'Critical Impostor',
    data: {
      target: 'upi://pay?pa=discom.billpay@fakeaxis&pn=Electricity%20Dept&am=2450.00&cu=INR&tn=Immediate%20Bill%20Overdue',
      decodedData: 'upi://pay?pa=discom.billpay@fakeaxis&pn=Electricity%20Dept&am=2450.00&cu=INR&tn=Immediate%20Bill%20Overdue',
      isUpi: true,
      upiDetails: {
        payeeVpa: 'discom.billpay@fakeaxis',
        payeeName: 'State Electricity Department (Impersonated)',
        amount: '2,450.00',
        currency: 'INR',
        transactionNote: 'Immediate Bill Overdue or Power Disconnect',
        isImpostorVpa: true,
        impersonatedEntity: 'State Electricity Board (DISCOM)',
      },
      riskScore: 94,
      verdict: 'CRITICAL THREAT',
      executiveSummary: 'Coercive UPI Quishing attack detected. Fraudulent personal VPA mimics State Electricity Board to collect fictitious overdue bill payments under threat of power disconnection.',
      quishingRisk: 'HIGH',
    },
  },
  {
    label: 'Banking KYC Phishing QR',
    risk: 'Phishing Redirect',
    data: {
      target: 'https://auth.secure-emudhra-gateway.org/login?ref=qr',
      decodedData: 'https://auth.secure-emudhra-gateway.org/login?ref=qr',
      isUpi: false,
      riskScore: 89,
      verdict: 'CRITICAL THREAT',
      executiveSummary: 'Deceptive QR code containing phishing URL. Redirects user to a rogue portal equipped with credential harvesting forms and compromised intermediate TLS certificate.',
      quishingRisk: 'HIGH',
      redirectUrl: 'https://auth.secure-emudhra-gateway.org/login?ref=qr',
    },
  },
  {
    label: 'Legitimate Merchant QR',
    risk: 'Verified Safe',
    data: {
      target: 'upi://pay?pa=starbucks.retail@hdfcbank&pn=Starbucks%20Coffee&cu=INR',
      decodedData: 'upi://pay?pa=starbucks.retail@hdfcbank&pn=Starbucks%20Coffee&cu=INR',
      isUpi: true,
      upiDetails: {
        payeeVpa: 'starbucks.retail@hdfcbank',
        payeeName: 'Starbucks Coffee Retail Pvt Ltd',
        currency: 'INR',
        transactionNote: 'In-store Point of Sale',
        isImpostorVpa: false,
      },
      riskScore: 10,
      verdict: 'VERIFIED SAFE',
      executiveSummary: 'Standard verified merchant UPI VPA registered under verified institutional banking gateway. No fraudulent redirection or impersonation detected.',
      quishingRisk: 'LOW',
    },
  },
];

export default function QuishingPage() {
  const [selectedResult, setSelectedResult] = useState<QrScanResult>(SAMPLE_PRESETS[0].data);
  const [activePresetIndex, setActivePresetIndex] = useState<number>(0);
  const [inputMode, setInputMode] = useState<'upload' | 'camera'>('upload');
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [copied, setCopied] = useState(false);
  const [textInput, setTextInput] = useState('');

  const handleCameraCapture = async (dataUrl: string) => {
    setIsScanning(true);
    try {
      const res = await scanQrCode(dataUrl);
      setSelectedResult(res);
      setActivePresetIndex(-1);
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_qr', JSON.stringify(res));
        if (res.target) {
          window.history.replaceState(null, '', `?target=${encodeURIComponent(res.target)}`);
        }
      }
    } catch (err) {
      console.warn('Camera frame scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  // Phase 1: Global State Synchronization & Deep Linking
  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const urlParams = new URLSearchParams(window.location.search);
    const targetParam = urlParams.get('target');

    // 1. Check if matching preset exists
    if (targetParam) {
      const matchedIdx = SAMPLE_PRESETS.findIndex((p) => p.data.target === targetParam || p.data.decodedData === targetParam);
      if (matchedIdx !== -1) {
        setSelectedResult(SAMPLE_PRESETS[matchedIdx].data);
        setActivePresetIndex(matchedIdx);
        return;
      }
    }

    // 2. Check local storage for active QR scan
    const cachedQr = localStorage.getItem('k9_active_qr');
    if (cachedQr) {
      try {
        const parsed = JSON.parse(cachedQr);
        if (parsed && (parsed.target || parsed.decodedData)) {
          if (!targetParam || targetParam === parsed.target || targetParam === parsed.decodedData) {
            setSelectedResult(parsed);
            setActivePresetIndex(-1);
            return;
          }
        }
      } catch {}
    }

    // 3. Check active scan from other modules if it's UPI or QR
    const cachedScan = localStorage.getItem('k9_active_scan');
    if (cachedScan) {
      try {
        const parsed = JSON.parse(cachedScan);
        if (parsed.qrInspection || parsed.url?.startsWith('upi://') || parsed.domain?.startsWith('upi://')) {
          const upiTarget = parsed.url || parsed.domain;
          const upiResult: QrScanResult = {
            target: upiTarget,
            decodedData: upiTarget,
            isUpi: true,
            upiDetails: parsed.qrInspection?.upi_details ? {
              payeeVpa: parsed.qrInspection.upi_details.payee_vpa,
              payeeName: parsed.qrInspection.upi_details.payee_name,
              amount: parsed.qrInspection.upi_details.amount,
              currency: parsed.qrInspection.upi_details.currency,
              transactionNote: parsed.qrInspection.upi_details.transaction_note,
              isImpostorVpa: parsed.qrInspection.threat_score > 50,
              impersonatedEntity: parsed.qrInspection.upi_details.impersonated_brand,
            } : undefined,
            riskScore: parsed.threatScore || parsed.qrInspection?.threat_score || 85,
            verdict: parsed.verdict || 'CRITICAL THREAT',
            executiveSummary: parsed.summary || parsed.qrInspection?.summary || 'UPI payment risk detected.',
            quishingRisk: 'HIGH',
          };
          setSelectedResult(upiResult);
          setActivePresetIndex(-1);
        }
      } catch {}
    }
  }, []);

  const handleFileUpload = async (file: File) => {
    setIsScanning(true);
    try {
      const res = await scanQrCode(file);
      setSelectedResult(res);
      setActivePresetIndex(-1);
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_qr', JSON.stringify(res));
        if (res.target) {
          window.history.replaceState(null, '', `?target=${encodeURIComponent(res.target)}`);
        }
      }
    } catch {
      // Fallback
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectPreset = (index: number) => {
    setActivePresetIndex(index);
    const preset = SAMPLE_PRESETS[index];
    if (preset) {
      setSelectedResult(preset.data);
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_qr', JSON.stringify(preset.data));
        window.history.replaceState(null, '', `?target=${encodeURIComponent(preset.data.target)}`);
      }
    }
  };

  const handleCopyPayload = () => {
    navigator.clipboard.writeText(selectedResult.decodedData);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isMalicious = selectedResult.verdict === 'CRITICAL THREAT' || selectedResult.riskScore >= 75;
  const isSuspicious = selectedResult.verdict === 'SUSPICIOUS' || (selectedResult.riskScore >= 30 && selectedResult.riskScore < 75);

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* 1. Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-zinc-800/80">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-400">
              <QrCode className="w-3.5 h-3.5 text-sky-400" />
              <span>Module 05 · Anti-Quishing & Payment Shield</span>
            </span>
            <span className="text-zinc-600">/</span>
            <span className="text-xs text-zinc-400">Offline & Online Decoder</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            QR Scam & Deceptive UPI Payment Guard
          </h1>
          <p className="text-sm text-zinc-400 max-w-2xl mt-1 leading-relaxed">
            Inspect physical or digital QR codes without pointing your personal camera. Detects disguised redirect links and fake utility merchant VPAs.
          </p>
        </div>

        <Link
          href="/"
          className="inline-flex items-center gap-1 text-xs text-zinc-400 hover:text-zinc-200 self-start md:self-auto px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 transition-colors"
        >
          <span>Return to Scanner</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* 2. Dual-Mode Scanner & Preset Selectors */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Dual-Mode Scanner Viewport */}
        <div className="lg:col-span-2 space-y-3">
          {/* Mode Switcher Pill */}
          <div className="flex items-center gap-1.5 bg-zinc-900/70 p-1 rounded-xl border border-zinc-800 w-fit">
            <button
              type="button"
              onClick={() => setInputMode('upload')}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                inputMode === 'upload'
                  ? 'bg-zinc-850 text-white shadow-sm border border-zinc-700'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Upload className="w-3.5 h-3.5 text-sky-400" />
              <span>Image Upload / Dropzone</span>
            </button>

            <button
              type="button"
              onClick={() => setInputMode('camera')}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                inputMode === 'camera'
                  ? 'bg-sky-500 text-zinc-950 shadow-md shadow-sky-950/40'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Camera className="w-3.5 h-3.5" />
              <span>Scan with Camera (Live Webcam / Mobile)</span>
            </button>
          </div>

          {/* Conditional Viewport: Camera Stream vs Image Dropzone */}
          {inputMode === 'camera' ? (
            <CameraScanner onCapture={handleCameraCapture} isScanning={isScanning} />
          ) : (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                const file = e.dataTransfer.files?.[0];
                if (file) handleFileUpload(file);
              }}
              className={`border-2 border-dashed rounded-xl p-8 text-center transition-all flex flex-col items-center justify-center min-h-[260px] ${
                isDragging
                  ? 'border-sky-500 bg-sky-950/10'
                  : 'border-zinc-800 bg-zinc-950/40 hover:border-zinc-700'
              }`}
            >
              <div className="w-12 h-12 rounded-xl bg-zinc-900 border border-zinc-800 flex items-center justify-center mb-4">
                {isScanning ? (
                  <div className="animate-spin rounded-full h-5 w-5 border-2 border-sky-400 border-t-transparent" />
                ) : (
                  <Upload className="w-5 h-5 text-sky-400" />
                )}
              </div>

              <p className="text-sm font-semibold text-white mb-1">
                Drag and drop QR code image file
              </p>
              <p className="text-xs text-zinc-500 max-w-sm mb-4">
                Supports PNG, JPG, WEBP screenshots or photos of physical flyers. Image processed securely.
              </p>

              <label className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-900 hover:bg-zinc-850 border border-zinc-700 text-xs font-medium text-zinc-200 transition-colors">
                <span>Choose Image File</span>
                <input
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleFileUpload(file);
                  }}
                />
              </label>
            </div>
          )}
        </div>

        {/* Preset Samples */}
        <div className="p-5 rounded-xl border border-zinc-800 bg-zinc-950/40 flex flex-col justify-between">
          <div>
            <h3 className="text-xs uppercase tracking-wider text-zinc-500 font-semibold mb-3 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
              <span>Verifiable Test Scenarios</span>
            </h3>
            <p className="text-xs text-zinc-400 mb-4 leading-relaxed">
              Test how the threat engine unmasks different categories of malicious QR codes.
            </p>

            <div className="space-y-2">
              {SAMPLE_PRESETS.map((preset, index) => (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => handleSelectPreset(index)}
                  className={`w-full text-left p-3 rounded-lg border text-xs transition-all flex items-center justify-between ${
                    activePresetIndex === index
                      ? 'border-sky-500/50 bg-sky-950/20 text-white'
                      : 'border-zinc-800/80 bg-zinc-900/50 hover:bg-zinc-900 text-zinc-300'
                  }`}
                >
                  <div className="font-medium truncate pr-2">{preset.label}</div>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                    preset.risk.includes('Critical')
                      ? 'bg-rose-950/60 text-rose-300 border border-rose-900/40'
                      : preset.risk.includes('Phishing')
                      ? 'bg-amber-950/60 text-amber-300 border border-amber-900/40'
                      : 'bg-emerald-950/60 text-emerald-300 border border-emerald-900/40'
                  }`}>
                    {preset.risk}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-zinc-800/80 text-[11px] text-zinc-500 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-zinc-400" />
            <span>Complies with NPCI UPI 2.0 payment specs</span>
          </div>
        </div>
      </div>

      {/* 3. Analysis Verdict Banner */}
      <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/70">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold tracking-wide border ${
              isMalicious
                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                : isSuspicious
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
            }`}>
              {isMalicious ? (
                <ShieldAlert className="w-4 h-4 text-rose-400" />
              ) : isSuspicious ? (
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              )}
              <span>{selectedResult.verdict}</span>
            </span>

            <span className="text-xs font-mono text-zinc-400 truncate max-w-sm sm:max-w-md">
              {selectedResult.isUpi ? 'UPI Payment QR' : 'URL Redirect QR'}
            </span>
          </div>

          <div className="flex items-baseline gap-2">
            <span className="text-xs uppercase tracking-wider text-zinc-500 font-medium">Risk Score:</span>
            <span className={`text-2xl font-bold font-mono ${
              isMalicious ? 'text-rose-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {selectedResult.riskScore}
            </span>
            <span className="text-xs text-zinc-600 font-mono">/ 100</span>
          </div>
        </div>

        <div className="py-4">
          <p className="text-sm text-zinc-200 leading-relaxed max-w-3xl">
            {selectedResult.executiveSummary}
          </p>
        </div>

        {/* Decoded Raw Payload with Copy */}
        <div className="mt-2 p-3 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-between gap-3">
          <div className="font-mono text-xs text-zinc-300 truncate">
            <span className="text-zinc-500 select-none mr-2">PAYLOAD:</span>
            <span>{selectedResult.decodedData}</span>
          </div>
          <button
            type="button"
            onClick={handleCopyPayload}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-mono transition-colors shrink-0"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* 4. Deep Evidence Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* UPI Details or URL Destination */}
        {selectedResult.isUpi && selectedResult.upiDetails ? (
          <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/40 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center gap-2">
                <CreditCard className="w-4 h-4 text-sky-400" />
                <h3 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold">
                  Parsed NPCI UPI Payload
                </h3>
              </div>
              {selectedResult.upiDetails.isImpostorVpa && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/60 border border-rose-900/40 text-rose-300">
                  IMPOSTOR VPA
                </span>
              )}
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-zinc-500 block mb-0.5">Payee Virtual Address (pa):</span>
                <span className="font-mono text-white bg-zinc-900 px-2 py-1 rounded border border-zinc-800 block truncate">
                  {selectedResult.upiDetails.payeeVpa}
                </span>
              </div>

              <div>
                <span className="text-zinc-500 block mb-0.5">Payee Registered Name (pn):</span>
                <span className="text-zinc-200 font-medium block">
                  {selectedResult.upiDetails.payeeName}
                </span>
              </div>

              {selectedResult.upiDetails.amount && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-zinc-500 block mb-0.5">Pre-filled Amount (am):</span>
                    <span className="font-mono text-zinc-100 font-semibold">
                      ₹{selectedResult.upiDetails.amount}
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500 block mb-0.5">Currency (cu):</span>
                    <span className="font-mono text-zinc-400">
                      {selectedResult.upiDetails.currency || 'INR'}
                    </span>
                  </div>
                </div>
              )}

              {selectedResult.upiDetails.transactionNote && (
                <div>
                  <span className="text-zinc-500 block mb-0.5">Transaction Note (tn):</span>
                  <span className="text-zinc-300 bg-zinc-900/60 p-2 rounded border border-zinc-800/80 block italic">
                    &quot;{selectedResult.upiDetails.transactionNote}&quot;
                  </span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/40 space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-zinc-800">
              <ExternalLink className="w-4 h-4 text-sky-400" />
              <h3 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold">
                Destination URL Audit
              </h3>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-zinc-500 block mb-0.5">Embedded Link:</span>
                <span className="font-mono text-white bg-zinc-900 px-2 py-1 rounded border border-zinc-800 block truncate">
                  {selectedResult.redirectUrl}
                </span>
              </div>

              <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 text-zinc-300 leading-relaxed">
                <span className="font-semibold block mb-1 text-white">Quishing Redirection Risk:</span>
                When scanned by a mobile device, this QR forces the operating system to launch a browser directly to an external host, bypassing email spam filters and network boundary blocks.
              </div>

              {selectedResult.redirectUrl && (
                <Link
                  href={`/threats`}
                  className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-medium pt-2"
                >
                  <span>Inspect host typosquatting & forms</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              )}
            </div>
          </div>
        )}

        {/* Protection Advisory Protocol */}
        <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/40 space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-zinc-800">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h3 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold">
              Actionable Defense Protocol
            </h3>
          </div>

          <div className="space-y-3 text-xs text-zinc-300">
            <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800">
              <span className="font-semibold text-white block mb-1">
                1. Never Enter PIN to &quot;Receive&quot; Money
              </span>
              <span>
                UPI PIN is strictly required only to send money from your account. Legitimate utility refunds or government credits never require entering a PIN.
              </span>
            </div>

            <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800">
              <span className="font-semibold text-white block mb-1">
                2. Verify Merchant VPA Suffix
              </span>
              <span>
                Official utilities use registered corporate handles (e.g., <code className="text-sky-300 font-mono">@sbipay</code>, <code className="text-sky-300 font-mono">@icici</code> with verified merchant tier). Scammers use generic handles like <code className="text-rose-300 font-mono">@okaxis</code> or <code className="text-rose-300 font-mono">@ybl</code>.
              </span>
            </div>

            <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800">
              <span className="font-semibold text-white block mb-1">
                3. Physical Sticker Overlay Inspection
              </span>
              <span>
                Always feel the physical surface of store payment displays to ensure a malicious counterfeit QR sticker has not been pasted over the genuine merchant code.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
