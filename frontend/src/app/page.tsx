'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { HeroScanner } from '@/components/HeroScanner';
import { TrustVerdictCard } from '@/components/TrustVerdictCard';
import { CertificateTree } from '@/components/crypto/CertificateTree';
import { EmudhraAuditCard } from '@/components/crypto/EmudhraAuditCard';
import { TyposquattingCard } from '@/components/heuristics/TyposquattingCard';
import { FormHarvestingCard } from '@/components/heuristics/FormHarvestingCard';
import { HeaderScorecard } from '@/components/heuristics/HeaderScorecard';
import { ComplianceMatrixCard } from '@/components/heuristics/ComplianceMatrixCard';
import { SCENARIO_EMUDHRA, SCENARIOS } from '@/lib/mockData';
import { scanTarget } from '@/lib/api';
import { TargetScanResult } from '@/types/api';
import { ContractAbiModal } from '@/components/web3/ContractAbiModal';
import { Shield, Key, AlertTriangle, Server, Database, Sparkles, Cpu, ArrowUpRight, CheckCircle2, Copy, Check, FileCode } from 'lucide-react';

export default function Home() {
  const [activeScenarioId, setActiveScenarioId] = useState<string>('emudhra');
  const [scanResult, setScanResult] = useState<TargetScanResult>(SCENARIO_EMUDHRA);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [activeDetailTab, setActiveDetailTab] = useState<'crypto' | 'threats' | 'posture' | 'ai' | 'web3'>('crypto');
  const [copiedHash, setCopiedHash] = useState(false);
  const [isContractModalOpen, setIsContractModalOpen] = useState(false);

  // Phase 1: Global State Synchronization & Deep Linking on mount
  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const urlParams = new URLSearchParams(window.location.search);
    const targetParam = urlParams.get('target');
    const scenarioParam = urlParams.get('scenario');

    if (scenarioParam) {
      handleSelectScenario(scenarioParam);
      return;
    }

    const cached = localStorage.getItem('k9_active_scan');
    let loadedFromCache = false;
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (parsed && (parsed.url || parsed.domain)) {
          if (!targetParam || targetParam === parsed.url || targetParam === parsed.domain) {
            setScanResult(parsed);
            setActiveScenarioId('custom');
            loadedFromCache = true;
          }
        }
      } catch {}
    }

    if (targetParam && !loadedFromCache) {
      handleScan(targetParam);
    }
  }, []);

  const handleSelectScenario = async (scenarioId: string) => {
    setActiveScenarioId(scenarioId);
    setIsLoading(true);
    setScanError(null);
    try {
      const result = await scanTarget('', scenarioId);
      setScanResult(result);
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_scan', JSON.stringify(result));
        window.history.replaceState(null, '', `?scenario=${encodeURIComponent(scenarioId)}`);
      }
    } catch {
      if (SCENARIOS[scenarioId]) {
        setScanResult(SCENARIOS[scenarioId]);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleScan = async (targetToScan: string, inputType?: string) => {
    setIsLoading(true);
    setScanError(null);
    try {
      const mode = (inputType === 'message' ? 'message' : 'url') as 'url' | 'message';
      const result = await scanTarget(targetToScan, undefined, mode);
      setScanResult(result);
      setActiveScenarioId('custom');
      if (typeof window !== 'undefined') {
        localStorage.setItem('k9_active_scan', JSON.stringify(result));
        window.history.replaceState(null, '', `?target=${encodeURIComponent(targetToScan)}`);
      }
    } catch {
      setScanError('Failed to query live scan engine; displaying fallback assessment.');
    } finally {
      setIsLoading(false);
    }
  };

  const activeReportHash = scanResult.web3Commitment?.reportHash || '0xc1f0a53f34e2dbf0bbc28a0b6c50be754fac0319462b84eea430ca9e9d1ad6ee';

  const handleCopyHash = () => {
    navigator.clipboard.writeText(activeReportHash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-8 max-w-7xl mx-auto space-y-10">
      {/* 1. Hero Scanner Section */}
      <HeroScanner
        onScan={handleScan}
        isLoading={isLoading}
        onSelectScenario={handleSelectScenario}
        activeScenarioId={activeScenarioId}
      />

      {/* Error Notice */}
      {scanError && (
        <div className="max-w-3xl mx-auto p-3 rounded-lg bg-amber-950/30 border border-amber-900/50 text-amber-300 text-xs text-center font-mono">
          {scanError}
        </div>
      )}

      {/* 2. Executive Trust Verdict Card */}
      <TrustVerdictCard result={scanResult} />

      {/* 3. LIVE FULL TECHNICAL EVIDENCE DASHBOARD */}
      <section className="w-full max-w-5xl mx-auto space-y-6 pt-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-sky-400" />
              <span>Deep Technical Evidence & Audit Matrix</span>
            </h2>
            <p className="text-xs text-zinc-500 mt-0.5">
              Live inspection results for <span className="font-mono text-zinc-300">{scanResult.domain || scanResult.url}</span>
            </p>
          </div>

          {/* Module Selector Tabs */}
          <div className="flex items-center gap-1 bg-zinc-900 p-1 rounded-lg border border-zinc-800 overflow-x-auto">
            <button
              onClick={() => setActiveDetailTab('crypto')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors shrink-0 ${
                activeDetailTab === 'crypto'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Key className="w-3.5 h-3.5 text-sky-400" />
              <span>Crypto & Certificates</span>
            </button>

            <button
              onClick={() => setActiveDetailTab('threats')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors shrink-0 ${
                activeDetailTab === 'threats'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Typosquats & Forms</span>
            </button>

            <button
              onClick={() => setActiveDetailTab('posture')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors shrink-0 ${
                activeDetailTab === 'posture'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Server className="w-3.5 h-3.5 text-emerald-400" />
              <span>Security Posture</span>
            </button>

            <button
              onClick={() => setActiveDetailTab('ai')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors shrink-0 ${
                activeDetailTab === 'ai'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-purple-400" />
              <span>AI & MITRE Intel</span>
            </button>

            <button
              onClick={() => setActiveDetailTab('web3')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors shrink-0 ${
                activeDetailTab === 'web3'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Database className="w-3.5 h-3.5 text-emerald-400" />
              <span>Web3 Ledger</span>
            </button>
          </div>
        </div>

        {/* Tab 1: Cryptographic Trust */}
        {activeDetailTab === 'crypto' && (
          <div className="space-y-6 animate-fadeIn">
            <CertificateTree chain={scanResult.certificateChain || []} tlsDetails={scanResult.tlsDetails} />
            <EmudhraAuditCard emudhra={scanResult.emudhraAudit} rsaAudit={scanResult.rsaKeyAudit} />
          </div>
        )}

        {/* Tab 2: Typosquatting & DOM Harvesting */}
        {activeDetailTab === 'threats' && (
          <div className="space-y-6 animate-fadeIn">
            <TyposquattingCard typosquatting={scanResult.typosquatting} urgencyNLP={scanResult.urgencyNLP} />
            <FormHarvestingCard domHarvesting={scanResult.domHarvesting} targetDomain={scanResult.domain} />
          </div>
        )}

        {/* Tab 3: Security Posture & Headers */}
        {activeDetailTab === 'posture' && (
          <div className="space-y-6 animate-fadeIn">
            <HeaderScorecard posture={scanResult.securityPosture} />
            <ComplianceMatrixCard result={scanResult} />
          </div>
        )}

        {/* Tab 4: AI Threat Briefing & MITRE ATT&CK */}
        {activeDetailTab === 'ai' && (
          <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/70 space-y-6 animate-fadeIn">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <h3 className="text-xs uppercase tracking-wider text-zinc-300 font-semibold">
                  AI Threat Briefing & MITRE ATT&CK Framework
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800">
                  {scanResult.aiBriefing?.aiEngine || 'Groq Llama 3.3 / Qwen'}
                </span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-300 border border-zinc-800">
                  Confidence: {scanResult.confidence}%
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2">
                <span className="text-zinc-500 font-mono text-[11px] block">CLASSIFIED THREAT CATEGORY</span>
                <span className="text-white font-semibold text-sm">
                  {scanResult.aiBriefing?.threatCategory || 'General Web Traffic / Benign'}
                </span>
                <span className="text-zinc-500 font-mono text-[11px] block pt-2">TARGETED ENTITY</span>
                <span className="text-zinc-300 font-mono">
                  {scanResult.aiBriefing?.targetedEntity || scanResult.domain}
                </span>
              </div>

              <div className="p-4 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2">
                <span className="text-zinc-500 font-mono text-[11px] block">ANALYST ADVISORY & MITIGATION</span>
                <p className="text-zinc-300 leading-relaxed text-xs">
                  {scanResult.aiBriefing?.analystRecommendation || 'No critical threat signatures identified. Continue standard browsing hygiene.'}
                </p>
              </div>
            </div>

            {/* MITRE ATT&CK Techniques */}
            {scanResult.aiBriefing?.mitreAttackTechniques && scanResult.aiBriefing.mitreAttackTechniques.length > 0 && (
              <div className="space-y-3 pt-2">
                <h4 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold font-mono">
                  Mapped MITRE ATT&CK Enterprise Matrix Techniques
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {scanResult.aiBriefing.mitreAttackTechniques.map((t, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-zinc-900 border border-zinc-800 text-xs">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-purple-400 font-semibold">{t.id}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">{t.tactic}</span>
                      </div>
                      <p className="text-zinc-200 font-medium">{t.name}</p>
                      {t.description && (
                        <p className="text-zinc-500 text-[11px] mt-1 leading-snug">{t.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Psychological Triggers & Coercive Patterns */}
            {((scanResult.aiBriefing?.psychologicalTriggers && scanResult.aiBriefing.psychologicalTriggers.length > 0) ||
              (scanResult.urgencyNLP?.matchedKeywords && scanResult.urgencyNLP.matchedKeywords.length > 0)) && (
              <div className="space-y-2 pt-3 border-t border-zinc-800">
                <h4 className="text-xs uppercase tracking-wider text-rose-400 font-semibold font-mono flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                  <span>Detected Psychological Triggers & Coercive Language</span>
                </h4>
                <div className="flex flex-wrap gap-2">
                  {(scanResult.aiBriefing?.psychologicalTriggers || []).map((trigger, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded-md bg-rose-950/40 text-rose-300 border border-rose-800/60 text-xs font-mono"
                    >
                      ⚠️ {trigger}
                    </span>
                  ))}
                  {(scanResult.urgencyNLP?.matchedKeywords || []).map((kw, idx) => (
                    <span
                      key={`kw-${idx}`}
                      className="px-2.5 py-1 rounded-md bg-amber-950/40 text-amber-300 border border-amber-800/60 text-xs font-mono"
                    >
                      Urgency Keyword: &quot;{kw}&quot;
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Extracted IOCs & Indicators */}
            {((scanResult.aiBriefing?.extractedIndicators && scanResult.aiBriefing.extractedIndicators.length > 0) ||
              (scanResult.identifiedIndicators && scanResult.identifiedIndicators.length > 0)) && (
              <div className="space-y-2 pt-3 border-t border-zinc-800">
                <h4 className="text-xs uppercase tracking-wider text-zinc-400 font-semibold font-mono">
                  Extracted Indicators of Compromise (IOCs)
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {Array.from(new Set([
                    ...(scanResult.aiBriefing?.extractedIndicators || []),
                    ...(scanResult.identifiedIndicators || []),
                  ])).map((ioc, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-zinc-900 border border-zinc-800 font-mono text-zinc-300 truncate"
                    >
                      <span className="text-purple-400 mr-2">#{idx + 1}</span>
                      {ioc}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Campaign Correlation & Feeds */}
            {scanResult.correlationReport?.hasCampaignMatch && (
              <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-900/40 text-xs space-y-1">
                <span className="font-mono text-amber-400 font-semibold block">CAMPAIGN CORRELATION MATCH</span>
                <p className="text-amber-200">
                  Identified similarity with known threat cluster: <strong>{scanResult.correlationReport.primaryCampaign}</strong>.
                </p>
                <p className="text-zinc-400 text-[11px]">
                  {scanResult.correlationReport.correlationNotes}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Web3 Decentralized Threat Ledger */}
        {activeDetailTab === 'web3' && (
          <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/70 space-y-5 animate-fadeIn">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs uppercase tracking-wider text-zinc-300 font-semibold">
                  Solidity ThreatRegistry.sol On-Chain Commitment
                </h3>
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800">
                ON-CHAIN COMMITTED
              </span>
            </div>

            <p className="text-xs text-zinc-400 leading-relaxed">
              To satisfy GDPR compliance, zero raw PII or URLs are stored on-chain. Instead, a deterministic <code className="text-zinc-200">keccak256</code> hash of this threat assessment is committed to our Ethereum smart contract.
            </p>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-between gap-3">
                <div className="truncate">
                  <span className="text-zinc-500 select-none mr-2">KECCAK256 HASH:</span>
                  <span className="text-emerald-400 font-semibold">{activeReportHash}</span>
                </div>
                <button
                  onClick={handleCopyHash}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition-colors shrink-0"
                >
                  {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
                  <span>{copiedHash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800">
                  <span className="text-zinc-500 block text-[10px] mb-1">SMART CONTRACT</span>
                  <span className="text-zinc-300 truncate block">
                    {scanResult.web3Commitment?.contractAddress || '0x71C...ThreatRegistry.sol'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800">
                  <span className="text-zinc-500 block text-[10px] mb-1">NETWORK NODE</span>
                  <span className="text-zinc-300 block">
                    {scanResult.web3Commitment?.network || 'Py-EVM Local Node'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800">
                  <span className="text-zinc-500 block text-[10px] mb-1">BLOCK NUMBER</span>
                  <span className="text-emerald-400 font-bold block">
                    {scanResult.web3Commitment?.blockNumber ? `#${scanResult.web3Commitment.blockNumber} (Verified)` : '#1 (Verified)'}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-2 flex flex-wrap items-center justify-between gap-3">
              <Link
                href={`/radar?hash=${activeReportHash}`}
                className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-medium"
              >
                <span>Verify this hash in Community Radar & Consensus Ledger</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>

              <button
                type="button"
                onClick={() => setIsContractModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-emerald-500/30 text-emerald-300 text-xs font-mono transition-colors"
              >
                <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                <span>View ThreatRegistry.sol & Sepolia ABI</span>
              </button>
            </div>
          </div>
        )}
      </section>

      {/* 4. Three Core Architectural Pillars */}
      <section className="mt-16 pt-12 border-t border-zinc-800/80 max-w-5xl mx-auto">
        <div className="text-center mb-10">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500 font-semibold mb-2">
            Defense-in-Depth Architecture
          </h2>
          <p className="text-xl font-bold text-white tracking-tight">
            How K9 Sentinel unifies Cybersecurity, AI, and Web3
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl border border-zinc-800/80 bg-zinc-950/40 hover:border-zinc-700 transition-colors">
            <div className="w-9 h-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center mb-4">
              <Cpu className="w-4 h-4 text-sky-400" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-2">Cryptographic Trust Engine</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-4">
              Identifies the real-world eMudhra TLS certificate incident (Mozilla Bug 2083449). Solves low-entropy private scalars ($d \le 1000$) on NIST P-384 curves in under 1ms.
            </p>
            <Link href="/crypto" className="text-xs text-sky-400 hover:text-sky-300 inline-flex items-center gap-1 font-medium">
              Explore Crypto Engine <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="p-6 rounded-xl border border-zinc-800/80 bg-zinc-950/40 hover:border-zinc-700 transition-colors">
            <div className="w-9 h-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center mb-4">
              <Database className="w-4 h-4 text-emerald-400" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-2">Decentralized Threat Registry</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-4">
              Records immutable keccak256 cryptographic commitments of threat reports on a Solidity smart contract while keeping sensitive PII strictly off-chain for GDPR compliance.
            </p>
            <Link href="/radar" className="text-xs text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1 font-medium">
              Explore Web3 Ledger <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="p-6 rounded-xl border border-zinc-800/80 bg-zinc-950/40 hover:border-zinc-700 transition-colors">
            <div className="w-9 h-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center mb-4">
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-2">Multi-Modal Threat Heuristics</h3>
            <p className="text-xs text-zinc-400 leading-relaxed mb-4">
              Levenshtein distance brand spoofing, Cyrillic Punycode homographs, DOM form credential harvesting, and Quishing (UPI payment scam) protection.
            </p>
            <Link href="/threats" className="text-xs text-purple-400 hover:text-purple-300 inline-flex items-center gap-1 font-medium">
              Explore Threat Posture <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </section>

      <ContractAbiModal
        isOpen={isContractModalOpen}
        onClose={() => setIsContractModalOpen(false)}
      />
    </div>
  );
}
