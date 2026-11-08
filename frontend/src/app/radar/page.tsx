'use client';

import React, { useState, useEffect } from 'react';
import { Radio, Users, CheckCircle, ThumbsUp, ThumbsDown, ShieldAlert, FileCode, Clock, ShieldCheck, Database, Search, Sparkles, Plus, X, Send, Loader2 } from 'lucide-react';
import { fetchRadarIncidents, generateSTIXBundle, API_BASE_URL, verifyWeb3Report, reportRadarIncident } from '@/lib/api';
import { STIXExportModal } from '@/components/collaborative/STIXExportModal';
import { ContractAbiModal } from '@/components/web3/ContractAbiModal';
import { RadarIncident } from '@/types/api';

export default function RadarPage() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [latestCommitments, setLatestCommitments] = useState<any[]>([]);
  const [filter, setFilter] = useState('ALL');
  const [isContractModalOpen, setIsContractModalOpen] = useState(false);
  const [userVotes, setUserVotes] = useState<Record<string, 'fake' | 'legit'>>({});
  const [verifyHashInput, setVerifyHashInput] = useState('');
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // Report Modal State
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [newTarget, setNewTarget] = useState('');
  const [newCategory, setNewCategory] = useState('Brand Phishing');
  const [newExperience, setNewExperience] = useState('');
  const [newVictimStatus, setNewVictimStatus] = useState('Blocked in Time');
  const [newReporter, setNewReporter] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // STIX modal
  const [stixOpen, setStixOpen] = useState(false);
  const [activeBundle, setActiveBundle] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    // 1. Fetch community incidents
    fetch(`${API_BASE_URL}/api/v1/incidents`)
      .then((res) => {
        if (res.ok) return res.json();
        throw new Error('Offline fallback');
      })
      .then(setIncidents)
      .catch(() => {
        // Fallback to local incidents
        setIncidents([
          {
            id: 'inc-001',
            target: 'https://auth.secure-emudhra-gateway.org',
            domain: 'auth.secure-emudhra-gateway.org',
            category: 'eMudhra Flawed CA',
            reporter: 'cryptographer-certin@k9-sentinel',
            timestamp: '2 mins ago',
            user_experience: 'Alerted during digital signature renewal. Intermediate TLS cert uses weak scalar d=4 on NIST P-384, cracked in <1ms via Wayne discrete log.',
            victim_status: 'Blocked in Time',
            fake_votes: 54,
            legit_votes: 1,
            consensus_status: 'Consensus: Confirmed Fake (98%)',
            countdown_hours_remaining: 16,
          },
          {
            id: 'inc-002',
            target: 'https://paypa1-security-check.com/login',
            domain: 'paypa1-security-check.com',
            category: 'Brand Typosquatting & Harvesting',
            reporter: 'soc-analyst-99@dfir-network.org',
            timestamp: '14 mins ago',
            user_experience: 'Received phishing email claiming unauthorized $499 purchase. Login form submitted password to external drop server evil-exfiltrator.net.',
            victim_status: 'Credentials Entered',
            fake_votes: 98,
            legit_votes: 2,
            consensus_status: 'Consensus: Confirmed Fake (98%)',
            countdown_hours_remaining: 8,
          },
          {
            id: 'inc-003',
            target: 'upi://pay?pa=bescom.electricity.bill@okhdfcbank&pn=StateElectricityDiscom&am=4800&cu=INR',
            domain: 'okhdfcbank',
            category: 'Utility Quishing Scam',
            reporter: 'rahul.k@consumer-forum.in',
            timestamp: '32 mins ago',
            user_experience: 'Pasted on power bill disconnection notice stuck to apartment gate. Malicious QR code demands immediate INR 4,800 transfer to individual VPA.',
            victim_status: 'Financial Loss Attempted',
            fake_votes: 67,
            legit_votes: 0,
            consensus_status: 'Consensus: Confirmed Fake (100%)',
            countdown_hours_remaining: 12,
          },
        ]);
      });

    // 2. Fetch live Web3 on-chain commitments
    fetch(`${API_BASE_URL}/api/v1/web3/latest`)
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => {
        if (Array.isArray(data)) setLatestCommitments(data.slice(0, 5));
      })
      .catch(() => {});

    // 3. Auto-populate hash from URL query param or active scan in localStorage
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      const urlHash = urlParams.get('hash');
      if (urlHash) {
        setVerifyHashInput(urlHash);
        setIsVerifying(true);
        verifyWeb3Report(urlHash)
          .then((res) => setVerifyResult(res))
          .catch(() => setVerifyResult({ is_valid: false, error: 'Web3 verification node unreachable.' }))
          .finally(() => setIsVerifying(false));
      } else {
        const cached = localStorage.getItem('k9_active_scan');
        if (cached) {
          try {
            const parsed = JSON.parse(cached);
            if (parsed.web3Commitment?.reportHash) {
              setVerifyHashInput(parsed.web3Commitment.reportHash);
            }
          } catch {}
        }
      }
    }
  }, []);

  const handleVote = async (incidentId: string, voteType: 'fake' | 'legit') => {
    if (userVotes[incidentId] === voteType) return;

    // Optimistically update UI
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id !== incidentId) return inc;
        const previousVote = userVotes[incidentId];
        let newFake = inc.fake_votes;
        let newLegit = inc.legit_votes;

        if (voteType === 'fake') {
          newFake += 1;
          if (previousVote === 'legit') newLegit -= 1;
        } else {
          newLegit += 1;
          if (previousVote === 'fake') newFake -= 1;
        }

        return { ...inc, fake_votes: newFake, legit_votes: newLegit };
      })
    );

    setUserVotes((prev) => ({ ...prev, [incidentId]: voteType }));

    try {
      await fetch(`${API_BASE_URL}/api/v1/incidents/${incidentId}/vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vote: voteType }),
      });
    } catch {
      // offline silent pass
    }
  };

  const handleVerifyOnChain = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanHash = verifyHashInput.trim();
    if (!cleanHash) return;
    setIsVerifying(true);
    setVerifyResult(null);

    if (typeof window !== 'undefined') {
      window.history.replaceState(null, '', `?hash=${encodeURIComponent(cleanHash)}`);
    }

    try {
      const res = await verifyWeb3Report(cleanHash);
      setVerifyResult(res);
    } catch {
      setVerifyResult({
        is_valid: false,
        error: 'Web3 verification node unreachable.',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim() || !newExperience.trim()) return;
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const created = await reportRadarIncident({
        target: newTarget.trim(),
        category: newCategory,
        user_experience: newExperience.trim(),
        victim_status: newVictimStatus,
        reporter: newReporter.trim() || 'Anonymous Reporter',
      });
      setIncidents((prev) => [created, ...prev]);
      setIsReportOpen(false);
      setNewTarget('');
      setNewExperience('');
      setNewReporter('');
    } catch (err: any) {
      setSubmitError(err?.message || 'Failed to submit incident report.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const categories = [
    'ALL',
    'eMudhra Flawed CA',
    'Brand Phishing',
    'Utility Quishing Scam',
    'Insecure Config',
    'Credential Harvest',
  ];

  const filteredIncidents = filter === 'ALL'
    ? incidents
    : incidents.filter((inc) => {
        const cat = (inc.category || '').toLowerCase();
        const target = (inc.target || '').toLowerCase();
        if (filter === 'eMudhra Flawed CA') return cat.includes('emudhra') || target.includes('emudhra');
        if (filter === 'Brand Phishing') return cat.includes('phish') || cat.includes('typosquat') || target.includes('paypa1') || target.includes('sbi');
        if (filter === 'Utility Quishing Scam') return cat.includes('quish') || cat.includes('util') || target.includes('upi://');
        if (filter === 'Insecure Config') return cat.includes('config') || cat.includes('header');
        if (filter === 'Credential Harvest') return cat.includes('harvest') || cat.includes('credential');
        return cat.includes(filter.toLowerCase());
      });

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-zinc-800">
        <div>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-[11px] font-medium text-emerald-400 mb-2">
            <Database className="w-3.5 h-3.5" />
            <span>Web3 Decentralized Registry & Collaborative Radar</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Community Consensus Radar & On-Chain Integrity
          </h1>
          <p className="text-zinc-400 text-xs sm:text-sm mt-1 max-w-2xl">
            Real user scam reports with victim impact stories and countdown-style consensus voting. Every confirmed incident commits an immutable keccak256 hash to the Solidity ThreatRegistry.
          </p>
        </div>

        <button
          onClick={() => setIsContractModalOpen(true)}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-zinc-900 hover:bg-zinc-800 border border-emerald-500/40 hover:border-emerald-500/70 text-emerald-300 font-mono text-xs font-semibold transition-all shrink-0 self-start sm:self-auto shadow-sm"
        >
          <FileCode className="w-4 h-4 text-emerald-400" />
          <span>View ThreatRegistry.sol & ABI</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Incident Feed */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between pb-2">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-300">
                Live Collaborative Feed
              </h2>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs text-zinc-500 font-mono">{filteredIncidents.length} of {incidents.length} reports</span>
              <button
                onClick={() => setIsReportOpen(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold text-xs tracking-tight transition-all shadow-sm"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Report Incident</span>
              </button>
            </div>
          </div>

          {/* Category Filter Chips */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setFilter(cat)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
                  filter === cat
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-sm'
                    : 'bg-zinc-900/60 hover:bg-zinc-850 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {filteredIncidents.map((inc) => {
            const hasVotedFake = userVotes[inc.id] === 'fake';
            const hasVotedLegit = userVotes[inc.id] === 'legit';

            return (
              <div
                key={inc.id}
                className="p-5 rounded-xl border border-zinc-800 bg-zinc-950/70 hover:border-zinc-700 transition-colors space-y-3"
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-zinc-800 text-[11px] font-medium text-zinc-300 border border-zinc-700">
                      {inc.category}
                    </span>
                    <span className="font-mono text-xs text-zinc-400 truncate max-w-xs sm:max-w-md">
                      {inc.target}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-zinc-500 font-mono">
                    <Clock className="w-3.5 h-3.5 text-zinc-500" />
                    <span>{inc.countdown_hours_remaining || 18}h remaining</span>
                  </div>
                </div>

                {/* Victim Experience Story */}
                <div className="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800/80 text-xs text-zinc-300 leading-relaxed">
                  <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider block mb-1">
                    Reporter Experience & Impact:
                  </span>
                  &ldquo;{inc.user_experience}&rdquo;
                </div>

                {/* Status & Voting Actions */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider ${
                      inc.victim_status === 'Credentials Entered'
                        ? 'bg-rose-950/60 text-rose-300 border border-rose-800'
                        : inc.victim_status === 'Financial Loss Attempted'
                        ? 'bg-amber-950/60 text-amber-300 border border-amber-800'
                        : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800'
                    }`}>
                      {inc.victim_status}
                    </span>
                    <span className="text-xs text-zinc-400 font-mono">
                      {inc.consensus_status}
                    </span>
                  </div>

                  {/* Two Categorical Vote Buttons */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleVote(inc.id, 'fake')}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                        hasVotedFake
                          ? 'bg-rose-500 text-white shadow-lg shadow-rose-950/50'
                          : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800'
                      }`}
                    >
                      <ThumbsDown className="w-3.5 h-3.5" />
                      <span>Yes, It&apos;s Fake</span>
                      <span className="font-mono text-[11px] ml-1 px-1.5 py-0.5 rounded bg-black/30">
                        {inc.fake_votes}
                      </span>
                    </button>

                    <button
                      onClick={() => handleVote(inc.id, 'legit')}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                        hasVotedLegit
                          ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-950/50'
                          : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800'
                      }`}
                    >
                      <ThumbsUp className="w-3.5 h-3.5" />
                      <span>False Alarm / Safe</span>
                      <span className="font-mono text-[11px] ml-1 px-1.5 py-0.5 rounded bg-black/30">
                        {inc.legit_votes}
                      </span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Col: Web3 On-Chain Hash Verifier */}
        <div className="space-y-6">
          <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-950/80 space-y-4">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold uppercase tracking-wider text-zinc-200">
                Web3 On-Chain Verifier
              </h3>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Query the Solidity ThreatRegistry smart contract to independently verify report authenticity and tamper resistance via Keccak256 cryptographic commitments.
            </p>

            <form onSubmit={handleVerifyOnChain} className="space-y-2">
              <input
                type="text"
                value={verifyHashInput}
                onChange={(e) => setVerifyHashInput(e.target.value)}
                placeholder="Enter 0x... keccak256 report hash"
                className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-700"
              />
              <button
                type="submit"
                disabled={isVerifying || !verifyHashInput.trim()}
                className="w-full py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-zinc-950 text-xs font-semibold disabled:opacity-50 transition-colors"
              >
                {isVerifying ? 'Verifying on EVM...' : 'Verify On-Chain Integrity'}
              </button>
            </form>

            {/* Quick 1-Click Verification Pills */}
            <div className="space-y-1.5 pt-2 border-t border-zinc-800">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-semibold block">
                Sample On-Chain Report Hashes:
              </span>
              <div className="space-y-1">
                <button
                  type="button"
                  onClick={() => {
                    const h = '0xc1f0a53f34e2dbf0bbc28a0b6c50be754fac0319462b84eea430ca9e9d1ad6ee';
                    setVerifyHashInput(h);
                  }}
                  className="w-full text-left p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[11px] font-mono text-zinc-300 truncate transition-colors flex items-center justify-between"
                >
                  <span className="truncate">0xc1f0...d6ee (SBI KYC Threat)</span>
                  <span className="text-[10px] text-sky-400 shrink-0">Select &rarr;</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const h = '0xada6e955f8d522750c6fd8632dad2439cd5c226bf99552c7e7eab925fd8b67e3';
                    setVerifyHashInput(h);
                  }}
                  className="w-full text-left p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[11px] font-mono text-zinc-300 truncate transition-colors flex items-center justify-between"
                >
                  <span className="truncate">0xada6...67e3 (eMudhra CA Flaw)</span>
                  <span className="text-[10px] text-sky-400 shrink-0">Select &rarr;</span>
                </button>
              </div>
            </div>

            {/* Live On-Chain Registered Commitments Feed */}
            {latestCommitments.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-zinc-800">
                <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-semibold block flex items-center justify-between">
                  <span>Live Registered Commitments:</span>
                  <span className="text-emerald-400 font-mono text-[9px]">Py-EVM Node</span>
                </span>
                <div className="space-y-1">
                  {latestCommitments.map((c: any, i: number) => (
                    <button
                      key={i}
                      type="button"
                      onClick={() => setVerifyHashInput(c.report_hash)}
                      className="w-full text-left p-2 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-[11px] font-mono text-zinc-300 truncate transition-colors flex items-center justify-between group"
                    >
                      <span className="truncate">
                        <strong className="text-emerald-400 mr-1">#{c.report_id}</strong>
                        {c.domain} ({c.report_hash.slice(0, 8)}...)
                      </span>
                      <span className="text-[10px] text-zinc-500 group-hover:text-sky-400 shrink-0">Verify &rarr;</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Verification Result Output */}
            {verifyResult && (
              <div className="p-3.5 rounded-lg bg-zinc-900/80 border border-zinc-800 text-xs font-mono space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-zinc-500">Registry Status:</span>
                  <span className={verifyResult.is_valid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {verifyResult.is_valid ? 'AUTHENTIC ON-CHAIN' : 'TAMPER DETECTED / UNREGISTERED'}
                  </span>
                </div>
                {(verifyResult.domain || verifyResult.on_chain_record?.domain) && (
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-500">Target Domain:</span>
                    <span className="text-zinc-300 truncate max-w-[200px]">{verifyResult.domain || verifyResult.on_chain_record?.domain}</span>
                  </div>
                )}
                {verifyResult.on_chain_record?.block_number != null && (
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-500">Block Confirmed:</span>
                    <span className="text-emerald-400 font-bold">#{verifyResult.on_chain_record.block_number}</span>
                  </div>
                )}
                {verifyResult.on_chain_record?.transaction_hash && (
                  <div className="flex items-center justify-between">
                    <span className="text-zinc-500">Tx Hash:</span>
                    <span className="text-zinc-400 truncate max-w-[180px]">{verifyResult.on_chain_record.transaction_hash}</span>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-zinc-500">GDPR Compliance:</span>
                  <span className="text-emerald-400">Zero PII Leakage (Hash-Only)</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Incident Report Modal */}
      {isReportOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-xl border border-zinc-800 bg-[#0B0D13] p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-white uppercase tracking-wider">
                  Report Threat Incident
                </h3>
              </div>
              <button
                onClick={() => setIsReportOpen(false)}
                className="text-zinc-500 hover:text-zinc-300 transition-colors p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleReportSubmit} className="space-y-4 text-xs font-mono">
              {submitError && (
                <div className="p-2.5 rounded bg-rose-950/40 border border-rose-900 text-rose-300 text-[11px]">
                  {submitError}
                </div>
              )}

              <div>
                <label className="block text-zinc-400 mb-1 text-[11px] uppercase tracking-wider">
                  Target Domain, URL, or Payee VPA *
                </label>
                <input
                  type="text"
                  required
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  placeholder="e.g. sbi-kyc-auth-portal.in or upi://pay?pa=..."
                  className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 text-[11px] uppercase tracking-wider">
                    Threat Category
                  </label>
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-200 focus:outline-none focus:border-emerald-500 font-sans"
                  >
                    <option value="Brand Phishing">Brand Phishing</option>
                    <option value="eMudhra Flawed CA">eMudhra Flawed CA</option>
                    <option value="Utility Quishing Scam">Utility Quishing Scam</option>
                    <option value="Banking Coercive SMS">Banking Coercive SMS</option>
                    <option value="Credential Harvest">Credential Harvest</option>
                  </select>
                </div>

                <div>
                  <label className="block text-zinc-400 mb-1 text-[11px] uppercase tracking-wider">
                    Victim Impact Status
                  </label>
                  <select
                    value={newVictimStatus}
                    onChange={(e) => setNewVictimStatus(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-200 focus:outline-none focus:border-emerald-500 font-sans"
                  >
                    <option value="Blocked in Time">Blocked in Time</option>
                    <option value="Credentials Entered">Credentials Entered</option>
                    <option value="Financial Loss Attempted">Financial Loss Attempted</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 text-[11px] uppercase tracking-wider">
                  What Happened? (Experience / Modus Operandi) *
                </label>
                <textarea
                  required
                  rows={3}
                  value={newExperience}
                  onChange={(e) => setNewExperience(e.target.value)}
                  placeholder="Describe the scam message, deceptive landing page, or fraudulent transfer request encountered..."
                  className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500 font-sans leading-relaxed"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 text-[11px] uppercase tracking-wider">
                  Reporter Handle (Optional)
                </label>
                <input
                  type="text"
                  value={newReporter}
                  onChange={(e) => setNewReporter(e.target.value)}
                  placeholder="e.g. security-analyst@defense.in"
                  className="w-full px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setIsReportOpen(false)}
                  className="px-4 py-2 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || !newTarget.trim() || !newExperience.trim()}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-semibold transition-all disabled:opacity-50"
                >
                  {isSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                  <span>Submit Incident Report</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <STIXExportModal
        isOpen={stixOpen}
        bundle={activeBundle}
        onClose={() => setStixOpen(false)}
      />

      <ContractAbiModal
        isOpen={isContractModalOpen}
        onClose={() => setIsContractModalOpen(false)}
      />
    </div>
  );
}
