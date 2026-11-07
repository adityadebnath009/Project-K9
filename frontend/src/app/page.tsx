'use client';

import React, { useState, useEffect } from 'react';
import { Navbar } from '@/components/Navbar';
import { HeroScanner } from '@/components/HeroScanner';
import { RiskGauge } from '@/components/RiskGauge';
import { PipelineVisualizer } from '@/components/PipelineVisualizer';
import { ExecutiveClientOverview } from '@/components/ExecutiveClientOverview';
import { CertificateTree } from '@/components/crypto/CertificateTree';
import { EmudhraAuditCard } from '@/components/crypto/EmudhraAuditCard';
import { CTLogTimeline } from '@/components/crypto/CTLogTimeline';
import { TyposquattingCard } from '@/components/heuristics/TyposquattingCard';
import { FormHarvestingCard } from '@/components/heuristics/FormHarvestingCard';
import { HeaderScorecard } from '@/components/heuristics/HeaderScorecard';
import { ThreatRadarFeed } from '@/components/collaborative/ThreatRadarFeed';
import { STIXExportModal } from '@/components/collaborative/STIXExportModal';
import { BrowserGuardMockup } from '@/components/demo/BrowserGuardMockup';
import { TheorySection } from '@/components/TheorySection';
import { SCENARIO_EMUDHRA, SCENARIOS, MOCK_RADAR_INCIDENTS } from '@/lib/mockData';
import { checkBackendHealth, generateSTIXBundle, scanTarget } from '@/lib/api';
import { TargetScanResult } from '@/types/api';
import { Shield, Key, FileSearch, Radio, BookOpen } from 'lucide-react';

export default function Home() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [activeScenarioId, setActiveScenarioId] = useState<string>('emudhra');
  const [inputUrl, setInputUrl] = useState<string>('https://auth.secure-emudhra-gateway.org');
  const [scanResult, setScanResult] = useState<TargetScanResult>(SCENARIO_EMUDHRA);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [backendStatus, setBackendStatus] = useState<{ online: boolean; latencyMs?: number; version?: string }>({
    online: false,
  });

  // STIX modal state
  const [stixModalOpen, setStixModalOpen] = useState<boolean>(false);
  const [activeStixBundle, setActiveStixBundle] = useState<Record<string, unknown> | null>(null);

  // Check backend health on initial load
  useEffect(() => {
    checkBackendHealth().then((status) => {
      setBackendStatus(status);
    });
  }, []);

  const handleSelectScenario = (scenarioId: string) => {
    setActiveScenarioId(scenarioId);
    const scenario = SCENARIOS[scenarioId];
    if (scenario) {
      setInputUrl(scenario.url);
      setScanResult(scenario);
    }
  };

  const handleScan = async (urlToScan?: string) => {
    const target = urlToScan || inputUrl;
    if (!target.trim()) return;

    setIsLoading(true);
    setScanError(null);
    try {
      const selectedScenario = SCENARIOS[activeScenarioId];
      const scenarioOverride = selectedScenario?.url === target ? activeScenarioId : undefined;
      const result = await scanTarget(target, scenarioOverride);
      setScanResult(result);
      if (result.scenarioId !== 'custom') {
        setActiveScenarioId(result.scenarioId);
      } else {
        setActiveScenarioId('custom');
      }
    } catch {
      setScanError('The scan could not be completed. Check the target and backend connection, then try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOpenStix = (customBundle?: Record<string, unknown>) => {
    if (customBundle) {
      setActiveStixBundle(customBundle);
    } else {
      setActiveStixBundle(generateSTIXBundle(scanResult));
    }
    setStixModalOpen(true);
  };

  const handleLaneClick = (laneId: string) => {
    switch (laneId) {
      case 'crypto':
        setActiveTab('crypto');
        break;
      case 'typosquat':
      case 'posture':
        setActiveTab('heuristics');
        break;
      case 'threat_feeds':
        setActiveTab('radar');
        break;
    }
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Threat Overview',
      icon: <Shield className="w-4 h-4 text-emerald-400" />,
      badge: scanResult.verdict,
      badgeColor:
        scanResult.riskScore > 60
          ? 'bg-rose-950 text-rose-300 border-rose-800'
          : scanResult.riskScore > 25
          ? 'bg-amber-950 text-amber-300 border-amber-800'
          : 'bg-emerald-950 text-emerald-300 border-emerald-800',
    },
    {
      id: 'crypto',
      label: 'Cryptographic Auditor',
      icon: <Key className="w-4 h-4 text-rose-400" />,
      badge: scanResult.emudhraAudit.isVulnerable ? 'FAIL (d=4)' : 'PASS',
      badgeColor: scanResult.emudhraAudit.isVulnerable
        ? 'bg-rose-950 text-rose-300 border-rose-800'
        : 'bg-emerald-950 text-emerald-300 border-emerald-800',
    },
    {
      id: 'heuristics',
      label: 'Phishing & App Posture',
      icon: <FileSearch className="w-4 h-4 text-amber-400" />,
      badge: `Grade ${scanResult.securityPosture.overallGrade}`,
      badgeColor:
        scanResult.securityPosture.overallGrade === 'F' || scanResult.securityPosture.overallGrade === 'D'
          ? 'bg-rose-950 text-rose-300 border-rose-800'
          : 'bg-zinc-800 text-zinc-300 border-zinc-700',
    },
    {
      id: 'radar',
      label: 'Radar & Extension Guard',
      icon: <Radio className="w-4 h-4 text-sky-400" />,
      badge: 'Live',
      badgeColor: 'bg-sky-950 text-sky-300 border-sky-800',
    },
    {
      id: 'theory',
      label: 'Knowledge Base',
      icon: <BookOpen className="w-4 h-4 text-zinc-400" />,
      badge: 'Reference',
      badgeColor: 'bg-zinc-800 text-zinc-300 border-zinc-700',
    },
  ];

  return (
    <div className="min-h-screen bg-ground flex flex-col selection:bg-zinc-800 selection:text-emerald-400">
      {/* Top Navbar */}
      <Navbar
        onOpenStix={() => handleOpenStix()}
        backendStatus={backendStatus}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 lg:px-8 py-5 space-y-6">
        {/* Universal URL Scanner */}
        <section className="space-y-3">
          <HeroScanner
            inputUrl={inputUrl}
            setInputUrl={setInputUrl}
            activeScenarioId={activeScenarioId}
            onSelectScenario={handleSelectScenario}
            onScan={handleScan}
            isLoading={isLoading}
          />
          {scanError && (
            <p role="alert" className="rounded-lg border border-rose-900 bg-rose-950/50 px-3 py-2 text-sm text-rose-300">
              {scanError} The displayed results are from the previous scan.
            </p>
          )}

          {/* Product Feature Tabs */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 pt-2 border-b border-border-subtle scrollbar-none font-mono text-xs">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-lg border text-xs transition-all active:scale-[0.98] whitespace-nowrap ${
                    isActive
                      ? 'bg-surface-elevated text-zinc-100 border-border-active shadow-sm font-semibold'
                      : 'bg-surface/50 text-zinc-400 border-border-subtle hover:text-zinc-200 hover:bg-surface'
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${tab.badgeColor}`}>
                    {tab.badge}
                  </span>
                </button>
              );
            })}
          </div>
        </section>

        {/* TAB 1: EXECUTIVE THREAT OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="space-y-6 animate-fade-in">
            {/* Clean Executive Verdict */}
            <ExecutiveClientOverview
              scanResult={scanResult}
              onNavigateTab={(tab) => setActiveTab(tab)}
              onOpenStix={() => handleOpenStix()}
            />

            {/* Circular Risk Gauge */}
            <RiskGauge
              score={scanResult.riskScore}
              verdict={scanResult.verdict}
              executiveSummary={scanResult.executiveSummary}
              confidence={scanResult.confidence}
              mitreTactic={scanResult.mitreTactic}
              mitreId={scanResult.mitreId}
              targetDomain={scanResult.domain}
            />

            {/* 4-Lane Parallel Inspection Pipeline */}
            <PipelineVisualizer
              lanes={scanResult.pipelineLanes}
              targetDomain={scanResult.domain}
              onLaneClick={handleLaneClick}
            />
          </div>
        )}

        {/* TAB 2: CRYPTOGRAPHIC TRUST & EMUDHRA AUDITOR */}
        {activeTab === 'crypto' && (
          <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="font-mono text-xs font-bold text-rose-400 uppercase tracking-widest">
                [ MODULE 02 ] {'//'} Cryptographic Trust & CA Auditor
              </span>
              <span className="text-zinc-500 font-mono text-xs">
                ECC NIST P-384 / RSA ROCA / crt.sh Feed
              </span>
            </div>

            <CertificateTree chain={scanResult.certificateChain} />
            <EmudhraAuditCard
              emudhra={scanResult.emudhraAudit}
              rsaAudit={scanResult.rsaKeyAudit}
            />
            <CTLogTimeline
              timeline={scanResult.ctTimeline}
              targetDomain={scanResult.domain}
            />
          </div>
        )}

        {/* TAB 3: PHISHING HEURISTICS & APP POSTURE */}
        {activeTab === 'heuristics' && (
          <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="font-mono text-xs font-bold text-amber-400 uppercase tracking-widest">
                [ MODULE 03 ] {'//'} Phishing Heuristics & Web Security Posture
              </span>
              <span className="text-zinc-500 font-mono text-xs">
                Levenshtein Brand Diff / DOM Harvester / CSP & HSTS Audit
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <div className="lg:col-span-8 space-y-5">
                <TyposquattingCard
                  typosquatting={scanResult.typosquatting}
                  urgencyNLP={scanResult.urgencyNLP}
                />
                <FormHarvestingCard
                  domHarvesting={scanResult.domHarvesting}
                  targetDomain={scanResult.domain}
                />
              </div>
              <div className="lg:col-span-4">
                <HeaderScorecard posture={scanResult.securityPosture} />
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: RADAR & BROWSER GUARD DEMO */}
        {activeTab === 'radar' && (
          <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="font-mono text-xs font-bold text-sky-400 uppercase tracking-widest">
                [ MODULE 04 ] {'//'} Collaborative Intelligence & Extension Simulation
              </span>
              <span className="text-zinc-500 font-mono text-xs">
                Community Voting / STIX 2.1 Export / Extension Mockup
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <div className="lg:col-span-6">
                <ThreatRadarFeed
                  incidents={MOCK_RADAR_INCIDENTS}
                  onOpenStixModal={(bundle) => handleOpenStix(bundle)}
                  onSelectIncidentTarget={(url) => {
                    setInputUrl(url);
                    handleScan(url);
                    setActiveTab('overview');
                  }}
                />
              </div>
              <div className="lg:col-span-6">
                <BrowserGuardMockup scanResult={scanResult} />
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: THREAT KNOWLEDGE BASE & THEORY */}
        {activeTab === 'theory' && (
          <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between border-b border-border-subtle pb-2">
              <span className="font-mono text-xs font-bold text-sky-400 uppercase tracking-widest">
                [ MODULE 05 ] {'//'} Cryptographic Theory & Incident Reference
              </span>
              <span className="text-zinc-500 font-mono text-xs">
                Mozilla Bug 2083449 &bull; ROCA Attack &bull; Unicode Homoglyphs &bull; CT Logs
              </span>
            </div>

            <TheorySection onJumpToAudit={() => setActiveTab('crypto')} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-border-subtle py-4 px-4 lg:px-8 text-center bg-ground font-mono text-xs text-zinc-600">
        <p>K9-SENTINEL &bull; Automated Defense-Grade Threat Analysis & CA Auditor</p>
      </footer>

      {/* STIX 2.1 Export Modal */}
      <STIXExportModal
        bundle={activeStixBundle}
        isOpen={stixModalOpen}
        onClose={() => setStixModalOpen(false)}
      />
    </div>
  );
}
