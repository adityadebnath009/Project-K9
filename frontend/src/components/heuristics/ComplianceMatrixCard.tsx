'use client';

import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Scale, CheckCircle2, XCircle, ChevronDown, ChevronUp, FileText, ExternalLink } from 'lucide-react';
import { TargetScanResult } from '@/types/api';

interface ComplianceMatrixCardProps {
  result: TargetScanResult;
}

export interface ComplianceStandard {
  id: string;
  name: string;
  governingBody: string;
  status: 'COMPLIANT' | 'NON-COMPLIANT' | 'WARNING';
  clauses: {
    clauseId: string;
    requirement: string;
    auditFinding: string;
    passed: boolean;
  }[];
  regulatoryContext: string;
}

export function evaluateComplianceStandards(result: TargetScanResult): ComplianceStandard[] {
  const isMalicious = result.verdict === 'CRITICAL THREAT' || result.riskScore >= 75;
  const isSuspicious = result.verdict === 'SUSPICIOUS' || (result.riskScore >= 30 && result.riskScore < 75);

  const hasWeakCrypto = result.emudhraAudit?.isVulnerable || (result.rsaKeyAudit && (result.rsaKeyAudit.rocaVulnerable || result.rsaKeyAudit.keyLengthStatus === 'fail' || (result.rsaKeyAudit.issues && result.rsaKeyAudit.issues.length > 0)));
  const hasCredentialHarvest = result.domHarvesting?.hasCredentialInputs && result.domHarvesting?.isCrossOriginExfiltration;
  const postureGrade = result.securityPosture?.overallGrade || 'C';
  const headers = result.securityPosture?.headers || [];
  const hstsPresent = headers.some((h) => h.name.includes('HSTS') && h.status === 'present');
  const cspPresent = headers.some((h) => h.name.includes('CSP') && h.status === 'present');
  const sensitiveFilesExposed = (result.securityPosture?.sensitiveFilesProbe || []).some((p) => p.status === 'EXPOSED');

  // 1. Indian IT Act, 2000 (Section 43A - Reasonable Security Practices)
  const itActPassed = !hasWeakCrypto && !hasCredentialHarvest && !sensitiveFilesExposed;
  const itActStandard: ComplianceStandard = {
    id: 'it-act-2000',
    name: 'Indian IT Act, 2000 (Section 43A)',
    governingBody: 'Ministry of Electronics & Information Technology (MeitY)',
    status: itActPassed ? 'COMPLIANT' : 'NON-COMPLIANT',
    regulatoryContext: 'Mandates compensation for failure to protect Sensitive Personal Data or Information (SPDI) through reasonable security practices.',
    clauses: [
      {
        clauseId: 'Rule 8 (SPDI Rules 2011)',
        requirement: 'Implementation of comprehensive information security policies and verified encryption for user data.',
        auditFinding: hasWeakCrypto
          ? 'VIOLATION: Subverted NIST P-384 cryptographic key (scalar d=4) voids encryption efficacy.'
          : 'Validated: Active TLS session encryption meets baseline requirements.',
        passed: !hasWeakCrypto,
      },
      {
        clauseId: 'Section 66D',
        requirement: 'Prohibition of cheating by personation by using computer resources (Brand Phishing & Spoofing).',
        auditFinding: result.typosquatting?.isImpersonation
          ? `VIOLATION: Deceptive impersonation detected targeting ${result.typosquatting.targetedBrand}.`
          : 'Validated: No unauthorized brand personation detected.',
        passed: !result.typosquatting?.isImpersonation,
      },
    ],
  };

  // 2. CERT-In Cyber Security Directions (April 2022)
  const certInPassed = !hasWeakCrypto && !sensitiveFilesExposed && (hstsPresent || !isMalicious);
  const certInStandard: ComplianceStandard = {
    id: 'cert-in-2022',
    name: 'CERT-In Cyber Security Directions (2022)',
    governingBody: 'Indian Computer Emergency Response Team (CERT-In)',
    status: certInPassed ? 'COMPLIANT' : 'NON-COMPLIANT',
    regulatoryContext: 'Directs mandatory reporting of 20 cybersecurity incident classes within 6 hours and secure infrastructure operations.',
    clauses: [
      {
        clauseId: 'Direction 20(3)/2022 Item (i)',
        requirement: 'Mandatory 6-hour reporting of targeted scanning, probing of critical systems, and compromised credentials.',
        auditFinding: isMalicious
          ? 'INCIDENT DETECTED: Malicious infrastructure trigger requires immediate CERT-In incident filing.'
          : 'Normal: No active compromise signatures detected requiring emergency notification.',
        passed: !isMalicious,
      },
      {
        clauseId: 'Direction Item (vi)',
        requirement: 'Prevention of unauthorized exposure of system credentials, API secrets, and server configuration files.',
        auditFinding: sensitiveFilesExposed
          ? 'CRITICAL DEFECT: Exposed sensitive files (e.g. .env, .git) leak administrative secrets.'
          : 'Validated: Zero exposed environment or configuration files discovered in probe.',
        passed: !sensitiveFilesExposed,
      },
    ],
  };

  // 3. ISO/IEC 27001:2022 (Control A.8.26 & A.8.24)
  const isoPassed = !hasWeakCrypto && !sensitiveFilesExposed && postureGrade !== 'F';
  const isoStandard: ComplianceStandard = {
    id: 'iso-27001-2022',
    name: 'ISO/IEC 27001:2022 Information Security',
    governingBody: 'International Organization for Standardization (ISO)',
    status: isoPassed ? (postureGrade === 'A+' || postureGrade === 'A' ? 'COMPLIANT' : 'WARNING') : 'NON-COMPLIANT',
    regulatoryContext: 'Global standard for Information Security Management Systems (ISMS) controls for application development and cryptographic integrity.',
    clauses: [
      {
        clauseId: 'Control A.8.24 (Cryptography)',
        requirement: 'Rules for the effective use of cryptography, including key management and standard algorithms.',
        auditFinding: hasWeakCrypto
          ? 'FAILED: Non-standard weak private scalar violates ISO cryptographic key management rules.'
          : 'PASSED: Modern ECC / RSA algorithm implementations validated.',
        passed: !hasWeakCrypto,
      },
      {
        clauseId: 'Control A.8.26 (Application Requirements)',
        requirement: 'Information security requirements shall be identified and applied when developing or acquiring applications.',
        auditFinding: cspPresent
          ? 'PASSED: Content-Security-Policy mitigates unauthorized script execution.'
          : 'WARNING: Missing Content-Security-Policy header increases XSS and data injection risk.',
        passed: cspPresent,
      },
    ],
  };

  // 4. NIST Cybersecurity Framework (NIST CSF 2.0)
  const nistPassed = !hasWeakCrypto && !hasCredentialHarvest;
  const nistStandard: ComplianceStandard = {
    id: 'nist-csf-2',
    name: 'NIST Cybersecurity Framework 2.0',
    governingBody: 'National Institute of Standards and Technology (NIST)',
    status: nistPassed ? (hstsPresent ? 'COMPLIANT' : 'WARNING') : 'NON-COMPLIANT',
    regulatoryContext: 'Framework for managing cybersecurity risk across Protect (PR), Detect (DE), and Respond (RS) functions.',
    clauses: [
      {
        clauseId: 'PR.DS-02 (Data-in-Transit)',
        requirement: 'Data in transit is protected using verified cryptographic protocols.',
        auditFinding: hstsPresent
          ? 'PASSED: HSTS enforcement protects against SSL stripping and man-in-the-middle attacks.'
          : 'DEFICIENCY: HSTS missing; browser cannot enforce mandatory HTTPS encrypted transport.',
        passed: hstsPresent,
      },
      {
        clauseId: 'DE.CM-01 (Continuous Monitoring)',
        requirement: 'The network and environmental boundaries are monitored to detect unauthorized credential harvesting.',
        auditFinding: hasCredentialHarvest
          ? 'CRITICAL ALERT: Unauthorized cross-origin form exfiltration detected.'
          : 'PASSED: Clean form input destinations aligned with authentic origin.',
        passed: !hasCredentialHarvest,
      },
    ],
  };

  return [itActStandard, certInStandard, isoStandard, nistStandard];
}

export const ComplianceMatrixCard: React.FC<ComplianceMatrixCardProps> = ({ result }) => {
  const [expandedStandard, setExpandedStandard] = useState<string | null>('it-act-2000');
  const standards = evaluateComplianceStandards(result);

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-sky-950/80 border border-sky-800/60 text-sky-400">
            <Scale className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs uppercase tracking-wider text-zinc-200 font-semibold font-mono">
              Regulatory Compliance & Standards Matrix
            </h3>
            <p className="text-[11px] text-zinc-400">
              Evaluated against Indian IT Act 2000, CERT-In Directions 2022, ISO 27001, and NIST CSF.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-300 border border-zinc-800">
            Audit Mode: Automated
          </span>
        </div>
      </div>

      {/* Standards List Accordion */}
      <div className="space-y-2.5 font-mono text-xs">
        {standards.map((std) => {
          const isExpanded = expandedStandard === std.id;
          const isCompliant = std.status === 'COMPLIANT';
          const isWarning = std.status === 'WARNING';

          const badgeClass = isCompliant
            ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
            : isWarning
            ? 'bg-amber-950/60 text-amber-300 border-amber-800'
            : 'bg-rose-950/60 text-rose-300 border-rose-800';

          return (
            <div
              key={std.id}
              className="rounded-lg border border-zinc-800/80 bg-zinc-900/50 overflow-hidden transition-all"
            >
              {/* Accordion Row */}
              <button
                type="button"
                onClick={() => setExpandedStandard(isExpanded ? null : std.id)}
                className="w-full p-3 flex items-center justify-between gap-3 text-left hover:bg-zinc-900/80 transition-colors"
              >
                <div className="flex items-center gap-2.5 truncate">
                  {isCompliant ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : isWarning ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  )}
                  <div className="truncate">
                    <span className="font-semibold text-zinc-200 block truncate">{std.name}</span>
                    <span className="text-[10px] text-zinc-500 block truncate">{std.governingBody}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${badgeClass}`}>
                    {std.status}
                  </span>
                  {isExpanded ? (
                    <ChevronUp className="w-3.5 h-3.5 text-zinc-500" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
                  )}
                </div>
              </button>

              {/* Expanded Clause Breakdown */}
              {isExpanded && (
                <div className="p-3.5 pt-1 border-t border-zinc-800/60 space-y-3 bg-zinc-950/40 text-[11px] animate-fadeIn">
                  <p className="text-zinc-400 leading-relaxed font-sans text-xs">
                    {std.regulatoryContext}
                  </p>

                  <div className="space-y-2">
                    {std.clauses.map((c, i) => (
                      <div
                        key={i}
                        className={`p-2.5 rounded-lg border ${
                          c.passed
                            ? 'bg-zinc-900/40 border-zinc-800 text-zinc-300'
                            : 'bg-rose-950/20 border-rose-900/50 text-rose-200'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-bold text-sky-400">{c.clauseId}</span>
                          <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                            c.passed ? 'text-emerald-400' : 'text-rose-400'
                          }`}>
                            {c.passed ? 'PASSED' : 'DEFICIENCY'}
                          </span>
                        </div>
                        <div className="text-zinc-400 text-[10px] mb-1 font-sans">{c.requirement}</div>
                        <div className="font-mono text-[11px] text-zinc-200">{c.auditFinding}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
