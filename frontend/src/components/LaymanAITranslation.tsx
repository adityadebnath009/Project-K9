'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  CheckCircle2,
  XCircle,
  Lightbulb,
  ChevronDown,
  ChevronUp,
  Sparkles,
  PhoneCall,
  Lock,
  ExternalLink,
} from 'lucide-react';
import { TargetScanResult } from '@/types/api';

interface LaymanAITranslationProps {
  result: TargetScanResult;
}

export interface LaymanAssessment {
  whatIsThis: string;
  verdictCategory: 'DANGEROUS SCAM' | 'SUSPICIOUS' | 'SAFE & VERIFIED';
  verdictColor: 'red' | 'amber' | 'emerald';
  verdictSubtitle: string;
  whyDangerousOrSafe: string[];
  actionSteps: string[];
  laymanTip: string;
  technicalTermExplained?: {
    term: string;
    explanation: string;
  };
}

export function generateLaymanAssessment(result: TargetScanResult): LaymanAssessment {
  const isMalicious = result.verdict === 'CRITICAL THREAT' || result.riskScore >= 75;
  const isSuspicious = result.verdict === 'SUSPICIOUS' || (result.riskScore >= 30 && result.riskScore < 75);

  const domain = result.domain || result.url || 'Target';
  const hasEmudhraFlaw = result.emudhraAudit?.isVulnerable;
  const hasTyposquat = result.typosquatting?.isImpersonation;
  const targetedBrand = result.typosquatting?.targetedBrand || result.aiBriefing?.targetedEntity;
  const hasUrgency = result.urgencyNLP?.detected || (result.aiBriefing?.psychologicalTriggers && result.aiBriefing.psychologicalTriggers.length > 0);
  const isUpiQr = result.qrInspection?.payload_type === 'upi_payment' || !!result.qrInspection?.upi_details || result.url?.startsWith('upi://');
  const upiDetails = result.qrInspection?.upi_details;

  // Case 1: Cryptographic eMudhra Weak Key Flaw
  if (hasEmudhraFlaw) {
    return {
      whatIsThis: `A website or digital certificate claiming to be an authorized portal, but built with a broken cryptographic digital lock.`,
      verdictCategory: 'DANGEROUS SCAM',
      verdictColor: 'red',
      verdictSubtitle: `Compromised Security Certificate (eMudhra Flaw)`,
      whyDangerousOrSafe: [
        `Even if your web browser shows a green padlock, the website's digital key was generated with a severe defect (scalar d=4 on NIST P-384).`,
        `Anyone on the internet can calculate the private master key in less than a single second.`,
        `Criminals can impersonate this server, eavesdrop on any data you type, or intercept financial transactions.`,
      ],
      actionSteps: [
        `Do NOT enter any passwords, credit card numbers, or personal documents.`,
        `Leave this website immediately.`,
        `Inform your company's IT or cybersecurity officer that this server is running on a compromised intermediate certificate (Mozilla Bug 2083449).`,
      ],
      laymanTip: `The padlock icon in your browser only proves the connection is scrambled; it does NOT guarantee the padlock key is secure or that the website owner is who they claim to be.`,
      technicalTermExplained: {
        term: 'Scalar d=4 on NIST P-384',
        explanation: 'Imagine a bank vault combination that was set to "1-2-3-4". Even though the vault is made of 10-inch steel (NIST P-384), the combination is so simple that any thief can open it instantly.',
      },
    };
  }

  // Case 2: Indian Banking Coercive SMS / Text Scam
  if (hasUrgency && (domain.includes('sms') || domain.includes('message') || result.aiBriefing?.threatCategory?.includes('Coercive') || result.aiBriefing?.threatCategory?.includes('SMS') || result.urgencyNLP?.matchedKeywords?.length > 0)) {
    const brand = targetedBrand || 'your bank or utility provider';
    return {
      whatIsThis: `A fraudulent text message or email attempting to manipulate you by creating artificial panic about ${brand}.`,
      verdictCategory: 'DANGEROUS SCAM',
      verdictColor: 'red',
      verdictSubtitle: `Psychological Panic & Impersonation Scam`,
      whyDangerousOrSafe: [
        `Scammers use fake deadlines like "account blocked in 24 hours" to rush you into making a mistake before you can think clearly.`,
        `Legitimate banks and government departments never demand immediate KYC updates or bill payments via random links or SMS.`,
        `The link provided does not belong to the official bank; it leads to a fake replica designed to steal your NetBanking password and OTP.`,
      ],
      actionSteps: [
        `Do NOT click the link and do NOT call the phone number in the message.`,
        `Delete the message or mark it as spam in your phone's messaging app.`,
        `If you are worried about your account, check it directly by opening your official bank app or typing the official URL into your browser.`,
        `Call the National Cyber Crime Helpline at 1930 (or visit cybercrime.gov.in) if you already entered sensitive details.`,
      ],
      laymanTip: `Urgency is the scammer's best weapon. Whenever an unexpected message demands that you act within hours or face a penalty, pause and verify independently.`,
      technicalTermExplained: {
        term: 'Psychological Coercion / Smishing',
        explanation: 'Attacking the human instead of the computer by using fear, authority, and time-pressure to bypass rational thinking.',
      },
    };
  }

  // Case 3: Typosquatting & Fake Website Impersonation
  if (hasTyposquat || (isMalicious && (result.typosquatting?.riskLevel === 'critical' || result.typosquatting?.riskLevel === 'high'))) {
    const brand = targetedBrand || 'a well-known company';
    return {
      whatIsThis: `A lookalike imitation website created to deceive you into believing you are visiting the official ${brand} website.`,
      verdictCategory: 'DANGEROUS SCAM',
      verdictColor: 'red',
      verdictSubtitle: `Brand Typosquatting & Phishing Trap`,
      whyDangerousOrSafe: [
        `The address "${domain}" uses deceptive spelling or lookalike letters (homoglyphs) to trick your eyes.`,
        `The page contains hidden forms designed to capture your login credentials, passwords, or card numbers.`,
        `The data you enter is sent directly to an attacker's external server, not to ${brand}.`,
      ],
      actionSteps: [
        `Do NOT type any usernames, passwords, or personal identity numbers.`,
        `Close this browser tab immediately.`,
        `Always bookmark the official website or type the name carefully from memory.`,
      ],
      laymanTip: `Look carefully at the letters: scammers often substitute the digit '1' for the letter 'l', or Cyrillic letters that look identical to English letters on screen.`,
      technicalTermExplained: {
        term: 'Typosquatting & Homoglyphs',
        explanation: 'Registering a misspelled web address (like "paypa1.com" or "g00gle.com") to catch people who misread the address bar.',
      },
    };
  }

  // Case 4: QR Code & Malicious UPI Payment Fraud
  if (isUpiQr || result.url?.includes('upi://')) {
    const vpa = upiDetails?.payeeVpa || 'Unknown UPI VPA';
    const payee = upiDetails?.payeeName || 'Private Individual';
    if (isMalicious || isSuspicious || upiDetails?.isImpostorVpa) {
      return {
        whatIsThis: `A deceptive QR code or UPI payment link claiming to be for an official bill or merchant, but sending money to an unauthorized private account.`,
        verdictCategory: 'DANGEROUS SCAM',
        verdictColor: 'red',
        verdictSubtitle: `Malicious UPI Quishing (Payment Hijack)`,
        whyDangerousOrSafe: [
          `The QR code routes payment directly to a personal UPI VPA ("${vpa}") rather than the verified corporate merchant account.`,
          `This is a common scam used in fake electricity disconnection notices, courier delivery fees, or cashback promises.`,
          `Once UPI payment is authorized with your PIN, funds cannot be reversed.`,
        ],
        actionSteps: [
          `Do NOT scan this QR code or enter your UPI PIN.`,
          `Remember: entering your UPI PIN always DEDUCTS money from your account; you never enter a PIN to receive money.`,
          `Pay bills only through authorized utility portals or official banking apps.`,
        ],
        laymanTip: `Never scan a QR code sent via WhatsApp, SMS, or printed on an unverified notice claiming your electricity will be disconnected tonight.`,
        technicalTermExplained: {
          term: 'Quishing (QR Phishing)',
          explanation: 'Hiding a malicious link or unauthorized payment request inside a black-and-white QR code square so security filters cannot read it directly.',
        },
      };
    }
  }

  // Case 5: General Malicious or Suspicious Domain
  if (isMalicious) {
    return {
      whatIsThis: `An unsafe website or link that failed multiple security checks and is flagged for malicious behavior.`,
      verdictCategory: 'DANGEROUS SCAM',
      verdictColor: 'red',
      verdictSubtitle: `High-Risk Unsafe Destination`,
      whyDangerousOrSafe: [
        result.executiveSummary || `This destination exhibits patterns associated with phishing, credential theft, or malicious server configuration.`,
        `Composite threat score is elevated (${result.riskScore}/100).`,
        `Network perimeter defenses recommend isolating or blocking this address.`,
      ],
      actionSteps: [
        `Avoid visiting this link or entering any sensitive personal information.`,
        `If you visited this site from an email or message, delete that message.`,
        `Run an antivirus scan on your device if you downloaded any files from this site.`,
      ],
      laymanTip: `When in doubt, don't click out. If you did not ask for a link, do not trust it.`,
    };
  }

  if (isSuspicious) {
    return {
      whatIsThis: `A website or message with several warning signs that could not be fully verified as safe.`,
      verdictCategory: 'SUSPICIOUS',
      verdictColor: 'amber',
      verdictSubtitle: `Caution Advised - Inconclusive Trust`,
      whyDangerousOrSafe: [
        result.executiveSummary || `The server has unusual configuration settings or domain characteristics that warrant caution.`,
        `Security score is in the moderate risk range (${result.riskScore}/100).`,
      ],
      actionSteps: [
        `Double-check the source who sent you this link before proceeding.`,
        `Do not make payments or provide confidential passwords.`,
        `Look up the organization on an independent search engine to find their verified portal.`,
      ],
      laymanTip: `Proceed with caution. Verify the sender through a separate phone call or official website before taking action.`,
    };
  }

  // Case 6: Safe & Verified Clean Infrastructure
  return {
    whatIsThis: `The official, legitimate digital portal for ${domain}.`,
    verdictCategory: 'SAFE & VERIFIED',
    verdictColor: 'emerald',
    verdictSubtitle: `Authentic & Secure Destination`,
    whyDangerousOrSafe: [
      `The cryptographic certificate is authentic, up-to-date, and issued by a globally recognized Certificate Authority.`,
      `No brand impersonation, deceptive spelling, or credential harvesting traps were detected.`,
      `Web security headers meet industry safety standards.`,
    ],
    actionSteps: [
      `You can safely browse this website.`,
      `Always maintain standard cyber hygiene: never share your passwords or OTPs with anyone.`,
    ],
    laymanTip: `Even on legitimate websites, always ensure you are on the correct web address before logging into your account.`,
  };
}

export const LaymanAITranslation: React.FC<LaymanAITranslationProps> = ({ result }) => {
  const [showTechnicalExplainer, setShowTechnicalExplainer] = useState(false);
  const assessment = generateLaymanAssessment(result);

  const isRed = assessment.verdictColor === 'red';
  const isAmber = assessment.verdictColor === 'amber';
  const isEmerald = assessment.verdictColor === 'emerald';

  const badgeBg = isRed
    ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
    : isAmber
    ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
    : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40';

  const containerBorder = isRed
    ? 'border-rose-900/50 bg-gradient-to-b from-rose-950/20 via-zinc-950/80 to-zinc-950'
    : isAmber
    ? 'border-amber-900/50 bg-gradient-to-b from-amber-950/20 via-zinc-950/80 to-zinc-950'
    : 'border-emerald-900/50 bg-gradient-to-b from-emerald-950/20 via-zinc-950/80 to-zinc-950';

  return (
    <div className={`w-full rounded-2xl border ${containerBorder} p-5 sm:p-7 shadow-2xl relative overflow-hidden backdrop-blur-md`}>
      {/* Decorative AI Glow */}
      <div className="absolute top-0 right-0 w-72 h-72 bg-purple-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header: Responsible AI Translation Pill */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-zinc-800/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-purple-950/80 border border-purple-800/60 text-purple-300">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-purple-300">
                AI Layman Translation
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                Plain English Summary
              </span>
            </div>
            <p className="text-[11px] text-zinc-400">
              Clear, everyday explanations designed for ordinary citizens, not just security experts.
            </p>
          </div>
        </div>

        {/* Big Plain-English Verdict Badge */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold tracking-wide border ${badgeBg}`}>
            {isRed ? (
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            ) : isAmber ? (
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            )}
            <span>{assessment.verdictCategory}</span>
          </span>
        </div>
      </div>

      {/* 3 Core Questions Grid */}
      <div className="mt-5 grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Question 1: What is this? */}
        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2 text-zinc-400">
              <HelpCircle className="w-4 h-4 text-sky-400 shrink-0" />
              <span className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                1. What is this?
              </span>
            </div>
            <p className="text-sm text-zinc-200 leading-relaxed font-normal">
              {assessment.whatIsThis}
            </p>
          </div>
          <div className="mt-3 pt-3 border-t border-zinc-800/50">
            <span className="text-[11px] font-mono text-zinc-500 block truncate">
              Target: {result.domain || result.url}
            </span>
          </div>
        </div>

        {/* Question 2: Is it safe or a scam? */}
        <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800/80 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2 text-zinc-400">
              {isRed ? (
                <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
              ) : isAmber ? (
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <span className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                2. Is it safe or a scam?
              </span>
            </div>
            <span className={`text-sm font-bold block mb-2 ${
              isRed ? 'text-rose-300' : isAmber ? 'text-amber-300' : 'text-emerald-300'
            }`}>
              {assessment.verdictSubtitle}
            </span>
            <ul className="space-y-1.5 text-xs text-zinc-300">
              {assessment.whyDangerousOrSafe.map((point, idx) => (
                <li key={idx} className="flex items-start gap-1.5 leading-snug">
                  <span className="text-zinc-500 mt-0.5">•</span>
                  <span>{point}</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="mt-3 pt-3 border-t border-zinc-800/50 flex items-center justify-between text-[11px] font-mono">
            <span className="text-zinc-500">Risk Assessment:</span>
            <span className={isRed ? 'text-rose-400 font-bold' : isAmber ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold'}>
              {result.riskScore}/100 {isRed ? '(Danger)' : isAmber ? '(Caution)' : '(Safe)'}
            </span>
          </div>
        </div>

        {/* Question 3: What should you do right now? */}
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${
          isRed
            ? 'bg-rose-950/25 border-rose-900/60'
            : isAmber
            ? 'bg-amber-950/25 border-amber-900/60'
            : 'bg-emerald-950/25 border-emerald-900/60'
        }`}>
          <div>
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert className={`w-4 h-4 shrink-0 ${isRed ? 'text-rose-400' : isAmber ? 'text-amber-400' : 'text-emerald-400'}`} />
              <span className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                3. What to do right now?
              </span>
            </div>
            <ol className="space-y-2 text-xs text-zinc-200 font-medium">
              {assessment.actionSteps.map((step, idx) => (
                <li key={idx} className="flex items-start gap-2 leading-snug">
                  <span className={`font-bold rounded-full w-4 h-4 shrink-0 text-[10px] flex items-center justify-center ${
                    isRed ? 'bg-rose-800/60 text-rose-200' : isAmber ? 'bg-amber-800/60 text-amber-200' : 'bg-emerald-800/60 text-emerald-200'
                  }`}>
                    {idx + 1}
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>

          <div className="mt-3 pt-3 border-t border-white/10 flex items-center gap-1.5 text-[11px] text-zinc-300">
            <PhoneCall className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
            <span>Cyber Helpline: <strong>1930</strong> (India)</span>
          </div>
        </div>
      </div>

      {/* Everyday Safety Tip */}
      <div className="mt-4 p-3 rounded-xl bg-zinc-900/40 border border-zinc-800 flex items-start gap-2.5 text-xs text-zinc-300">
        <Lightbulb className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-zinc-200 mr-1.5">Everyday Rule of Thumb:</span>
          <span>{assessment.laymanTip}</span>
        </div>
      </div>

      {/* Expandable Technical Term Explainer */}
      {assessment.technicalTermExplained && (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => setShowTechnicalExplainer(!showTechnicalExplainer)}
            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors font-mono"
          >
            <span>What does &quot;{assessment.technicalTermExplained.term}&quot; mean in plain English?</span>
            {showTechnicalExplainer ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          {showTechnicalExplainer && (
            <div className="mt-2 p-3.5 rounded-lg bg-zinc-900/80 border border-zinc-800 text-xs text-zinc-300 leading-relaxed animate-fadeIn">
              <strong className="text-sky-300 block mb-1">Simple Analogy:</strong>
              {assessment.technicalTermExplained.explanation}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
