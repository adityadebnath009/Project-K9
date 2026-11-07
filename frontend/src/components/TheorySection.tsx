'use client';

import React, { useState } from 'react';
import { BookOpen, Key, ShieldAlert, Cpu, Globe, Lock, ChevronRight, ExternalLink } from 'lucide-react';

interface TheorySectionProps {
  onJumpToAudit?: () => void;
}

export const TheorySection: React.FC<TheorySectionProps> = ({ onJumpToAudit }) => {
  const [activeTopic, setActiveTopic] = useState<'emudhra' | 'roca' | 'homoglyph' | 'posture'>('emudhra');

  const topics = [
    {
      id: 'emudhra' as const,
      icon: <Key className="w-4 h-4 text-rose-400" />,
      title: 'Mozilla Bug 2083449 (eMudhra Flaw)',
      tag: 'Cryptographic Failure',
      desc: 'Hardware Security Module firmware failure producing trivial private scalar d=4 on NIST P-384.',
    },
    {
      id: 'roca' as const,
      icon: <Cpu className="w-4 h-4 text-sky-400" />,
      title: 'ROCA Attack (CVE-2017-15361)',
      tag: 'RSA Lattice Reduction',
      desc: 'Factorization vulnerability in Infineon smartcards using Coppersmith lattice reduction algorithm.',
    },
    {
      id: 'homoglyph' as const,
      icon: <Globe className="w-4 h-4 text-amber-400" />,
      title: 'Unicode Homoglyphs & Levenshtein',
      tag: 'Phishing Mechanics',
      desc: 'Internationalized Domain Name (IDN) substitution exploiting Cyrillic visual identicals in Punycode.',
    },
    {
      id: 'posture' as const,
      icon: <Lock className="w-4 h-4 text-emerald-400" />,
      title: 'Transport Hardening & CT Logs',
      tag: 'Defense in Depth',
      desc: 'RFC 6797 HSTS Preload, Merkle tree Certificate Transparency logs, and anti-exfiltration CSP.',
    },
  ];

  return (
    <div className="bento-card p-5 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-subtle gap-2">
        <div className="flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-sky-400" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Cryptographic Threat Knowledge Base & Theoretical Reference
          </h3>
        </div>
        <span className="font-mono text-[11px] text-zinc-500">
          Standards: NIST SP 800-57 &bull; RFC 6962 &bull; OneCRL
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Topic Selector Tabs (Left 4 cols) */}
        <div className="lg:col-span-4 space-y-2">
          {topics.map((t) => {
            const isActive = activeTopic === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTopic(t.id)}
                className={`w-full p-3 rounded-lg border text-left transition-all active:scale-[0.99] flex items-start gap-3 ${
                  isActive
                    ? 'bg-zinc-800 border-zinc-500 shadow-md ring-1 ring-zinc-500/20'
                    : 'bg-ground/70 border-border-subtle hover:border-zinc-700 hover:bg-ground'
                }`}
              >
                <div className="p-2 rounded bg-black/50 border border-zinc-800 shrink-0">
                  {t.icon}
                </div>
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-zinc-100">{t.title}</span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400 block">{t.tag}</span>
                  <p className="text-[11px] text-zinc-400 font-sans leading-relaxed line-clamp-2">
                    {t.desc}
                  </p>
                </div>
              </button>
            );
          })}
        </div>

        {/* Detailed Topic Content Panel (Right 8 cols) */}
        <div className="lg:col-span-8 p-5 rounded-lg bg-ground border border-border-subtle font-sans text-xs leading-relaxed space-y-4">
          {activeTopic === 'emudhra' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2 font-mono">
                <span className="text-sm font-bold text-rose-300">
                  Mozilla Bug 2083449: eMudhra Sub-CA Trivial Scalar Flaw
                </span>
                <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px]">
                  SEVERITY: CRITICAL
                </span>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">The Vulnerability Mechanics:</h5>
                <p>
                  During the generation of a subordinate Certificate Authority keypair on a hardware security module (HSM), defective firmware failed to cycle the internal state of the cryptographically secure pseudorandom number generator (CSPRNG).
                </p>
                <p>
                  Instead of generating a cryptographically secure 384-bit random private scalar $d \in [1, n-1]$, the HSM outputted the curve base generator point doubled exactly twice:
                </p>
                <div className="p-3 rounded bg-black/70 border border-zinc-800 font-mono text-emerald-400 text-center text-xs">
                  Q = 2(2G) = 4 · G (mod p) &emsp;⟹&emsp; Private Key Scalar: d = 4
                </div>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">Why is this fatal for Web PKI?</h5>
                <p>
                  In Elliptic Curve Cryptography, security relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP)—the mathematical impossibility of deriving $d$ from $Q = d \cdot G$ when $d$ is a 384-bit integer.
                </p>
                <p>
                  However, with d = 4, solving Q = d &middot; G requires only 4 point additions (derived in 0.04 ms). Because this private key belonged to an intermediate CA, any attacker with d = 4 can forge legally valid TLS certificates for <strong>any domain on the internet</strong>.
                </p>
              </div>

              <div className="p-3 rounded bg-black/40 border border-rose-900/50 text-[11px] font-mono text-rose-200">
                <span>MITIGATION: Mozilla NSS and Chromium added the intermediate certificate to OneCRL / CRLite revocation lists, preventing browsers from accepting signatures from this key.</span>
              </div>
            </div>
          )}

          {activeTopic === 'roca' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2 font-mono">
                <span className="text-sm font-bold text-sky-300">
                  ROCA: Return of Coppersmith&apos;s Attack (CVE-2017-15361)
                </span>
                <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800 text-[10px]">
                  RSA FACTORIZATION
                </span>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">Algorithmic Flaw in Infineon Chips:</h5>
                <p>
                  The ROCA attack targeted smartcards and TPMs manufactured by Infineon Technologies. To accelerate key generation, the chip enforced prime candidates of a specific algebraic structure:
                </p>
                <div className="p-3 rounded bg-black/70 border border-zinc-800 font-mono text-sky-300 text-center text-xs">
                  p = k · M + (65537^a mod M)
                </div>
                <p>
                  This dramatically reduced the entropy of the resulting RSA public modulus $N = p \cdot q$. Using Coppersmith&apos;s lattice reduction algorithm, an adversary can factor a 1024-bit modulus in under 2 hours on a laptop, and a 2048-bit modulus for under $75 in AWS compute.
                </p>
              </div>

              <div className="space-y-2 text-zinc-300 font-mono text-xs">
                <h5 className="font-semibold text-zinc-100">K9 Detection Engine:</h5>
                <p className="font-sans text-xs">
                  K9-Sentinel inspects the public RSA modulus $N$ against known ROCA fingerprint masks ($N \bmod M_i$), flagging vulnerable keys instantaneously without requiring active factoring attempts.
                </p>
              </div>
            </div>
          )}

          {activeTopic === 'homoglyph' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2 font-mono">
                <span className="text-sm font-bold text-amber-300">
                  Unicode Homoglyphs & Levenshtein Brand Defense
                </span>
                <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px]">
                  PHISHING DETECTION
                </span>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">The Punycode Substitution Attack:</h5>
                <p>
                  Internationalized Domain Names (IDNs) allow foreign alphabets in web addresses. Attackers register visually indistinguishable characters from the Cyrillic or Greek alphabets to spoof high-value targets:
                </p>
                <div className="p-3 rounded bg-black/70 border border-zinc-800 font-mono text-amber-300 text-xs space-y-1">
                  <div>Latin &apos;a&apos; (U+0061) vs. Cyrillic &apos;а&apos; (U+0430)</div>
                  <div className="text-[11px] text-zinc-400">Punycode output: <code className="text-emerald-400">xn--pypal-4ve.com</code> rendered as <code className="text-zinc-200">pаypal.com</code></div>
                </div>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">Levenshtein Distance Metric:</h5>
                <p>
                  The Levenshtein distance measures the minimum number of single-character edits (insertions, deletions, or substitutions) needed to change one string into another. When a newly registered domain exhibits a distance &le; 2 against a protected trademark while routing forms to external IP addresses, K9 flags the domain as an active brand credential harvesting impersonation.
                </p>
              </div>
            </div>
          )}

          {activeTopic === 'posture' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2 font-mono">
                <span className="text-sm font-bold text-emerald-300">
                  Transport Defense-in-Depth & Certificate Transparency
                </span>
                <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px]">
                  BEST PRACTICES
                </span>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">HTTP Strict Transport Security (RFC 6797):</h5>
                <p>
                  HSTS instructs browsers to strictly communicate over HTTPS, eliminating SSL-stripping attacks. To be fully protected, domains must use:
                </p>
                <div className="p-2.5 rounded bg-black/70 border border-zinc-800 font-mono text-emerald-400 text-xs">
                  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
                </div>
              </div>

              <div className="space-y-2 text-zinc-300">
                <h5 className="font-semibold text-zinc-100 font-mono text-xs">Certificate Transparency (CT Logs - RFC 6962):</h5>
                <p>
                  Certificate Transparency is a public, append-only Merkle tree log of all issued SSL certificates. K9 monitors public logs (e.g. Cloudflare Nimbus, Google Argon) to identify rogue intermediate certificates or sudden certificate issuance velocity spikes targeting client domains before they are deployed in live phishing campaigns.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
