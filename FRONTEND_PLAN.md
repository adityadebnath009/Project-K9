# Concrete Frontend Architecture & Execution Plan

**Target Aesthetic:** Linear / Cloudflare / Snyk / Datadog (High-density, authoritative, zero cyberpunk/neon slop).  
**Design Standard:** Strict adherence to `taste-skill` (`design-taste-frontend` v2.5.0).  
**Owner:** Member 3 (Frontend & UI/UX Lead).

---

## 1. Visual Design System & Design Tokens

### Color Palette (Subdued, Functional, Authoritative)
No neon glowing borders or matrix greens. We use a grounded neutral zinc base with functional status accents:

| Token | Hex Value | Usage |
| :--- | :--- | :--- |
| **Ground (Background)** | `#09090b` (zinc-950) | Full page viewport ground |
| **Surface (Cards/Panels)** | `#121215` / `#18181b` (zinc-900) | Bento panels, app-frame container |
| **Subtle Border** | `#27272a` (zinc-800) | 1px clean borders for cards and inputs |
| **Border Active / Hover**| `#3f3f46` (zinc-700) | Subtle 1-2px lift and crisp boundary |
| **Primary Typography** | `#f4f4f5` (zinc-100) | Headlines, primary metrics |
| **Muted Typography** | `#71717a` (zinc-500) | Labels, descriptions, timestamps |
| **Status Safe / Valid** | `#10b981` (emerald-500) | Valid X.509 chain, clean domain, safe pass |
| **Status Warning** | `#f59e0b` (amber-500) | Missing HSTS/CSP, untrusted root, self-signed |
| **Status Critical Threat**| `#e11d48` (rose-600) | eMudhra weak scalar key ($d=4$), phishing clone |
| **Status Informational** | `#0284c7` (sky-600) | CT log entries, STIX identifiers, DNS records |

### Typography
* **UI Interface Font:** Geist Sans / Inter (`font-sans`), tight tracking (`tracking-tight`).
* **Cryptographic & Code Data:** Geist Mono / JetBrains Mono (`font-mono`) for public keys, modulus, scalar integers, PEM certs, SHA-256 fingerprints, and DNS records.

### Micro-Interactions (Rule 5 of `taste-skill`)
* Cards lift **1–2px** on hover with a crisp border highlight (`hover:border-zinc-700 transition-all duration-200`).
* Buttons have physical click states: `active:scale-[0.98]`.
* Zero cartoon bounce animations, zero auto-spinning carousels.

---

## 2. Screen-by-Screen Layout (Bento Grid Architecture)

Following the rule **"One section per screen at 1440x900 viewport"**, the application has 4 distinct, cohesive screens:

```
+-----------------------------------------------------------------------------------------+
|                                    APPLICATION MAP                                      |
+-----------------------------------------------------------------------------------------+
|  SCREEN 1: The Threat Command Center & Parallel Inspection Pipeline (The Hero)          |
|  SCREEN 2: The Cryptographic Trust & eMudhra Auditor (The Deep Differentiator)          |
|  SCREEN 3: Phishing Heuristics & Web Application Security Posture                       |
|  SCREEN 4: Collaborative Threat Intelligence Radar & Live Browser Guard Simulation     |
+-----------------------------------------------------------------------------------------+
```

---

### Screen 1: The Command Console & Parallel Inspection Pipeline (The Hero)

* **Top Bar:** 
  - Logo: `K9-SENTINEL` (monospaced badge `v1.0.4-PROD`).
  - Real-time indicator: `SYSTEM: ARMED` (subtle emerald dot).
  - Quick action: `Export STIX 2.1` and `View API Docs`.
* **Universal Target Scanner Input:**
  - High-precision URL bar with placeholder: `Enter target URL or domain (e.g., https://secure-bank.example.com)...`
  - Deep Scan action button with instantaneous hotkey (`Enter` or `Cmd+K`).
* **Preset Scenario Pills (Crucial for Live Demos):**
  - Pill 1: `🚨 eMudhra Flawed CA (d=4)`
  - Pill 2: `⚠️ PayPal Phishing Clone`
  - Pill 3: `🔒 Insecure University Portal`
  - Pill 4: `✅ Legitimate Domain (google.com)`
* **The Inspection Pipeline (Based on `lanes` layout from `taste-skill`):**
  An interactive horizontal diagram showing the target domain entering a central dispatcher and feeding 4 parallel lanes:
  - *Lane 1:* Cryptographic Scalar & Chain Audit
  - *Lane 2:* Typosquatting & Homograph Verification
  - *Lane 3:* HTTP Security Posture Audit
  - *Lane 4:* Collaborative Threat Feeds
* **Primary Threat Verdict Card:**
  - Radial / Circular Score Gauge (0–100 Risk Score).
  - Decisive Status Badge: `CRITICAL THREAT` / `SUSPICIOUS` / `VERIFIED SAFE`.
  - Executive summary line (e.g., *"Immediate impersonation detected: Rogue intermediate CA certificate with trivially small private scalar d=4."*).

---

### Screen 2: The Cryptographic Trust & eMudhra Auditor (The Judge Magnet)

This screen proves mathematical depth and avoids AI slop by displaying real cryptographic primitives:

* **Interactive X.509 Trust Chain Hierarchy:**
  - Root CA (e.g. `Global Root Authority`) $\rightarrow$
  - Intermediate CA (Highlighted with an amber/red warning border: `eMudhra Sub-CA`) $\rightarrow$
  - Leaf Domain Certificate (`*.target-bank.com`).
* **The eMudhra Flawed Key Inspector (Bug 2083449):**
  - **Curve Details:** NIST P-384 / P-256.
  - **Public Point Coordinates:** $Q = (x, y)$ rendered in crisp monospaced blocks with copy button.
  - **Scalar Verification Metric:** Candidate scalar test $Q' = d \cdot G$.
  - **Discovered Private Scalar:** `d = 4` (Highlighted in ruby text: *"CRITICAL: Low-entropy private key derived in 0.04 ms"*).
* **ROCA & RSA Key Quality Audit:**
  - Key Length: `2048-bit` / `4096-bit` / `1024-bit (FAIL)`.
  - ROCA Vulnerability Check: Pass / Fail.
  - Signature Algorithm: SHA-256 with RSA (flags deprecated SHA-1/MD5).
* **Certificate Transparency (CT) Timeline:**
  - Chronological list of certificates issued for this domain logged on public CT logs (crt.sh).
  - Highlights sudden re-issuances or unauthorized certificate velocity.

---

### Screen 3: Phishing Heuristics & Application Security Posture

* **Left Panel: Phishing & Impersonation Heuristics (2/3 width):**
  - **Typosquatting & Homograph Comparison:**
    - Target Domain vs. Legitimate Domain side-by-side (`paypa1.com` vs `paypal.com`).
    - Levenshtein Distance Badge: `Distance: 1 (Targeting PayPal Inc.)`.
    - Punycode / Cyrillic Homograph Flag (e.g. `xn--...` substituting `а` for `a`).
  - **DOM Credential Harvesting Scanner:**
    - Password / Card input detection badge.
    - Form Action Audit: Flags cross-origin exfiltration (e.g. Form on `domainA.com` posts credentials to `evil-drop.net/steal.php`).
  - **Deceptive Urgency NLP Heuristics:**
    - Flags keywords detected in DOM: *"Urgent KYC Verification"*, *"Account Suspended within 24h"*.
* **Right Panel: Web Application Security Posture (1/3 width):**
  - Security Headers Grade: `A+`, `A`, `B`, `C`, `F`.
  - Checklist of critical headers:
    - `Strict-Transport-Security` (HSTS)
    - `Content-Security-Policy` (CSP)
    - `X-Frame-Options` (Clickjacking defense)
    - `X-Content-Type-Options: nosniff`
  - Exposed Sensitive Files Probe:
    - Status for `/.git/HEAD`, `/.env`, `/wp-config.php.bak`, `/swagger.json`.

---

### Screen 4: Collaborative Threat Intelligence & Browser Guard Demo

* **Collaborative Threat Radar (Live Community Feed):**
  - Real-time stream of recently submitted suspicious links.
  - Interactive Community Voting:
    - `[ Confirm Phishing ]` (+1 Reputation)
    - `[ Flag False Positive ]` (-1 Reputation)
  - Community Consensus Bar (e.g. 94% Consensus based on 28 security researcher votes).
  - One-click **STIX 2.1 / MISP JSON Export** button for enterprise SIEM ingestion.
* **Interactive Browser Extension Simulator:**
  - An authentic browser window mockup (URL bar, navigation buttons, viewport).
  - Displays what the user sees when navigating to a flagged malicious site:
    - A crisp, urgent warning banner: *"K9-Sentinel Shield: Navigation Intercepted"*.
    - Details: *"This site impersonates PayPal and uses an insecure eMudhra TLS certificate."*
    - Actions: `[ Go Back to Safety ]` or `[ Proceed at Own Risk ]`.

---

## 3. Frontend Component Structure (`frontend/src/`)

```
frontend/src/
├── app/
│   ├── globals.css                # Zinc theme, custom scrollbars, subtle 1px border utilities
│   ├── layout.tsx                 # Root layout with Geist/Inter font
│   └── page.tsx                   # Main orchestrator mounting the 4 screens
│
├── components/
│   ├── Navbar.tsx                 # Minimal top navigation & system status pill
│   ├── HeroScanner.tsx            # URL input bar + Quick scenario selector
│   ├── PipelineVisualizer.tsx     # 4-lane parallel analysis diagram (taste-skill spec)
│   ├── RiskGauge.tsx              # 0-100 Radial Threat Index gauge
│   │
│   ├── crypto/
│   │   ├── CertificateTree.tsx    # Root -> Intermediate -> Leaf visual hierarchy
│   │   ├── EmudhraAuditCard.tsx   # P-384 scalar d=4 discovery console
│   │   └── CTLogTimeline.tsx      # Certificate Transparency chronological feed
│   │
│   ├── heuristics/
│   │   ├── TyposquattingCard.tsx  # Brand diff visualizer with Levenshtein distance
│   │   ├── FormHarvestingCard.tsx # Cross-origin form exfiltration alert
│   │   └── HeaderScorecard.tsx    # HSTS, CSP, XFO audit badges
│   │
│   ├── collaborative/
│   │   ├── ThreatRadarFeed.tsx    # Live incident stream with upvote/downvote
│   │   └── STIXExportModal.tsx    # STIX 2.1 JSON inspector & download
│   │
│   └── demo/
│       └── BrowserGuardMockup.tsx # Interactive Chrome browser extension simulation
│
├── lib/
│   ├── mockData.ts                # Full, realistic mock data for all 4 scenarios
│   └── api.ts                     # Fetch client to connect to FastAPI backend
│
└── types/
    └── api.ts                     # TypeScript definitions for scan results and threat feeds
```

---

## 4. Execution Roadmap for Member 3

| Step | Time | Task | Deliverable |
| :--- | :--- | :--- | :--- |
| **Step 1** | Hour 1 | Initialize Next.js 15, install Lucide icons & Tailwind, configure zinc theme | Clean working dev server at `localhost:3000` |
| **Step 2** | Hour 2 | Build `Navbar.tsx`, `HeroScanner.tsx`, and `RiskGauge.tsx` with preset scenario buttons | Screen 1 fully interactive with toggleable presets |
| **Step 3** | Hour 3 | Build `CertificateTree.tsx` and `EmudhraAuditCard.tsx` (the eMudhra inspector) | Screen 2 showing X.509 chain and scalar $d=4$ alert |
| **Step 4** | Hour 4 | Build `TyposquattingCard.tsx`, `FormHarvestingCard.tsx`, and `HeaderScorecard.tsx` | Screen 3 displaying heuristics and security posture |
| **Step 5** | Hour 5 | Build `ThreatRadarFeed.tsx` (voting buttons) and `BrowserGuardMockup.tsx` | Screen 4 collaborative feed and extension demo |
| **Step 6** | Hour 6 | Connect `lib/api.ts` to backend REST endpoints; run `npm run build` to verify zero errors | Production-ready frontend ready for Vercel deployment |

---

## 5. Ready-to-Use Mock Data for Member 3
Member 3 does NOT need to wait for backend deployment to start building. The 4 demo scenarios are pre-defined:
1. `SCENARIO_EMUDHRA`: Fails cryptographic test (P-384, scalar $d=4$, intermediate revoked in OneCRL).
2. `SCENARIO_PAYPAL_PHISH`: Fails brand check (`paypa1-secure-login.com`, harvesting password to foreign IP).
3. `SCENARIO_INSECURE_APP`: Missing HSTS/CSP, exposed `/.git/HEAD`.
4. `SCENARIO_CLEAN_GOOGLE`: 100% clean, valid Google Trust Services CA, Grade A+ headers.
