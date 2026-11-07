# K9-SENTINEL Frontend

> **Defense-Grade Threat Intelligence, Cryptographic CA Auditor & Impersonation Defense Console**

Built strictly in accordance with `FRONTEND_PLAN.md` and following the high-density authoritative design language of Linear, Cloudflare, Snyk, and Datadog.

---

## Architecture Overview

```
frontend/src/
├── app/
│   ├── globals.css                # Zinc theme, custom scrollbars, subtle 1px border utilities
│   ├── layout.tsx                 # Root layout
│   └── page.tsx                   # Main orchestrator mounting all 4 screens
│
├── components/
│   ├── Navbar.tsx                 # Minimal top navigation & system status pill
│   ├── HeroScanner.tsx            # URL input bar + Quick scenario selector + Cmd+K shortcut
│   ├── PipelineVisualizer.tsx     # 4-lane parallel analysis diagram
│   ├── RiskGauge.tsx              # 0-100 Radial Threat Index gauge
│   │
│   ├── crypto/
│   │   ├── CertificateTree.tsx    # Root -> Intermediate -> Leaf visual hierarchy
│   │   ├── EmudhraAuditCard.tsx   # P-384 scalar d=4 discovery console (Bug 2083449) + ROCA
│   │   └── CTLogTimeline.tsx      # Certificate Transparency chronological feed (crt.sh)
│   │
│   ├── heuristics/
│   │   ├── TyposquattingCard.tsx  # Brand diff visualizer with Levenshtein distance
│   │   ├── FormHarvestingCard.tsx # Cross-origin form exfiltration alert
│   │   └── HeaderScorecard.tsx    # HSTS, CSP, XFO audit badges & sensitive file probes
│   │
│   ├── collaborative/
│   │   ├── ThreatRadarFeed.tsx    # Live incident stream with interactive community voting
│   │   └── STIXExportModal.tsx    # STIX 2.1 JSON inspector & download
│   │
│   └── demo/
│       └── BrowserGuardMockup.tsx # Interactive Chrome browser extension simulation
│
├── lib/
│   ├── mockData.ts                # Full, realistic mock data for all 4 scenarios
│   └── api.ts                     # Dual-mode fetch client (auto-detects FastAPI backend)
│
└── types/
    └── api.ts                     # TypeScript definitions for scan results and threat feeds
```

---

## 4 Distinct Screen Layouts

1. **Screen 1: Threat Command Center & Parallel Inspection Pipeline (The Hero)**
   - Top Bar: System armed status pill, API documentation drawer, STIX 2.1 exporter.
   - Target Scanner: Universal URL bar with global `Cmd+K` / `Ctrl+K` hotkey.
   - Preset Scenario Pills:
     - 🚨 `eMudhra Flawed CA (d=4)`
     - ⚠️ `PayPal Phishing Clone`
     - 🔒 `Insecure University Portal`
     - ✅ `Legitimate Domain (google.com)`
   - 4-Lane Parallel Pipeline: Horizontal worker status for Cryptographic Scalar Audit, Typosquatting Verification, HTTP Posture, and Threat Feeds.
   - Primary Verdict Card: SVG radial gauge (0–100 risk score), verdict badges, and executive summary.

2. **Screen 2: Cryptographic Trust & eMudhra Auditor (The Deep Differentiator)**
   - Interactive X.509 Trust Chain Hierarchy (Root CA $\rightarrow$ Intermediate Sub-CA $\rightarrow$ Leaf Cert).
   - eMudhra Flawed Key Inspector (Mozilla Bug 2083449):
     - NIST P-384 curve coordinates $Q = (x, y)$ with copy actions.
     - Generator point $G = (x, y)$.
     - Discovered private scalar $d = 4$ solved in 0.04 ms.
     - Interactive Scalar Multiplier Solver simulation button.
   - ROCA (Return of Coppersmith's Attack, CVE-2017-15361) and RSA key quality inspection.
   - Certificate Transparency (CT) Timeline with crt.sh query links and anomaly indicators.

3. **Screen 3: Phishing Heuristics & Web Application Security Posture**
   - Side-by-side Target vs. Legitimate brand domain diff.
   - Levenshtein Distance badge and Punycode homoglyph detector.
   - DOM Credential Harvesting Scanner with cross-origin POST exfiltration detection.
   - Deceptive Urgency NLP heuristics detector.
   - Web Observatory Grade (`A+` to `F`) with HSTS, CSP, X-Frame-Options checklist and sensitive file probes (`/.git/HEAD`, `/.env`).

4. **Screen 4: Collaborative Threat Radar & Live Browser Guard Simulation**
   - Live Community Incident Feed with interactive voting (`[ Confirm Phishing ]` / `[ Flag False Positive ]`) updating consensus in real-time.
   - One-click STIX 2.1 / MISP JSON viewer and download modal.
   - Authentic Browser Extension Simulator with warning interception banners, safety recovery, and extension popover toggles.

---

## Running Locally

To run the development server:

```bash
cd frontend
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser.

To create a production build:

```bash
npm run build
npm run start
```
