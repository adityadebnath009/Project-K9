# Member 3 Guide: Frontend Engineering & Anti-Slop UI/UX

This guide is for the **Frontend & UI/UX Lead (Member 3)**. It covers how to set up the frontend environment, install and follow the anti-slop design skill, and build a high-density, authoritative security platform that looks like a product built by Stripe, Cloudflare, or Linear—not a generic hackathon project.

---

## 1. What is "AI Slop" and Why Cyberpunk/Neon is Banned

Most AI-generated and beginner hackathon security tools make the same mistakes:
* **The "Cyberpunk / Neon Matrix" Trap (BANNED):** Glowing neon green text, intense purple/cyan blurred background orbs, matrix digital rain, "HACKER / CYBER" decals. It screams amateur and fake.
* **The "3-Card Marketing Cliché" (BANNED):** Centered title, generic subtitle, and 3 identical rounded cards with SVG icons claiming "Fast", "Secure", "Reliable".
* **Fake/Simulated Fluff:** Empty charts, meaningless progress bars, and fake numbers that don't reflect actual cryptographic or network realities.

### The Real Standard: Linear / Cloudflare / Figma / Snyk
Enterprise security tools are **high-density, sober, and authoritative**:
1. **Neutral, Grounded Palette:** 
   - Backgrounds: Deep neutral zinc/slate (`#09090b`, `#121215`, `#18181b`).
   - Borders: Subtle 1px lines (`#27272a`, `#3f3f46`), never glowing neon strokes.
   - Accents: Functional status colors only (muted emerald for valid, amber for warning, crimson/ruby for critical threat, steel blue for information).
2. **Typography First:**
   - Interface: Clean modern sans-serif (Inter, Geist, or system SF Pro).
   - Cryptographic / Network Data: Crisp monospaced font (Geist Mono, JetBrains Mono) for hashes, PEM certificates, scalar integers, and DNS records.
3. **Real Product UI:**
   - Display real data: ASN.1 certificate trees, HTTP response headers, exact mathematical scalar checks ($d = 4$), and real URL entropy metrics.

---

## 2. How to Install and Run `taste-skill`

The repository already has `design-taste-frontend` installed in:
```
.agents/skills/design-taste-frontend/
```

### If Member 3 is working locally with an AI agent (Claude Code, Cursor, Codex, Antigravity):
Run this in the terminal:
```bash
# Add skill globally to their agent environment
npx skills add Leonxlnx/taste-skill
```
Or simply point their AI editor to the instructions in:
`.agents/skills/design-taste-frontend/SKILL.md`

### Core Rules from `taste-skill` to Follow:
1. **One Section Per Screen:** At 1440x900 desktop viewport, the primary scan console and result inspector fill the screen cleanly—no awkward half-sections peeking in.
2. **Equal Edges:** Consistent left and right padding (`max-w-7xl mx-auto px-6` or `px-8`).
3. **Quiet Micro-Interactions:** 
   - Interactive cards lift by 1–2px on hover with a crisp border highlight (`border-zinc-700`).
   - Buttons have physical step/press states (active state scales slightly down: `active:scale-[0.98]`).
   - No bouncy cartoon animations or spinning carousels.

---

## 3. Recommended Frontend Tech Stack

* **Framework:** Next.js 15 (App Router, React 19, TypeScript)
* **Styling:** Tailwind CSS
* **Icons:** `lucide-react` (clean, thin-line stroke icons—never cartoonish emojis)
* **Components / Primitives:** Radix UI / shadcn-ui patterns (subdued, accessible)
* **Visualization:** Simple SVG / Recharts for the Risk Gauge and Certificate Hierarchy Tree

---

## 4. Key Components to Build

```
frontend/src/
├── app/
│   ├── layout.tsx             # Root layout with Geist/Inter font and dark zinc ground
│   └── page.tsx               # Main SOC Command Dashboard
├── components/
│   ├── Header.tsx             # Subdued top navigation: Brand, system status, API docs link
│   ├── ScanInput.tsx          # Single-line URL input bar + Quick demo scenario pills
│   ├── RiskScorecard.tsx      # High-density summary: Threat level, Trust score, Verdict
│   ├── CertificateTree.tsx    # X.509 Trust Visualizer (Root -> Intermediate -> Leaf)
│   ├── CryptoAuditPanel.tsx   # Detailed eMudhra (Bug 2083449) & ROCA mathematical results
│   ├── ThreatHeuristics.tsx   # Typosquatting, DOM form harvesting, and urgency flags
│   ├── WebPostureCard.tsx     # HTTP Security Headers (HSTS, CSP, XFO) scorecard
│   ├── ThreatRadar.tsx        # Live collaborative feed of community-submitted malicious links
│   └── ExtensionPreviewModal.tsx # Clean browser viewport mockup demonstrating real-time protection
└── types/
    └── api.ts                 # TypeScript types matching the backend FastAPI responses
```

---

## 5. UI Layout: Bento-Grid Architecture

Instead of a generic stacked page, organize the inspection results in an authoritative **Bento-Grid layout**:

```
+-----------------------------------------------------------------------------------+
|  [Header] K9-SENTINEL  |  ENGINE: ONLINE  |  API v1  |  COLLABORATIVE INTEL: 1,420 IOCs|
+-----------------------------------------------------------------------------------+
|  [Scan Bar] [ https://target-domain.com                             ] [ DEEP SCAN ]|
|  Quick Presets: [ eMudhra Flawed CA ]  [ PayPal Phishing ]  [ Insecure App ]  [ Google ] |
+-----------------------------------------------------------------------------------+
|  RESULTS GRID (Displayed after scan completes)                                    |
|                                                                                   |
|  +-----------------------------+  +--------------------------------------------+  |
|  | OVERALL VERDICT & RISK      |  | CRYPTOGRAPHIC TRUST INSPECTOR (eMudhra)    |  |
|  | Score: 94 / 100 (CRITICAL)  |  | Root: Self-Signed Root -> Intermediate     |  |
|  | Typosquatting: MATCH        |  | Curve: NIST P-384                          |  |
|  | Cross-Origin Forms: YES     |  | Scalar d: 4 (CRITICAL COMPROMISE DETECTED) |  |
|  | Cert Status: REVOKED        |  | Recovery: Private key derived in 0.04ms    |  |
|  +-----------------------------+  +--------------------------------------------+  |
|                                                                                   |
|  +-----------------------------+  +--------------------------------------------+  |
|  | APPLICATION POSTURE SCORE   |  | COLLABORATIVE RADAR & COMMUNITY VERDICT    |  |
|  | HSTS: Missing               |  | Community Reports: 18                      |  |
|  | CSP: None                   |  | Consensus: 96% Malicious Phishing          |  |
|  | Exposed: /.git/HEAD (200)   |  | [ Verify Phishing ]  [ Report Safe ]       |  |
|  +-----------------------------+  +--------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 6. TypeScript Interface for Backend Integration (`types/api.ts`)

Share this type file with Member 3 so frontend and backend develop in parallel without blocking each other:

```typescript
export interface ScanResult {
  target_url: string;
  domain: string;
  timestamp: string;
  threat_score: number; // 0 to 100
  verdict: 'SAFE' | 'SUSPICIOUS' | 'CRITICAL';
  
  // Pillar 1: Cryptographic Trust (eMudhra & TLS)
  crypto_audit: {
    certificate_found: boolean;
    subject_cn: string;
    issuer_org: string;
    valid_from: string;
    valid_to: string;
    signature_algorithm: string;
    key_type: string;
    key_size: number;
    emudhra_vulnerability: {
      vulnerable: boolean;
      curve?: string;
      recovered_scalar_d?: number;
      discovery_method?: string;
      description?: string;
    };
    roca_vulnerability: {
      vulnerable: boolean;
      modulus_bits?: number;
    };
    trust_chain: Array<{
      depth: number;
      subject: string;
      issuer: string;
      is_trusted_root: boolean;
    }>;
  };

  // Pillar 2: Phishing & Content Heuristics
  phishing_analysis: {
    is_phishing: boolean;
    typosquatted_brand?: string;
    levenshtein_distance?: number;
    is_homograph: boolean;
    punycode?: string;
    credential_harvesting_forms: number;
    cross_origin_submission: boolean;
    suspicious_keywords_found: string[];
  };

  // Pillar 3: Web Security Posture
  web_posture: {
    posture_score: string; // A+, A, B, C, F
    headers: {
      hsts_enabled: boolean;
      csp_enabled: boolean;
      x_frame_options: string | null;
      x_content_type_options: boolean;
    };
    exposed_endpoints: Array<{
      path: string;
      status_code: number;
      risk: 'CRITICAL' | 'HIGH' | 'LOW';
    }>;
  };
}
```

---

## 7. Next Steps for Member 3

1. Initialize the frontend folder:
   ```bash
   npx create-next-app@latest frontend --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
   cd frontend
   npm install lucide-react clsx tailwind-merge
   ```
2. Set up the neutral zinc theme in `globals.css` and `tailwind.config.ts`.
3. Build the core components using the mockup data matching `types/api.ts`.
