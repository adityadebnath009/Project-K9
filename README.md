# K9-Sentinel 🛡️

> AI-Powered Web Threat Detection, Cryptographic Trust & Decentralized Intelligence Engine  
> **Hack Matrix 2026 – Hacktober** | Built by **Team Mavericks**

K9-Sentinel is an enterprise-grade digital trust intelligence platform that bridges the gap between surface-level phishing heuristics, AI intent analysis, and underlying cryptographic trust infrastructure vulnerabilities (specifically addressing the real-world **eMudhra TLS Certificate incident – Mozilla Bug 2083449**).

---

## 🚀 Core Capabilities

1. **Deterministic Cryptographic Trust Auditor (Phase 1):**
   - Detects low-entropy private keys via Wayne's small-scalar discrete log recovery ($d \le 1000$) on NIST P-256 / P-384 / secp256k1 curves (<1ms).
   - Verifies against Mozilla OneCRL blocklist SHA-256 fingerprints.
   - Audits RSA key lengths ($<2048$-bit), ROCA patterns, and deprecated signature algorithms (SHA-1).
   - Live port 443 TLS handshake validation and public Certificate Transparency (`crt.sh`) queries.

2. **Intelligent Threat & Impersonation Heuristics (Phase 2):**
   - Levenshtein distance typosquatting and Cyrillic Punycode homographs (`xn--`) against 5,000+ top financial and telecom brands.
   - Live DOM inspection for cross-origin credential harvesting forms and evasive obfuscated JavaScript (`eval(unescape(...))`).
   - Coercive urgency NLP patterns (mandatory KYC, SIM block, utility cutoff).

3. **Web Security Posture Scanner (Phase 3):**
   - 100-point security header scorecard (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) grading from **A+ to F**.
   - SSRF-safe passive exposed secrets probing (`/.env`, `/.git/HEAD`, `/swagger.json`).

4. **AI Scam Intent & MITRE ATT&CK Analyst (Phase 4):**
   - High-fidelity IOC extractor (URLs, Indian mobile numbers, UPI handles, and TRAI SMS headers).
   - Powered by **Groq Llama 3.3 / GPT-OSS 120B** with full Pydantic structured output.
   - Seamless offline fallback to a rule-based expert system with zero external API dependencies.
   - Maps threats to standard MITRE techniques: `T1566.002`, `T1598.002`, `T1657`, `T1584`, `T1204.001`.

5. **Web3 Decentralized Threat Intelligence Registry (Phase 5):**
   - Smart contract [`ThreatRegistry.sol`](backend/engine/web3/ThreatRegistry.sol) storing `keccak256` cryptographic commitments on-chain.
   - **GDPR Privacy Architecture**: Raw URLs, messages, and user PII remain strictly off-chain.
   - Embedded local `py-evm` execution engine: runs 100% locally with zero external RPC/testnet dependencies, with optional Sepolia support.

6. **Threat Feeds & Multi-Report Campaign Correlation (Phase 6):**
   - Asynchronously queries **abuse.ch URLhaus** with curated offline blacklists.
   - Clusters threats into active cybercrime campaigns: *Operation BlueKite* (Banking KYC), *Operation VoltCut* (Power Disconnection), *Operation QuickLure* (Evasive Shortlinks), *Operation CryptoDrain* (Web3 Phishing).

7. **FastAPI Endpoints & Mandatory Benchmarks (Phase 7):**
   - Unified `POST /api/v1/scan` returning the complete `MasterScanResponse`.
   - Pre-configured evaluation cases: **3 suspicious/malicious** (eMudhra weak key, PayPal harvest, SBI KYC scam) and **3 benign** (Python.org, Airtel Xstream, Google).
   - STIX 2.1 threat telemetry export.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.14.7 + FastAPI + `uvicorn`
- **Package Manager:** `uv`
- **Cryptography & Trust:** `cryptography`, `pyOpenSSL`, `eth-hash`, `pycryptodome`
- **AI & LLM:** `langchain-groq`, `langchain-core` (Llama 3.3 70B / GPT-OSS 120B)
- **Web3 & Blockchain:** Solidity 0.8.20 (`ThreatRegistry.sol`), `web3.py` v8.0, `py-evm`, `eth-tester`
- **Testing:** `pytest` (**120 automated unit and integration tests passing**)

---

## ⚡ Quickstart

### 1. Run the Complete Test Suite (120 Tests)
```bash
cd backend
uv run pytest -v
```

### 2. Launch the FastAPI Backend Server
```bash
cd backend
uv run uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- System Health Check: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- Benchmark Scenarios Catalog: [http://127.0.0.1:8000/api/v1/scenarios](http://127.0.0.1:8000/api/v1/scenarios)
- STIX 2.1 Threat Telemetry: [http://127.0.0.1:8000/api/v1/threats/stix](http://127.0.0.1:8000/api/v1/threats/stix)

---

## 🧪 Test Results
```bash
tests/test_ai_analyst.py ... 20 PASSED [100%]
tests/test_api.py .......... 15 PASSED [100%]
tests/test_crypto.py ....... 25 PASSED [100%]
tests/test_intel.py ........ 20 PASSED [100%]
tests/test_posture.py ......  7 PASSED [100%]
tests/test_threat.py ....... 13 PASSED [100%]
tests/test_web3.py ......... 20 PASSED [100%]
======================= 120 passed in 45.70s =======================
```
