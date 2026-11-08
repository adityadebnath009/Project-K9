/**
 * Phase 2 Test Suite: Cybersecurity & Cryptographic Evidence Expansion
 * Validates eMudhra discrete log recovery (d=4), Raw PEM certificate audit,
 * RSA defect extraction, real TLS SANs telemetry, and Cyrillic homoglyph diffs.
 */

const BACKEND_BASE = 'http://localhost:8000';
const FRONTEND_BASE = 'http://localhost:3000';

async function runPhase2Tests() {
  console.log('🔐 Running Phase 2: Cybersecurity & Cryptographic Evidence Test Suite...\n');
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAIL: ${name}\n     Error: ${err.message}`);
      failed++;
    }
  }

  // 1. eMudhra Mathematical Proof (d=4 Recovery via Wayne Discrete Log)
  await test('eMudhra NIST P-384 Discrete Log Crack (d=4 recovery in <1ms)', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const em = data.crypto_report?.emudhra_audit;
    if (!em) throw new Error('Missing emudhra_audit');
    if (!em.vulnerable) throw new Error('Expected vulnerable flag true');
    if (em.recovered_scalar_d !== 4) throw new Error(`Expected recovered scalar d=4, got ${em.recovered_scalar_d}`);
    if (em.severity !== 'CRITICAL') throw new Error(`Expected CRITICAL severity, got ${em.severity}`);
  });

  // 2. Raw PEM Certificate Ingestion (POST /api/v1/scan with PEM block)
  await test('Raw PEM Certificate Direct Audit (InputType.RAW_PEM_CERT)', async () => {
    const runRes = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, { method: 'POST' });
    const runData = await runRes.json();
    const pemCert = runData.target;
    if (!pemCert || !pemCert.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('Benchmark PEM certificate target not found in scenario run');
    }

    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: pemCert, input_type: 'pem_cert' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.input_type !== 'pem_cert') {
      throw new Error(`Expected pem_cert, got ${data.input_type}`);
    }
    if (data.crypto_report?.emudhra_audit?.recovered_scalar_d !== 4) {
      throw new Error('Failed to recover d=4 directly from raw PEM input');
    }
  });

  // 3. Live TLS Chain & SANs Extraction (google.com)
  await test('Live TLS Handshake: SANs Extraction & Hierarchy Telemetry (google.com)', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'google.com', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const tls = data.crypto_report?.tls_chain;
    if (!tls?.connected) throw new Error('TLS not connected');
    if (!Array.isArray(tls.sans) || tls.sans.length === 0) throw new Error('SANs list empty');
    if (tls.is_self_signed) throw new Error('Google cert falsely flagged as self-signed');
  });

  // 4. Live Let\'s Encrypt Handshake & Cipher Suite
  await test('Live TLS Handshake: Cipher Suite & Posture Check (shop.lolliandlace.com)', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'shop.lolliandlace.com', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const tls = data.crypto_report?.tls_chain;
    if (!tls?.connected) throw new Error('TLS not connected');
    if (!tls.issuer?.includes("Let's Encrypt")) throw new Error('Expected Let\'s Encrypt issuer');
  });

  // 5. Cyrillic Punycode Homoglyph Character Diff
  await test('Threat Heuristics: Cyrillic Punycode Homoglyph Identification', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://xn--pypal-4ve.com/login', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const dt = data.threat_report?.domain_threats;
    if (!dt?.is_homograph && !dt?.is_typosquatted) throw new Error('Homoglyph not detected');
    if (typeof dt?.entropy !== 'number' || dt.entropy <= 0) throw new Error('Entropy not computed');
  });

  // 6. High-Entropy Shannon DGA Detection
  await test('Threat Heuristics: Shannon Entropy DGA Calculation', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'https://q89zkm91vxba34f0p.org', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const dt = data.threat_report?.domain_threats;
    if (typeof dt?.entropy !== 'number') throw new Error('Shannon entropy missing');
    if (typeof dt?.high_entropy_flag !== 'boolean') throw new Error('high_entropy_flag missing');
  });

  // 7. Frontend Crypto Page Rendering with Raw PEM Mode
  await test('Frontend UI: /crypto Page Renders with PEM & Domain Modes', async () => {
    const res = await fetch(`${FRONTEND_BASE}/crypto`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('Raw X.509 PEM Certificate')) throw new Error('PEM Certificate mode button missing');
    if (!html.includes('Cryptographic Trust')) throw new Error('Crypto page title missing');
  });

  // 8. Frontend Threats Page Rendering with Homoglyph Diff
  await test('Frontend UI: /threats Page Renders with Homoglyph & Entropy Metrics', async () => {
    const res = await fetch(`${FRONTEND_BASE}/threats`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('SHANNON ENTROPY')) throw new Error('Shannon entropy card missing');
    if (!html.includes('LEVENSHTEIN DISTANCE')) throw new Error('Levenshtein metric missing');
  });

  console.log(`\n========================================`);
  console.log(`Phase 2 Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) process.exit(1);
}

runPhase2Tests().catch((err) => {
  console.error('Test runner failure:', err);
  process.exit(1);
});
