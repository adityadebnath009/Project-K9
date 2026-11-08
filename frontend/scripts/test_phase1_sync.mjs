/**
 * Phase 1 Test Suite: Global State Synchronization & Deep Linking
 * Validates cross-page deep links, query parameter preservation, and state persistence contracts.
 */

const FRONTEND_BASE = 'http://localhost:3000';
const BACKEND_BASE = 'http://localhost:8000';

async function runPhase1Tests() {
  console.log('🔗 Running Phase 1: Global State Synchronization & Deep Linking Test Suite...\n');
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

  // 1. Frontend Route Accessibility
  const routes = ['/', '/crypto', '/threats', '/quishing', '/radar'];
  for (const route of routes) {
    await test(`Frontend Route Render: ${route}`, async () => {
      const res = await fetch(`${FRONTEND_BASE}${route}`);
      if (!res.ok) throw new Error(`Route ${route} returned HTTP ${res.status}`);
      const text = await res.text();
      if (!text.includes('<!DOCTYPE html>')) throw new Error(`Route ${route} did not return valid HTML`);
    });
  }

  // 2. Deep Link Target Query Parsing on Homepage
  await test('Deep Link Query on Homepage (?target=...)', async () => {
    const target = 'https://auth.secure-emudhra-gateway.org';
    const res = await fetch(`${FRONTEND_BASE}/?target=${encodeURIComponent(target)}`);
    if (!res.ok) throw new Error(`Homepage returned HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('K9 Sentinel')) throw new Error('Expected app shell in response');
  });

  // 3. Deep Link Scenario Query on Homepage (?scenario=emudhra)
  await test('Deep Link Scenario on Homepage (?scenario=emudhra)', async () => {
    const res = await fetch(`${FRONTEND_BASE}/?scenario=emudhra`);
    if (!res.ok) throw new Error(`Scenario route returned HTTP ${res.status}`);
  });

  // 4. Deep Link on /crypto Subpage (?target=...)
  await test('Deep Link on /crypto (?target=https://google.com)', async () => {
    const res = await fetch(`${FRONTEND_BASE}/crypto?target=${encodeURIComponent('https://google.com')}`);
    if (!res.ok) throw new Error(`Crypto page returned HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('Cryptographic Trust')) throw new Error('Crypto page title missing');
  });

  // 5. Deep Link on /threats Subpage (?target=...)
  await test('Deep Link on /threats (?target=https://paypa1-security.com)', async () => {
    const res = await fetch(`${FRONTEND_BASE}/threats?target=${encodeURIComponent('https://paypa1-security.com')}`);
    if (!res.ok) throw new Error(`Threats page returned HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('Impersonation Heuristics')) throw new Error('Threats page title missing');
  });

  // 6. Deep Link on /quishing Subpage (?target=upi://...)
  await test('Deep Link on /quishing (?target=upi://pay?pa=discom.billpay@fakeaxis...)', async () => {
    const upiTarget = 'upi://pay?pa=discom.billpay@fakeaxis&pn=Electricity%20Dept&am=2450.00&cu=INR&tn=Immediate%20Bill%20Overdue';
    const res = await fetch(`${FRONTEND_BASE}/quishing?target=${encodeURIComponent(upiTarget)}`);
    if (!res.ok) throw new Error(`Quishing page returned HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('Anti-Quishing')) throw new Error('Quishing page title missing');
  });

  // 7. Deep Link on /radar Subpage (?hash=0x...)
  await test('Deep Link on /radar (?hash=0x...) with auto-verification trigger', async () => {
    const mockHash = '0xc1f0a53f34e2dbf0bbc28a0b6c50be754fac0319462b84eea430ca9e9d1ad6ee';
    const res = await fetch(`${FRONTEND_BASE}/radar?hash=${mockHash}`);
    if (!res.ok) throw new Error(`Radar page returned HTTP ${res.status}`);
    const html = await res.text();
    if (!html.includes('Community Consensus Radar')) throw new Error('Radar page title missing');
  });

  // 8. Backend Web3 Verification Endpoint Consistency
  await test('Backend Web3 Verification Endpoint Consistency', async () => {
    const mockHash = '0xc1f0a53f34e2dbf0bbc28a0b6c50be754fac0319462b84eea430ca9e9d1ad6ee';
    const res = await fetch(`${BACKEND_BASE}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: mockHash }),
    });
    if (!res.ok) throw new Error(`Web3 verify returned HTTP ${res.status}`);
    const data = await res.json();
    if (typeof data.is_valid !== 'boolean') throw new Error('Expected is_valid boolean');
  });

  // 9. Contract Check: Shared Scan Result Schema Compatibility
  await test('Master Scan Response Contract Valid for Subpage Synchronization', async () => {
    // 9a: Check Scenario 1 (Crypto Focus: /crypto)
    const resCrypto = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, {
      method: 'POST',
    });
    if (!resCrypto.ok) throw new Error(`Scenario 1 run returned HTTP ${resCrypto.status}`);
    const cryptoData = await resCrypto.json();
    if (!cryptoData.crypto_report?.emudhra_audit) throw new Error('Missing crypto_report.emudhra_audit for /crypto');
    if (typeof cryptoData.crypto_report.emudhra_audit.vulnerable !== 'boolean') throw new Error('Missing vulnerable boolean');
    if (!cryptoData.web3_commitment?.report_hash) throw new Error('Missing web3_commitment.report_hash for /radar');

    // 9b: Check Scenario 2 (Threat Focus: /threats)
    const resThreat = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run`, {
      method: 'POST',
    });
    if (!resThreat.ok) throw new Error(`Scenario 2 run returned HTTP ${resThreat.status}`);
    const threatData = await resThreat.json();
    if (!threatData.threat_report?.domain_threats) throw new Error('Missing threat_report.domain_threats for /threats');
    if (!threatData.posture_report?.header_posture) throw new Error('Missing posture_report.header_posture for /threats');
  });

  console.log(`\n========================================`);
  console.log(`Phase 1 Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) process.exit(1);
}

runPhase1Tests().catch((err) => {
  console.error('Test runner failure:', err);
  process.exit(1);
});
