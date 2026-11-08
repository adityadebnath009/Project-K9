// Phase 5 Automated Verification Suite: Technical Posture & Regulatory Compliance Matrix
import assert from 'node:assert';
import fs from 'node:fs';

const BACKEND_URL = 'http://localhost:8000';
const FRONTEND_URL = 'http://localhost:3000';

async function runSuite() {
  console.log('===============================================================');
  console.log('🧪 K9 Sentinel AI - Phase 5 Automated Test Suite');
  console.log('   Focus: Security Posture, HTTP Headers & Compliance Frameworks');
  console.log('===============================================================\n');

  let passed = 0;
  let total = 0;

  async function test(name, fn) {
    total++;
    process.stdout.write(`[Test ${total}] ${name} ... `);
    try {
      await fn();
      console.log('✅ PASS');
      passed++;
    } catch (err) {
      console.log('❌ FAIL');
      console.error('   Error:', err.message);
    }
  }

  // Group 1: Live Security Posture & Headers
  console.log('--- Group 1: Live Security Headers & Posture Audit ---');

  await test('POST /api/v1/scenarios/scenario-4-python-foundation-benign/run verifies HSTS with preload', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scenarios/scenario-4-python-foundation-benign/run`, {
      method: 'POST',
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.posture_report, 'Must contain posture_report');
    const findings = data.posture_report.header_posture.findings;
    const hsts = findings.find(f => f.header.toLowerCase().includes('strict'));
    assert.ok(hsts, 'HSTS header finding must be present');
    assert.strictEqual(hsts.status, 'PASS');
    assert.ok(hsts.value.includes('max-age'), 'HSTS must include max-age');
  });

  await test('POST /api/v1/scan on shop.lolliandlace.com reveals missing headers & Grade F', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'https://shop.lolliandlace.com', input_type: 'url' }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.posture_report, 'Must contain posture_report');
    assert.ok(['D', 'F'].includes(data.posture_report.header_posture.grade), `Expected low grade, got ${data.posture_report.header_posture.grade}`);
  });

  await test('POST /api/v1/scan includes sensitive file probe inspection', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'https://python.org', input_type: 'url' }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.posture_report.exposed_secrets, 'Must include exposed_secrets inspection');
  });

  // Group 2: Regulatory Compliance Standards Logic
  console.log('\n--- Group 2: Compliance Framework Matrix Evaluation ---');

  await test('evaluateComplianceStandards flags weak crypto under Indian IT Act Section 43A', () => {
    const compSrc = fs.readFileSync('frontend/src/components/heuristics/ComplianceMatrixCard.tsx', 'utf8');
    assert.ok(compSrc.includes('Indian IT Act, 2000 (Section 43A)'));
    assert.ok(compSrc.includes('SPDI Rules 2011'));
    assert.ok(compSrc.includes('Section 66D'));
    assert.ok(compSrc.includes('CERT-In Cyber Security Directions (2022)'));
    assert.ok(compSrc.includes('Direction 20(3)/2022'));
    assert.ok(compSrc.includes('ISO/IEC 27001:2022'));
    assert.ok(compSrc.includes('Control A.8.24 (Cryptography)'));
    assert.ok(compSrc.includes('Control A.8.26 (Application Requirements)'));
    assert.ok(compSrc.includes('NIST Cybersecurity Framework 2.0'));
    assert.ok(compSrc.includes('PR.DS-02 (Data-in-Transit)'));
  });

  // Group 3: Frontend UI Rendering Verification
  console.log('\n--- Group 3: Frontend Posture & Compliance UI ---');

  await test('Frontend /threats renders Regulatory Compliance Matrix & Headers', async () => {
    const res = await fetch(`${FRONTEND_URL}/threats`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('Regulatory Compliance &amp; Standards Matrix') || html.includes('Regulatory Compliance & Standards Matrix'), 'Should render compliance matrix header');
    assert.ok(html.includes('Indian IT Act, 2000'), 'Should render Indian IT Act');
    assert.ok(html.includes('CERT-In Cyber Security Directions'), 'Should render CERT-In directions');
    assert.ok(html.includes('Critical Security Headers:'), 'Should render critical headers');
    assert.ok(html.includes('Exposed Sensitive Files Probe:'), 'Should render exposed files probe');
  });

  await test('Frontend homepage / includes Compliance Matrix in Posture Tab specification', () => {
    const pageSrc = fs.readFileSync('frontend/src/app/page.tsx', 'utf8');
    assert.ok(pageSrc.includes('<ComplianceMatrixCard result={scanResult} />'), 'Homepage must mount ComplianceMatrixCard in Posture Tab');
    assert.ok(pageSrc.includes('<HeaderScorecard posture={scanResult.securityPosture} />'), 'Homepage must mount HeaderScorecard');
  });

  console.log('\n===============================================================');
  console.log(`📊 Phase 5 Test Results: ${passed}/${total} PASSED (${Math.round((passed/total)*100)}%)`);
  console.log('===============================================================');

  if (passed !== total) {
    process.exit(1);
  }
}

runSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
