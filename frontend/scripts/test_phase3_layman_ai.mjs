// Phase 3 Automated Verification Suite: Layman-First AI Translation & Live Scenarios
import assert from 'node:assert';

const BACKEND_URL = 'http://localhost:8000';
const FRONTEND_URL = 'http://localhost:3000';

async function runSuite() {
  console.log('===============================================================');
  console.log('🧪 K9 Sentinel AI - Phase 3 Automated Test Suite');
  console.log('   Focus: Layman-First Responsible AI & Live Benchmark Scenarios');
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

  // Group 1: Live Backend Benchmark Execution
  console.log('--- Group 1: Live Benchmark Scenario Execution ---');

  await test('POST /api/v1/scenarios/scenario-1-emudhra-weak-ca/run returns live d=4 proof', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, { method: 'POST' });
    assert.strictEqual(res.status, 200, `Expected 200, got ${res.status}`);
    const data = await res.json();
    assert.strictEqual(data.crypto_report.emudhra_audit.vulnerable, true);
    assert.strictEqual(data.crypto_report.emudhra_audit.recovered_scalar_d, 4);
    assert.ok(data.threat_score >= 80, 'Expected high threat score');
  });

  await test('POST /api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run returns DOM harvesting & MITRE', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run`, { method: 'POST' });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.threat_score, 100);
    assert.strictEqual(data.threat_report.dom_harvesting.has_password_field, true);
    assert.strictEqual(data.threat_report.dom_harvesting.harvesting_detected, true);
    assert.ok(data.ai_briefing.mitre_attack_techniques.length > 0, 'Should have mapped MITRE techniques');
  });

  await test('POST /api/v1/scenarios/scenario-3-sbi-kyc-sms-scam/run returns NLP urgency & coercion', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scenarios/scenario-3-sbi-kyc-sms-scam/run`, { method: 'POST' });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.threat_score >= 80);
    assert.strictEqual(data.threat_report.urgency_nlp.is_coercive, true);
    assert.ok(data.threat_report.urgency_nlp.urgency_score >= 40);
  });

  await test('POST /api/v1/scenarios/scenario-6-google-corporate-official/run returns low-risk benign tier', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scenarios/scenario-6-google-corporate-official/run`, { method: 'POST' });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.threat_score <= 20, `Expected threat score <= 20, got ${data.threat_score}`);
    assert.strictEqual(data.is_safe, true);
  });

  await test('POST /api/v1/scenarios/scenario-7-electricity-quishing-upi/run returns malicious UPI flag', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/scenarios/scenario-7-electricity-quishing-upi/run`, { method: 'POST' });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.qr_inspection.payload_type, 'upi_payment');
    assert.strictEqual(data.qr_inspection.upi_details.is_suspicious_vpa, true);
  });

  // Group 2: Frontend HTML Inspection for Layman-First AI Translation
  console.log('\n--- Group 2: Frontend Layman AI Translation Layer ---');

  await test('Frontend root (/) renders Layman AI Translation banner & structure', async () => {
    const res = await fetch(`${FRONTEND_URL}/`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('AI Layman Translation'), 'Should include "AI Layman Translation" header');
    assert.ok(html.includes('Plain English Summary'), 'Should include "Plain English Summary" badge');
    assert.ok(html.includes('1. What is this?'), 'Should include Question 1');
    assert.ok(html.includes('2. Is it safe or a scam?'), 'Should include Question 2');
    assert.ok(html.includes('3. What to do right now?'), 'Should include Question 3');
    assert.ok(html.includes('Cyber Helpline:'), 'Should feature National Cyber Helpline 1930');
    assert.ok(html.includes('Investigate Technical Evidence'), 'Should provide gateway to technical evidence');
  });

  await test('Frontend deep link /?scenario=scenario-2-paypal-typosquat-harvest responds with 200 OK', async () => {
    const res = await fetch(`${FRONTEND_URL}/?scenario=scenario-2-paypal-typosquat-harvest`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.length > 5000);
  });

  await test('Frontend deep link /?scenario=scenario-3-sbi-kyc-sms-scam responds with 200 OK', async () => {
    const res = await fetch(`${FRONTEND_URL}/?scenario=scenario-3-sbi-kyc-sms-scam`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.length > 5000);
  });

  // Group 3: Layman Assessment Logic Verification
  console.log('\n--- Group 3: Layman Translation Business Logic Coverage ---');

  await test('generateLaymanAssessment correctly diagnoses eMudhra weak scalar flaw in plain English', async () => {
    const fs = await import('fs');
    const src = fs.readFileSync('frontend/src/components/LaymanAITranslation.tsx', 'utf8');
    assert.ok(src.includes('Mozilla Bug 2083449'));
    assert.ok(src.includes('1930'));
    assert.ok(src.includes('scalar d=4 on NIST P-384'));
    assert.ok(src.includes('Imagine a bank vault combination that was set to "1-2-3-4"'));
  });

  await test('generateLaymanAssessment provides clear anti-panic advice for banking smishing', async () => {
    const fs = await import('fs');
    const src = fs.readFileSync('frontend/src/components/LaymanAITranslation.tsx', 'utf8');
    assert.ok(src.includes('Psychological Panic & Impersonation Scam'));
    assert.ok(src.includes('Legitimate banks and government departments never demand immediate KYC updates'));
    assert.ok(src.includes('Urgency is the scammer\'s best weapon'));
  });

  await test('generateLaymanAssessment warns never to enter UPI PIN to receive money', async () => {
    const fs = await import('fs');
    const src = fs.readFileSync('frontend/src/components/LaymanAITranslation.tsx', 'utf8');
    assert.ok(src.includes('entering your UPI PIN always DEDUCTS money from your account'));
    assert.ok(src.includes('Quishing (QR Phishing)'));
  });

  console.log('\n===============================================================');
  console.log(`📊 Phase 3 Test Results: ${passed}/${total} PASSED (${Math.round((passed/total)*100)}%)`);
  console.log('===============================================================');

  if (passed !== total) {
    process.exit(1);
  }
}

runSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
