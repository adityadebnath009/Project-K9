// Phase 6 Automated Verification Suite: Dual-Mode Camera Stream & Dead Code Cleanup
import assert from 'node:assert';
import fs from 'node:fs';

const BACKEND_URL = 'http://localhost:8000';
const FRONTEND_URL = 'http://localhost:3000';

async function runSuite() {
  console.log('===============================================================');
  console.log('🧪 K9 Sentinel AI - Phase 6 Automated Test Suite');
  console.log('   Focus: Dual-Mode Camera Stream, Anti-Quishing & Code Cleanup');
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

  // Group 1: Dormant Component Cleanup
  console.log('--- Group 1: Dormant Component Cleanup ---');

  await test('Verifies 6 dormant prototype components are completely removed', () => {
    const deadFiles = [
      'frontend/src/components/ExecutiveClientOverview.tsx',
      'frontend/src/components/PipelineVisualizer.tsx',
      'frontend/src/components/RiskGauge.tsx',
      'frontend/src/components/TheorySection.tsx',
      'frontend/src/components/collaborative/ThreatRadarFeed.tsx',
      'frontend/src/components/demo/BrowserGuardMockup.tsx',
    ];

    for (const file of deadFiles) {
      assert.strictEqual(fs.existsSync(file), false, `Dormant file must be removed: ${file}`);
    }
  });

  // Group 2: Camera Scanner Component Validation
  console.log('\n--- Group 2: Camera Scanner & Dual-Mode Component ---');

  await test('CameraScanner.tsx exists and contains HTML5 mediaStream implementation', () => {
    const src = fs.readFileSync('frontend/src/components/quishing/CameraScanner.tsx', 'utf8');
    assert.ok(src.includes('getUserMedia'), 'Must use navigator.mediaDevices.getUserMedia');
    assert.ok(src.includes('facingMode'), 'Must support back/front camera facingMode switching');
    assert.ok(src.includes('captureFrame'), 'Must implement canvas frame capture');
    assert.ok(src.includes('canvasRef'), 'Must use canvas for frame processing');
    assert.ok(src.includes('Snap & Audit QR') || src.includes('Snap &amp; Audit QR'), 'Must provide snap & audit trigger');
  });

  await test('Frontend /quishing renders Dual-Mode selector (Camera + File Dropzone)', async () => {
    const res = await fetch(`${FRONTEND_URL}/quishing`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('Scan with Camera'), 'Must include "Scan with Camera" button');
    assert.ok(html.includes('Image Upload / Dropzone'), 'Must include "Image Upload / Dropzone" button');
    assert.ok(html.includes('Module 05 · Anti-Quishing'), 'Must render module header');
    assert.ok(html.includes('Electricity Bill UPI Scam'), 'Must render verifiable test scenario');
  });

  // Group 3: Live QR & UPI Quishing Backend Analysis
  console.log('\n--- Group 3: Live QR & UPI Quishing Backend Analysis ---');

  await test('POST /api/v1/scan on deceptive electricity UPI URI flags impostor payee', async () => {
    const maliciousUpi = 'upi://pay?pa=bescom.electricity.bill@okhdfcbank&pn=StateElectricityDiscom&am=4800&cu=INR';
    const res = await fetch(`${BACKEND_URL}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: maliciousUpi, input_type: 'url' }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.threat_score >= 80, `Expected malicious score >= 80, got ${data.threat_score}`);
    assert.ok(data.qr_inspection, 'Must include qr_inspection');
    assert.strictEqual(data.qr_inspection.payload_type, 'upi_payment');
    assert.strictEqual(data.qr_inspection.upi_details.is_suspicious_vpa, true);
  });

  await test('POST /api/v1/scan on legitimate merchant UPI URI flags clean', async () => {
    const cleanUpi = 'upi://pay?pa=starbucks.retail@hdfcbank&pn=Starbucks%20Coffee&cu=INR';
    const res = await fetch(`${BACKEND_URL}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: cleanUpi, input_type: 'url' }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.threat_score <= 25, `Expected low threat score <= 25, got ${data.threat_score}`);
    assert.strictEqual(data.is_safe, true);
  });

  console.log('\n===============================================================');
  console.log(`📊 Phase 6 Test Results: ${passed}/${total} PASSED (${Math.round((passed/total)*100)}%)`);
  console.log('===============================================================');

  if (passed !== total) {
    process.exit(1);
  }
}

runSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
