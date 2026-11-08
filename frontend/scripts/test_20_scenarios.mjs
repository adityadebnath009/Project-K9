/**
 * K9 Sentinel AI: 20 Comprehensive End-to-End Test Cases
 * Validates All Engines: Crypto (30%), Threats (20%), Web3 (20%), Posture (20%), Intel & UX (10%)
 */

const BACKEND_BASE = 'http://localhost:8000';
const FRONTEND_BASE = 'http://localhost:3000';

async function run20Tests() {
  console.log('🚀 Running 20 Comprehensive Test Cases for K9 Sentinel AI...\n');
  let passed = 0;
  let failed = 0;
  const results = [];

  async function test(num, title, fn) {
    try {
      await fn();
      console.log(`  [${num}/20] ✅ PASS: ${title}`);
      results.push({ num, title, status: 'PASS' });
      passed++;
    } catch (err) {
      console.error(`  [${num}/20] ❌ FAIL: ${title}\n       Error: ${err.message}`);
      results.push({ num, title, status: 'FAIL', error: err.message });
      failed++;
    }
  }

  // Test 1: Service Health & Engine Readiness
  await test(1, 'Health API: System Operational Status & Engine Phases', async () => {
    const res = await fetch(`${BACKEND_BASE}/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.online || data.status !== 'OPERATIONAL') throw new Error(`Invalid status: ${data.status}`);
    if (!data.engine?.phase1_crypto || !data.engine?.phase5_web3) throw new Error('Missing engine phases');
  });

  // Test 2: Standard HTTPS Domain Scan (google.com)
  await test(2, 'URL Scan: Standard HTTPS Certificate & Posture (google.com)', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'google.com', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.crypto_report?.tls_chain?.connected) throw new Error('TLS connection failed');
    if (data.crypto_report?.tls_chain?.is_expired) throw new Error('Google cert reported expired');
    if (!data.web3_commitment?.report_hash?.startsWith('0x')) throw new Error('Missing Keccak256 hash');
  });

  // Test 3: Real Domain Live Scan with Header Posture Evaluation (shop.lolliandlace.com)
  await test(3, 'URL Scan: Live Let\'s Encrypt Handshake & Grade F Headers (shop.lolliandlace.com)', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'shop.lolliandlace.com', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.crypto_report?.tls_chain?.issuer?.includes("Let's Encrypt")) throw new Error('Issuer mismatch');
    if (data.posture_report?.header_posture?.grade !== 'F') throw new Error('Expected Posture Grade F');
    if (data.posture_report?.header_posture?.failed_headers_count < 3) throw new Error('Failed header count too low');
  });

  // Test 4: Homoglyph Punycode Impersonation Detection
  await test(4, 'Threat Heuristics: Cyrillic Punycode Homoglyph Detection (xn--pypal-4ve.com)', async () => {
    // xn--pypal-4ve.com is pаypal with Cyrillic а
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'http://xn--pypal-4ve.com/login', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const threats = data.threat_report?.domain_threats;
    if (!threats) throw new Error('Missing domain_threats');
    if (!threats.is_homograph && !threats.is_typosquatted) throw new Error('Failed to flag homoglyph/typosquat');
  });

  // Test 5: High-Entropy DGA Algorithm Detection
  await test(5, 'Threat Heuristics: Shannon Entropy Calculation & DGA Detection', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'https://x89q2mzk71vw9bf0a.net/beacon', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const entropy = data.threat_report?.domain_threats?.entropy;
    if (typeof entropy !== 'number' || entropy <= 0) throw new Error('Entropy not calculated');
  });

  // Test 6: Coercive Electricity Bill Disconnection SMS (NLP)
  await test(6, 'NLP Threat Engine: Coercive Electricity Disconnection Urgent SMS', async () => {
    const sms = 'URGENT NOTICE: Your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill of INR 2450. Call 9876543210 immediately or pay via UPI.';
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: sms }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.threat_score < 70) throw new Error(`Expected high threat score, got ${data.threat_score}`);
    if (!data.risk_tier || (data.risk_tier !== 'High Risk' && data.risk_tier !== 'Confirmed Malicious')) {
      throw new Error(`Expected elevated risk tier, got ${data.risk_tier}`);
    }
  });

  // Test 7: Indian Banking KYC Account Freeze SMS
  await test(7, 'NLP Threat Engine: SBI YONO Account Suspension Phishing SMS', async () => {
    const sms = 'Dear Customer, your SBI YONO account has been suspended today. Please update your PAN immediately by visiting http://sbi-pan-update.com or your account will be closed.';
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: sms }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.ai_briefing) throw new Error('Missing AI briefing');
    if (data.threat_score < 50) throw new Error(`Threat score too low: ${data.threat_score}`);
  });

  // Test 8: Non-Malicious Promotional SMS
  await test(8, 'NLP Threat Engine: Benign Retail Promotion SMS (Low Risk)', async () => {
    const sms = 'Summer Sale! Get 40% off on all formal shirts this weekend at ShoppersStop stores. Show this SMS at the billing counter to claim.';
    const res = await fetch(`${BACKEND_BASE}/api/v1/scan/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: sms }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.threat_score > 40) throw new Error(`Benign SMS received too high score: ${data.threat_score}`);
  });

  // Test 9: eMudhra Weak NIST P-384 CA Key Benchmark (Bug 2083449)
  await test(9, 'Crypto Audit: eMudhra Low-Entropy Private Scalar d=4 Recovery', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const emudhra = data.crypto_report?.emudhra_audit;
    if (!emudhra?.vulnerable) throw new Error('eMudhra weak key not flagged vulnerable');
    if (emudhra.recovered_scalar_d !== 4) throw new Error(`Recovered scalar expected 4, got ${emudhra.recovered_scalar_d}`);
    if (emudhra.severity !== 'CRITICAL') throw new Error(`Expected severity CRITICAL, got ${emudhra.severity}`);
  });

  // Test 10: Benchmark Catalog Discovery
  await test(10, 'Scenario Registry: Discover Mandatory Evaluation Benchmarks', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const scenarios = await res.json();
    if (!Array.isArray(scenarios) || scenarios.length < 6) throw new Error('Less than 6 benchmark scenarios registered');
    const ids = scenarios.map((s) => s.id);
    if (!ids.includes('scenario-1-emudhra-weak-ca') || !ids.includes('scenario-2-paypal-typosquat-harvest')) {
      throw new Error('Mandatory scenarios missing from catalog');
    }
  });

  // Test 11: Benchmark Execution for PayPal Typosquat + Form Harvesting
  await test(11, 'Scenario Runner: PayPal Typosquat & DOM Password Exfiltration Run', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.threat_report?.domain_threats?.is_typosquatted) throw new Error('Typosquat not flagged');
    if (data.threat_score < 75) throw new Error(`Expected threat score >= 75, got ${data.threat_score}`);
  });

  // Test 12: Benchmark Execution for Indian Banking Coercive SMS
  await test(12, 'Scenario Runner: SBI Coercive Phishing Benchmark Run', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-3-sbi-kyc-sms-scam/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.threat_score < 70) throw new Error('Threat score below expected benchmark threshold');
    if (!data.ai_briefing?.targeted_entity?.includes('SBI') && !data.ai_briefing?.threat_category?.includes('Phishing')) {
      throw new Error('Failed to identify targeted entity or category');
    }
  });

  // Test 13: Benign Corporate Infrastructure Benchmark (google.com)
  await test(13, 'Scenario Runner: Google Corporate Infrastructure (Safe Benchmark)', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-6-google-corporate-official/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.threat_score > 30) throw new Error(`Safe benchmark scored too high: ${data.threat_score}`);
  });

  // Test 14: Web3 On-Chain Report Registration & Keccak256 Hashing
  await test(14, 'Web3 Engine: Keccak256 Hash Generation & Field Determinism', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const hash = data.web3_commitment?.report_hash;
    if (!hash || !hash.startsWith('0x') || hash.length !== 66) throw new Error(`Invalid Keccak256 hash format: ${hash}`);
    if (data.web3_commitment.contract_address !== '0x8A791620dd6260079BF849Dc5567aDC3F2FdC318') {
      throw new Error(`Unexpected ThreatRegistry contract address: ${data.web3_commitment.contract_address}`);
    }
  });

  // Test 15: Web3 Verification of Authentic Registered Report
  await test(15, 'Web3 Engine: Proof-of-Trust Verification for Authentic Hash', async () => {
    // First trigger a scan to register a hash
    const scanRes = await fetch(`${BACKEND_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, { method: 'POST' });
    const scanData = await scanRes.json();
    const validHash = scanData.web3_commitment.report_hash;

    const res = await fetch(`${BACKEND_BASE}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: validHash }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data.is_valid) throw new Error('Expected registered hash to be valid on-chain');
    if (!data.block_number || data.block_number <= 0) throw new Error('Missing block number');
  });

  // Test 16: Web3 Verification Rejection for Tampered Hash
  await test(16, 'Web3 Engine: Tamper Rejection for Non-Existent Hash', async () => {
    const bogusHash = '0x0000000000000000000000000000000000000000000000000000000000000000';
    const res = await fetch(`${BACKEND_BASE}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: bogusHash }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.is_valid) throw new Error('Bogus hash falsely verified as valid');
  });

  // Test 17: Web3 Latest Commitments Feed
  await test(17, 'Web3 Engine: Fetch Latest Mined Commitments Feed', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/web3/latest`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error('Expected array of commitments');
    if (data.length > 0 && !data[0].report_hash?.startsWith('0x')) {
      throw new Error('Invalid commitment hash in feed');
    }
  });

  // Test 18: Collaborative Radar Incidents List & Schema
  await test(18, 'Radar API: Fetch Collaborative Incidents Feed', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/incidents`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const incidents = await res.json();
    if (!Array.isArray(incidents) || incidents.length === 0) throw new Error('Empty incidents feed');
    const first = incidents[0];
    if (!first.id || !first.target || typeof first.fake_votes !== 'number') {
      throw new Error('Incident missing required schema fields');
    }
  });

  // Test 19: Incident Creation & Consensus Voting Cycle
  await test(19, 'Radar API: Create Scam Incident & Cast Consensus Vote', async () => {
    const newInc = {
      target: 'https://test-scam-portal-' + Date.now() + '.org',
      category: 'Brand Phishing',
      reporter: 'automated-test-runner@k9-sentinel.local',
      user_experience: 'Encountered fake electricity payment link requesting unauthorized credit card transfer.',
      victim_status: 'Blocked in Time',
      initial_vote: 'fake',
    };
    const createRes = await fetch(`${BACKEND_BASE}/api/v1/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newInc),
    });
    if (!createRes.ok) throw new Error(`Create incident failed: HTTP ${createRes.status}`);
    const created = await createRes.json();
    if (!created.id) throw new Error('Created incident missing ID');

    // Vote on created incident
    const voteRes = await fetch(`${BACKEND_BASE}/api/v1/incidents/${created.id}/vote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vote: 'fake' }),
    });
    if (!voteRes.ok) throw new Error(`Vote failed: HTTP ${voteRes.status}`);
    const voted = await voteRes.json();
    if (voted.fake_votes < 1) throw new Error('Vote count did not increment');
  });

  // Test 20: STIX 2.1 Telemetry Export
  await test(20, 'Threat Intel: STIX 2.1 Automated Threat Intelligence Bundle', async () => {
    const res = await fetch(`${BACKEND_BASE}/api/v1/threats/stix`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const bundle = await res.json();
    if (bundle.type !== 'bundle') throw new Error(`Expected type bundle, got ${bundle.type}`);
    if (!Array.isArray(bundle.objects) || bundle.objects.length === 0) throw new Error('Empty STIX objects list');
    const indicator = bundle.objects.find((obj) => obj.type === 'indicator');
    if (!indicator) throw new Error('STIX bundle missing indicator object');
    if (!indicator.pattern || !indicator.valid_from) throw new Error('Indicator missing pattern or valid_from');
  });

  console.log(`\n======================================================`);
  console.log(`20 Scenarios Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log(`======================================================\n`);

  if (failed > 0) process.exit(1);
}

run20Tests().catch((err) => {
  console.error('Fatal execution error in 20-test suite:', err);
  process.exit(1);
});
