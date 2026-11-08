/**
 * K9 Sentinel End-to-End Live Integration Verification Suite
 * Tests live FastAPI backend on port 8000 and data mappers for frontend UI bindings.
 */

const API_BASE = 'http://localhost:8000';

async function runTests() {
  console.log('🚀 Starting K9 Sentinel End-to-End Live Integration Suite...\n');
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

  // 1. Health Endpoint
  await test('Backend Health Check (GET /health)', async () => {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (!data.online || (data.status !== 'OPERATIONAL' && data.status !== 'healthy')) {
      throw new Error(`Unexpected body: ${JSON.stringify(data)}`);
    }
  });

  // 2. Real Domain Scan (shop.lolliandlace.com)
  await test('Real Domain Live Scan (POST /api/v1/scan shop.lolliandlace.com)', async () => {
    const res = await fetch(`${API_BASE}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'shop.lolliandlace.com', input_type: 'url' }),
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.target !== 'shop.lolliandlace.com') throw new Error('Target mismatch');
    if (!data.crypto_report?.tls_chain?.connected) throw new Error('TLS not connected');
    if (!data.crypto_report?.tls_chain?.issuer.includes("Let's Encrypt")) throw new Error('Expected Let\'s Encrypt issuer');
    if (data.posture_report?.header_posture?.grade !== 'F') throw new Error('Expected Posture Grade F');
    if (!data.web3_commitment?.report_hash?.startsWith('0x')) throw new Error('Missing valid Keccak256 hash');
  });

  // 3. SMS / Message Scan (POST /api/v1/scan/message)
  await test('SMS Phishing Message Scan (POST /api/v1/scan/message)', async () => {
    const res = await fetch(`${API_BASE}/api/v1/scan/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'Dear customer, your SBI account will be blocked in 24h. Click http://sbi-kyc.in to verify.' }),
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.threat_score < 25) throw new Error(`Expected suspicious score, got ${data.threat_score}`);
    const hasMitre = data.identified_indicators?.some(i => i.includes('MITRE'));
    if (!hasMitre) throw new Error('Missing MITRE technique indicators');
  });

  // 4. eMudhra Flawed CA Scenario (POST /api/v1/scenarios/scenario-1-emudhra-weak-ca/run)
  await test('eMudhra Flawed CA Benchmark (POST /api/v1/scenarios/scenario-1-emudhra-weak-ca/run)', async () => {
    const res = await fetch(`${API_BASE}/api/v1/scenarios/scenario-1-emudhra-weak-ca/run`, { method: 'POST' });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    const em = data.crypto_report?.emudhra_audit;
    if (!em?.vulnerable) throw new Error('Expected eMudhra vulnerability flagged');
    if (em.recovered_scalar_d !== 4) throw new Error(`Expected scalar d=4, got ${em.recovered_scalar_d}`);
    if (data.threat_score < 75) throw new Error(`Expected critical threat score, got ${data.threat_score}`);
  });

  // 5. PayPal Typosquat Scenario (POST /api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run)
  await test('PayPal Typosquat Benchmark (POST /api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run)', async () => {
    const res = await fetch(`${API_BASE}/api/v1/scenarios/scenario-2-paypal-typosquat-harvest/run`, { method: 'POST' });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    const dt = data.threat_report?.domain_threats;
    if (!dt?.is_typosquatted) throw new Error('Expected typosquat detected');
    if (dt.impersonated_brand?.toLowerCase() !== 'paypal') throw new Error(`Expected brand paypal, got ${dt.impersonated_brand}`);
  });

  // 6. Web3 Verify Authentic Hash
  await test('Web3 On-Chain Verification Authentic (POST /api/v1/web3/verify)', async () => {
    const latestRes = await fetch(`${API_BASE}/api/v1/web3/latest`);
    const latest = await latestRes.json();
    if (!latest || latest.length === 0) throw new Error('No latest commitments');
    const validHash = latest[0].report_hash;

    const verifyRes = await fetch(`${API_BASE}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: validHash }),
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.is_valid) throw new Error(`Expected hash ${validHash} to be valid`);
  });

  // 7. Web3 Verify Fake/Tampered Hash
  await test('Web3 On-Chain Verification Tampered/Unregistered (POST /api/v1/web3/verify)', async () => {
    const fakeHash = '0x0000000000000000000000000000000000000000000000000000000000000000';
    const verifyRes = await fetch(`${API_BASE}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: fakeHash }),
    });
    const verifyData = await verifyRes.json();
    if (verifyData.is_valid) throw new Error('Expected fake hash to be invalid!');
  });

  // 8. Community Incidents Feed & Voting
  await test('Community Incidents Feed & Vote (GET /api/v1/incidents, POST /vote)', async () => {
    const res = await fetch(`${API_BASE}/api/v1/incidents`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const incidents = await res.json();
    if (!Array.isArray(incidents) || incidents.length === 0) throw new Error('Expected incident array');

    const inc = incidents[0];
    const initialVotes = inc.fake_votes;
    const voteRes = await fetch(`${API_BASE}/api/v1/incidents/${inc.id}/vote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vote: 'fake' }),
    });
    if (!voteRes.ok) throw new Error(`Vote failed with status ${voteRes.status}`);
    const updated = await voteRes.json();
    if (updated.fake_votes !== initialVotes + 1) throw new Error(`Expected ${initialVotes + 1} votes, got ${updated.fake_votes}`);
  });

  // 9. STIX 2.1 Threat Telemetry Export
  await test('STIX 2.1 Telemetry Export (GET /api/v1/threats/stix)', async () => {
    const res = await fetch(`${API_BASE}/api/v1/threats/stix`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const bundle = await res.json();
    if (bundle.type !== 'bundle') throw new Error('Invalid STIX bundle spec');
    if (!Array.isArray(bundle.objects) || bundle.objects.length === 0) throw new Error('Empty STIX objects list');
    if (bundle.objects[0].spec_version !== '2.1') throw new Error('STIX object version must be 2.1');
  });

  console.log(`\n========================================`);
  console.log(`Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================`);
  if (failed > 0) process.exit(1);
}

runTests();
