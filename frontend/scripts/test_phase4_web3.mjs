// Phase 4 Automated Verification Suite: Web3 Intelligence Drawer & On-Chain Integrity
import assert from 'node:assert';
import fs from 'node:fs';

const BACKEND_URL = 'http://localhost:8000';
const FRONTEND_URL = 'http://localhost:3000';

async function runSuite() {
  console.log('===============================================================');
  console.log('🧪 K9 Sentinel AI - Phase 4 Automated Test Suite');
  console.log('   Focus: Web3 Solidity Contract, ABI Drawer & On-Chain Registry');
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

  // Group 1: Live Web3 Engine Endpoints
  console.log('--- Group 1: Live Web3 Engine Endpoints ---');

  await test('POST /api/v1/web3/verify verifies authentic report hash on-chain', async () => {
    const latestRes = await fetch(`${BACKEND_URL}/api/v1/web3/latest`);
    const commitments = await latestRes.json();
    assert.ok(commitments.length > 0, 'Ledger must have commitments');
    const validHash = commitments[0].report_hash;

    const res = await fetch(`${BACKEND_URL}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: validHash }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.is_valid, true, 'Report hash should be verified on-chain');
    assert.ok(data.on_chain_record, 'Should contain on_chain_record');
    assert.ok(data.block_number != null, 'Should return block number');
  });

  await test('POST /api/v1/web3/verify rejects tampered or non-existent hash', async () => {
    const fakeHash = '0x0000000000000000000000000000000000000000000000000000000000000000';
    const res = await fetch(`${BACKEND_URL}/api/v1/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report_hash: fakeHash }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.is_valid, false, 'Tampered hash must be rejected');
  });

  await test('GET /api/v1/web3/latest returns live mined threat commitments', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/web3/latest`);
    assert.strictEqual(res.status, 200);
    const commitments = await res.json();
    assert.ok(Array.isArray(commitments), 'Should be an array');
    assert.ok(commitments.length > 0, 'Should have at least 1 commitment');
    const first = commitments[0];
    assert.ok(first.report_hash.startsWith('0x'), 'Must be a 0x-prefixed hex hash');
    assert.ok(first.domain, 'Should include domain');
  });

  // Group 2: Community Collaborative Consensus Feed
  console.log('\n--- Group 2: Collaborative Consensus Radar Endpoints ---');

  await test('GET /api/v1/incidents returns community reports feed', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/incidents`);
    assert.strictEqual(res.status, 200);
    const incidents = await res.json();
    assert.ok(Array.isArray(incidents));
    assert.ok(incidents.length >= 3, 'Should have at least 3 benchmark incidents');
  });

  await test('POST /api/v1/incidents/{id}/vote records live vote', async () => {
    const res = await fetch(`${BACKEND_URL}/api/v1/incidents/inc-001/vote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vote: 'fake' }),
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.fake_votes >= 1, 'Fake votes count should be incremented');
  });

  // Group 3: Solidity Smart Contract & ABI Validation
  console.log('\n--- Group 3: Solidity Smart Contract & ABI Validation ---');

  await test('ThreatRegistry.sol exists and contains standard EVM methods', () => {
    const sol = fs.readFileSync('backend/engine/web3/ThreatRegistry.sol', 'utf8');
    assert.ok(sol.includes('contract ThreatRegistry'), 'Must declare contract ThreatRegistry');
    assert.ok(sol.includes('registerThreatReport('), 'Must define registerThreatReport');
    assert.ok(sol.includes('verifyReport('), 'Must define verifyReport');
    assert.ok(sol.includes('getReportByHash('), 'Must define getReportByHash');
    assert.ok(sol.includes('ThreatReportCommitted('), 'Must emit ThreatReportCommitted event');
    assert.ok(sol.includes('pragma solidity ^0.8.20;'), 'Must target Solidity ^0.8.20');
  });

  await test('Contract ABI contains all functional signatures & event definitions', () => {
    const modalSrc = fs.readFileSync('frontend/src/components/web3/ContractAbiModal.tsx', 'utf8');
    assert.ok(modalSrc.includes('0x8A791620dd6260079BF849Dc5567aDC3F2FdC318'), 'Deployed address must be present');
    assert.ok(modalSrc.includes('registerThreatReport'), 'ABI must include registerThreatReport');
    assert.ok(modalSrc.includes('verifyReport'), 'ABI must include verifyReport');
    assert.ok(modalSrc.includes('getReportByHash'), 'ABI must include getReportByHash');
    assert.ok(modalSrc.includes('ThreatReportCommitted'), 'ABI must include ThreatReportCommitted');
  });

  // Group 4: Frontend UI Inspection
  console.log('\n--- Group 4: Frontend UI Integration ---');

  await test('Frontend /radar renders Web3 Contract drawer trigger & category filters', async () => {
    const res = await fetch(`${FRONTEND_URL}/radar`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('View ThreatRegistry.sol &amp; ABI') || html.includes('View ThreatRegistry.sol & ABI'), 'Should include contract viewer button');
    assert.ok(html.includes('Web3 Decentralized Registry'), 'Should include Web3 header');
    assert.ok(html.includes('eMudhra Flawed CA'), 'Should include eMudhra filter category');
    assert.ok(html.includes('Brand Phishing'), 'Should include Brand Phishing filter category');
    assert.ok(html.includes('Web3 On-Chain Verifier'), 'Should include on-chain verifier');
  });

  await test('Frontend homepage / renders Web3 Contract trigger button in Tab 5', async () => {
    const res = await fetch(`${FRONTEND_URL}/`);
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('ThreatRegistry.sol') || html.includes('Web3 Ledger'), 'Should include ThreatRegistry reference');
  });

  console.log('\n===============================================================');
  console.log(`📊 Phase 4 Test Results: ${passed}/${total} PASSED (${Math.round((passed/total)*100)}%)`);
  console.log('===============================================================');

  if (passed !== total) {
    process.exit(1);
  }
}

runSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
