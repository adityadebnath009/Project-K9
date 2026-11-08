'use client';

import React, { useState } from 'react';
import { X, Copy, Check, FileCode, Database, ExternalLink, Terminal, ShieldCheck, Cpu } from 'lucide-react';

interface ContractAbiModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SOLIDITY_SOURCE_CODE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @dev Decentralized Threat Intelligence Registry for K9 Sentinel AI.
 * Records immutable keccak256 cryptographic commitments of web threat audits on-chain.
 * Raw URLs, message contents, and PII are strictly preserved off-chain to ensure GDPR compliance.
 */
contract ThreatRegistry {
    // Standard 5-tier threat classifications matching K9 Sentinel schema
    enum RiskTier {
        LowRisk,            // 0
        Suspicious,         // 1
        HighRisk,           // 2
        ConfirmedMalicious, // 3
        Inconclusive        // 4
    }

    struct ThreatReport {
        uint256 reportId;
        bytes32 reportHash;    // keccak256 cryptographic commitment of full report
        string domain;         // Domain/Origin pseudonym (e.g. sbi-kyc.in)
        RiskTier riskTier;
        uint256 timestamp;
        address reporter;
    }

    // Report storage
    uint256 public reportCount;
    mapping(uint256 => ThreatReport) public reports;
    mapping(bytes32 => bool) public isReportRegistered;
    mapping(bytes32 => uint256) public hashToReportId;

    // Events
    event ThreatReportCommitted(
        uint256 indexed reportId,
        bytes32 indexed reportHash,
        string domain,
        RiskTier riskTier,
        uint256 timestamp,
        address indexed reporter
    );

    error ReportAlreadyRegistered(bytes32 reportHash);
    error InvalidReportId(uint256 reportId);
    error InvalidRiskTier(uint8 tier);

    /**
     * @notice Registers a new cryptographic commitment for an audited security report.
     * @param reportHash The keccak256 hash of the canonical report JSON.
     * @param domain Domain or target identifier.
     * @param riskTier Standard 5-tier classification integer (0 to 4).
     */
    function registerThreatReport(
        bytes32 reportHash,
        string calldata domain,
        uint8 riskTier
    ) external returns (uint256) {
        if (riskTier > uint8(RiskTier.Inconclusive)) {
            revert InvalidRiskTier(riskTier);
        }
        if (isReportRegistered[reportHash]) {
            revert ReportAlreadyRegistered(reportHash);
        }

        reportCount++;
        uint256 newId = reportCount;

        reports[newId] = ThreatReport({
            reportId: newId,
            reportHash: reportHash,
            domain: domain,
            riskTier: RiskTier(riskTier),
            timestamp: block.timestamp,
            reporter: msg.sender
        });

        isReportRegistered[reportHash] = true;
        hashToReportId[reportHash] = newId;

        emit ThreatReportCommitted(
            newId,
            reportHash,
            domain,
            RiskTier(riskTier),
            block.timestamp,
            msg.sender
        );

        return newId;
    }

    /**
     * @notice Verifies whether a given computed report hash matches the on-chain commitment.
     * @param reportId The registered report identifier.
     * @param computedHash The recomputed keccak256 hash from off-chain data.
     */
    function verifyReport(
        uint256 reportId,
        bytes32 computedHash
    ) external view returns (bool) {
        if (reportId == 0 || reportId > reportCount) {
            return false;
        }
        return reports[reportId].reportHash == computedHash;
    }

    /**
     * @notice Queries report details by its cryptographic commitment hash.
     * @param reportHash The keccak256 hash to look up.
     */
    function getReportByHash(
        bytes32 reportHash
    ) external view returns (
        bool exists,
        uint256 reportId,
        string memory domain,
        RiskTier riskTier,
        uint256 timestamp,
        address reporter
    ) {
        if (!isReportRegistered[reportHash]) {
            return (false, 0, "", RiskTier.LowRisk, 0, address(0));
        }
        uint256 id = hashToReportId[reportHash];
        ThreatReport memory rep = reports[id];
        return (true, id, rep.domain, rep.riskTier, rep.timestamp, rep.reporter);
    }

    /**
     * @notice Fetches the latest N threat reports registered on-chain.
     * @param limit Maximum number of records to retrieve.
     */
    function getLatestReports(uint256 limit) external view returns (ThreatReport[] memory) {
        uint256 total = reportCount;
        uint256 count = limit > total ? total : limit;

        ThreatReport[] memory latest = new ThreatReport[](count);
        for (uint256 i = 0; i < count; i++) {
            latest[i] = reports[total - i];
        }
        return latest;
    }
}`;

export const CONTRACT_ABI_JSON = [
  {
    inputs: [
      { internalType: 'bytes32', name: 'reportHash', type: 'bytes32' },
      { internalType: 'string', name: 'domain', type: 'string' },
      { internalType: 'uint8', name: 'riskTier', type: 'uint8' },
    ],
    name: 'registerThreatReport',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'uint256', name: 'reportId', type: 'uint256' },
      { internalType: 'bytes32', name: 'computedHash', type: 'bytes32' },
    ],
    name: 'verifyReport',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'bytes32', name: 'reportHash', type: 'bytes32' }],
    name: 'getReportByHash',
    outputs: [
      { internalType: 'bool', name: 'exists', type: 'bool' },
      { internalType: 'uint256', name: 'reportId', type: 'uint256' },
      { internalType: 'string', name: 'domain', type: 'string' },
      { internalType: 'uint8', name: 'riskTier', type: 'uint8' },
      { internalType: 'uint256', name: 'timestamp', type: 'uint256' },
      { internalType: 'address', name: 'reporter', type: 'address' },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint256', name: 'limit', type: 'uint256' }],
    name: 'getLatestReports',
    outputs: [
      {
        components: [
          { internalType: 'uint256', name: 'reportId', type: 'uint256' },
          { internalType: 'bytes32', name: 'reportHash', type: 'bytes32' },
          { internalType: 'string', name: 'domain', type: 'string' },
          { internalType: 'uint8', name: 'riskTier', type: 'uint8' },
          { internalType: 'uint256', name: 'timestamp', type: 'uint256' },
          { internalType: 'address', name: 'reporter', type: 'address' },
        ],
        internalType: 'struct ThreatRegistry.ThreatReport[]',
        name: '',
        type: 'tuple[]',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'reportCount',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: 'uint256', name: 'reportId', type: 'uint256' },
      { indexed: true, internalType: 'bytes32', name: 'reportHash', type: 'bytes32' },
      { indexed: false, internalType: 'string', name: 'domain', type: 'string' },
      { indexed: false, internalType: 'uint8', name: 'riskTier', type: 'uint8' },
      { indexed: false, internalType: 'uint256', name: 'timestamp', type: 'uint256' },
      { indexed: true, internalType: 'address', name: 'reporter', type: 'address' },
    ],
    name: 'ThreatReportCommitted',
    type: 'event',
  },
];

export const CONTRACT_ADDRESS = '0x8A791620dd6260079BF849Dc5567aDC3F2FdC318';

export const ContractAbiModal: React.FC<ContractAbiModalProps> = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'solidity' | 'abi' | 'methods'>('solidity');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="w-full max-w-4xl max-h-[90vh] bg-zinc-950 border border-zinc-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-5 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-950/80 border border-emerald-800/60 text-emerald-400">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  ThreatRegistry.sol
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                  Sepolia Verified
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono mt-0.5">
                Contract: <span className="text-zinc-200">{CONTRACT_ADDRESS}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <a
              href={`https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-xs text-sky-400 hover:text-sky-300 transition-colors"
            >
              <span>Sepolia Etherscan</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Controls & Copy Button */}
        <div className="px-5 py-2.5 bg-zinc-900/40 border-b border-zinc-800 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-1">
            <button
              onClick={() => setActiveTab('solidity')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-colors ${
                activeTab === 'solidity'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5 text-emerald-400" />
              <span>Solidity Source (^0.8.20)</span>
            </button>

            <button
              onClick={() => setActiveTab('abi')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-colors ${
                activeTab === 'abi'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-sky-400" />
              <span>Contract ABI (JSON)</span>
            </button>

            <button
              onClick={() => setActiveTab('methods')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-colors ${
                activeTab === 'methods'
                  ? 'bg-zinc-800 text-white shadow'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              <span>Method & Event Spec</span>
            </button>
          </div>

          <button
            onClick={() => handleCopy(activeTab === 'solidity' ? SOLIDITY_SOURCE_CODE : JSON.stringify(CONTRACT_ABI_JSON, null, 2))}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-mono transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
            <span>{copied ? 'Copied to Clipboard' : 'Copy'}</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 font-mono text-xs">
          {activeTab === 'solidity' && (
            <div className="rounded-xl bg-zinc-950 p-4 border border-zinc-800 overflow-x-auto text-zinc-300">
              <pre className="leading-relaxed whitespace-pre font-mono text-[11px]">
                {SOLIDITY_SOURCE_CODE}
              </pre>
            </div>
          )}

          {activeTab === 'abi' && (
            <div className="rounded-xl bg-zinc-950 p-4 border border-zinc-800 overflow-x-auto text-emerald-400">
              <pre className="leading-relaxed whitespace-pre font-mono text-[11px]">
                {JSON.stringify(CONTRACT_ABI_JSON, null, 2)}
              </pre>
            </div>
          )}

          {activeTab === 'methods' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">function registerThreatReport</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">EXTERNAL NONPAYABLE</span>
                </div>
                <code className="block text-[11px] text-emerald-400 bg-zinc-950 p-2 rounded border border-zinc-800/80">
                  registerThreatReport(bytes32 reportHash, string calldata domain, uint8 riskTier) returns (uint256)
                </code>
                <p className="text-zinc-400 text-[11px]">
                  Records the keccak256 hash of an audited incident report on the immutable Ethereum ledger. Emits a <code className="text-zinc-200">ThreatReportCommitted</code> event.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">function verifyReport</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">EXTERNAL VIEW</span>
                </div>
                <code className="block text-[11px] text-sky-400 bg-zinc-950 p-2 rounded border border-zinc-800/80">
                  verifyReport(uint256 reportId, bytes32 computedHash) view returns (bool)
                </code>
                <p className="text-zinc-400 text-[11px]">
                  Cryptographically asserts whether a computed off-chain hash matches the immutable block commitment.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">function getReportByHash</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400">EXTERNAL VIEW</span>
                </div>
                <code className="block text-[11px] text-purple-400 bg-zinc-950 p-2 rounded border border-zinc-800/80">
                  getReportByHash(bytes32 reportHash) view returns (bool exists, uint256 reportId, string memory domain, RiskTier riskTier, uint256 timestamp, address reporter)
                </code>
                <p className="text-zinc-400 text-[11px]">
                  Queries on-chain registration state, domain pseudonym, and mining timestamp by keccak256 hash.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">event ThreatReportCommitted</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">EVM EVENT</span>
                </div>
                <code className="block text-[11px] text-amber-400 bg-zinc-950 p-2 rounded border border-zinc-800/80">
                  ThreatReportCommitted(uint256 indexed reportId, bytes32 indexed reportHash, string domain, RiskTier riskTier, uint256 timestamp, address indexed reporter)
                </code>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-zinc-800 bg-zinc-900/30 flex items-center justify-between text-xs text-zinc-400">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>GDPR Compliance: Zero PII on-chain (Keccak-256 only)</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition-colors font-mono"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
