// SPDX-License-Identifier: MIT
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
}
