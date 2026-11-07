"""
Application Binary Interface (ABI) for ThreatRegistry.sol
Matches the Solidity 0.8.20 smart contract.
"""

THREAT_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"internalType": "string", "name": "domain", "type": "string"},
            {"internalType": "uint8", "name": "riskTier", "type": "uint8"}
        ],
        "name": "registerThreatReport",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "reportId", "type": "uint256"},
            {"internalType": "bytes32", "name": "computedHash", "type": "bytes32"}
        ],
        "name": "verifyReport",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
        "name": "getReportByHash",
        "outputs": [
            {"internalType": "bool", "name": "exists", "type": "bool"},
            {"internalType": "uint256", "name": "reportId", "type": "uint256"},
            {"internalType": "string", "name": "domain", "type": "string"},
            {"internalType": "uint8", "name": "riskTier", "type": "uint8"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "address", "name": "reporter", "type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "limit", "type": "uint256"}],
        "name": "getLatestReports",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "reportId", "type": "uint256"},
                    {"internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
                    {"internalType": "string", "name": "domain", "type": "string"},
                    {"internalType": "uint8", "name": "riskTier", "type": "uint8"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    {"internalType": "address", "name": "reporter", "type": "address"}
                ],
                "internalType": "struct ThreatRegistry.ThreatReport[]",
                "name": "",
                "type": "tuple[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "reportCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "name": "isReportRegistered",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "reportId", "type": "uint256"},
            {"indexed": True, "internalType": "bytes32", "name": "reportHash", "type": "bytes32"},
            {"indexed": False, "internalType": "string", "name": "domain", "type": "string"},
            {"indexed": False, "internalType": "uint8", "name": "riskTier", "type": "uint8"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "reporter", "type": "address"}
        ],
        "name": "ThreatReportCommitted",
        "type": "event"
    }
]
