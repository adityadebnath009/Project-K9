export type ThreatVerdict = 'CRITICAL THREAT' | 'SUSPICIOUS' | 'VERIFIED SAFE';

export type PipelineLaneStatus = 'running' | 'passed' | 'warning' | 'failed';

export interface PipelineLane {
  laneId: 'crypto' | 'typosquat' | 'posture' | 'threat_feeds';
  title: string;
  status: PipelineLaneStatus;
  latencyMs: number;
  badge: string;
  insight: string;
}

export interface CertificateNode {
  level: 'root' | 'intermediate' | 'leaf';
  subject: string;
  issuer: string;
  serialNumber: string;
  sha256Fingerprint: string;
  validFrom: string;
  validTo: string;
  signatureAlgorithm: string;
  keyType: string;
  status: 'trusted' | 'warning' | 'revoked' | 'invalid';
  statusReason?: string;
  oneCrlRevoked?: boolean;
  sans?: string[];
  isSelfSigned?: boolean;
  tlsVersion?: string;
  cipher?: string;
  error?: string;
}

export interface EmudhraAudit {
  isVulnerable: boolean;
  cveOrBugId: string;
  curve: string;
  publicPointQ: {
    x: string;
    y: string;
  };
  generatorG: {
    x: string;
    y: string;
  };
  scalarEquation: string;
  discoveredScalar: number | string;
  scalarDerivationTimeMs: number;
  rubyAlert: string;
  technicalNotes: string;
  discoveryMethod?: string;
  keyType?: string;
}

export interface RSAKeyAudit {
  keyLength: number;
  keyLengthStatus: 'pass' | 'fail' | 'warn';
  rocaVulnerable: boolean;
  rocaStatus: 'PASS' | 'FAIL';
  signatureAlgorithm: string;
  isAlgorithmDeprecated: boolean;
  publicExponent: number;
  issues?: string[];
  isRsa?: boolean;
}

export interface CTLogEntry {
  id: string;
  timestamp: string;
  issuer: string;
  logOperator: string;
  logName: string;
  status: 'valid' | 'revocation_anomaly' | 'unusual_velocity';
  certType: string;
  serial: string;
}

export interface TyposquattingAudit {
  isImpersonation: boolean;
  targetDomain: string;
  targetedBrand: string;
  legitimateDomain: string;
  levenshteinDistance: number;
  punycodeHomoglyph: boolean;
  punycodeRepresentation?: string;
  homoglyphBreakdown?: string;
  registrar: string;
  domainAgeDays: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  entropy?: number;
  highEntropyFlag?: boolean;
  deceptiveTokens?: string[];
}

export interface DOMHarvestingAudit {
  hasCredentialInputs: boolean;
  passwordFieldsDetected: number;
  cardFieldsDetected: number;
  formActionUrl: string;
  isCrossOriginExfiltration: boolean;
  destinationDomain: string;
  flaggedInputNames: string[];
}

export interface UrgencyNLPAudit {
  detected: boolean;
  urgencyScore: number; // 0-100
  matchedKeywords: string[];
  extractedSnippets: string[];
}

export interface SecurityHeaderItem {
  name: string;
  status: 'present' | 'missing' | 'warning';
  value?: string;
  recommendation?: string;
}

export interface SensitiveFileProbe {
  path: string;
  status: 'EXPOSED' | 'PROTECTED';
  httpCode: number;
  risk: 'CRITICAL' | 'HIGH' | 'LOW' | 'SAFE';
}

export interface SecurityPostureAudit {
  overallGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  gradeNumeric: number;
  headers: SecurityHeaderItem[];
  sensitiveFilesProbe: SensitiveFileProbe[];
}

export interface RadarIncident {
  id: string;
  url: string;
  domain: string;
  category: 'eMudhra Flawed CA' | 'Brand Phishing' | 'Insecure Config' | 'Malware Dropper' | 'Credential Harvest';
  reporter: string;
  timestamp: string;
  confirmVotes: number;
  flagFalseVotes: number;
  userVoted?: 'confirm' | 'flag' | null;
  consensusPercent: number;
  severity: 'CRITICAL' | 'SUSPICIOUS' | 'LOW';
  stixBundle: Record<string, unknown>;
}

export interface TargetScanResult {
  scenarioId: 'emudhra' | 'paypal_phish' | 'insecure_app' | 'clean_google' | 'custom';
  url: string;
  domain: string;
  timestamp: string;
  riskScore: number; // 0-100
  verdict: ThreatVerdict;
  executiveSummary: string;
  confidence: number;
  mitreTactic: string;
  mitreId: string;
  pipelineLanes: PipelineLane[];
  certificateChain: CertificateNode[];
  emudhraAudit: EmudhraAudit;
  rsaKeyAudit: RSAKeyAudit;
  ctTimeline: CTLogEntry[];
  typosquatting: TyposquattingAudit;
  domHarvesting: DOMHarvestingAudit;
  urgencyNLP: UrgencyNLPAudit;
  securityPosture: SecurityPostureAudit;
  web3Commitment?: {
    reportHash?: string;
    transactionHash?: string;
    blockNumber?: number;
    contractAddress?: string;
    verificationUrl?: string;
    network?: string;
    isCommitted?: boolean;
  };
  aiBriefing?: {
    threatCategory?: string;
    targetedEntity?: string;
    analystRecommendation?: string;
    aiEngine?: string;
    psychologicalTriggers?: string[];
    mitreAttackTechniques?: Array<{
      id: string;
      name: string;
      tactic: string;
      description?: string;
    }>;
    extractedIndicators?: string[];
  };
  threatIntel?: {
    blacklisted: boolean;
    source: string;
    matchesCount: number;
    findings?: any[];
  };
  correlationReport?: {
    hasCampaignMatch: boolean;
    primaryCampaign?: string | null;
    correlationNotes?: string;
    campaigns?: any[];
  };
  recommendedPrecautions?: string[];
  identifiedIndicators?: string[];
  tlsDetails?: {
    connected: boolean;
    tlsVersion?: string;
    cipher?: string;
    sans?: string[];
    isSelfSigned?: boolean;
    hostnameMatches?: boolean;
    error?: string;
  };
  qrInspection?: any;
}

export interface QrScanResult {
  target: string;
  decodedData: string;
  isUpi: boolean;
  upiDetails?: {
    payeeVpa?: string;
    payeeName?: string;
    amount?: string;
    currency?: string;
    transactionNote?: string;
    isImpostorVpa?: boolean;
    impersonatedEntity?: string;
  };
  riskScore: number;
  verdict: 'CRITICAL THREAT' | 'SUSPICIOUS' | 'VERIFIED SAFE';
  executiveSummary: string;
  quishingRisk: 'HIGH' | 'MEDIUM' | 'LOW';
  redirectUrl?: string;
}
