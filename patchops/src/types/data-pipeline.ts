// Data pipeline specific types for vulnerability intelligence

export interface VulnerabilitySource {
  id: string;
  name: string;
  url: string;
  type: 'firecrawl' | 'api' | 'rss';
  ecosystem: string[];
  lastScanned?: string;
  creditsUsed?: number;
}

export interface PackageInfo {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pip' | 'maven' | 'gradle';
  isDirect: boolean;
  isTransitive: boolean;
  manifestFile: string;
  lockfileEntry?: string;
}

export interface PackageUsage {
  packageName: string;
  isImported: boolean;
  importFiles: string[];
  importPatterns: string[];
  usageCount: number;
  lastAnalyzed: string;
}

export interface VulnerabilityIntelligence {
  id: string;
  packageName: string;
  ecosystem: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore?: number;
  affectedVersions: string;
  fixedVersions: string;
  description: string;
  references: string[];
  source: string;
  discoveredAt: string;
  isZeroDay: boolean;
  exploitAvailable?: boolean;
  isKEV?: boolean; // Known Exploited Vulnerabilities
}

export interface CriticalHit {
  vulnerability: VulnerabilityIntelligence;
  packageInfo: PackageInfo;
  usage: PackageUsage;
  impactLevel: 'CRITICAL_HIT' | 'LOW_PRIORITY';
  threatScore: number;
  evidence: {
    manifestProof: string;
    usageProof: string[];
    riskFactors: string[];
  };
}

export interface ScanResult {
  repositoryId: string;
  scanStarted: string;
  scanCompleted: string;
  packagesScanned: number;
  vulnerabilitiesFound: number;
  criticalHitsCount: number;
  lowPriority: number;
  newVulnerabilities: VulnerabilityIntelligence[];
  criticalHits: CriticalHit[];
}

export interface RepositoryMonitoring {
  repositoryId: string;
  owner: string;
  repo: string;
  defaultBranch: string;
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle';
  manifestPath: string;
  lockfilePath?: string;
  lastScanned?: string;
  scanInterval: number; // hours
  isActive: boolean;
  criticalHitCount: number;
  totalPackages: number;
}

export interface FirecrawlConfig {
  apiKey: string;
  maxCreditsPerScan: number;
  rateLimitDelay: number;
  retryAttempts: number;
}

export interface OSVQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

export interface OSVResponse {
  vulns: Array<{
    id: string;
    summary: string;
    details: string;
    severity: Array<{
      type: string;
      score: string;
    }>;
    affected: Array<{
      package: {
        name: string;
        ecosystem: string;
      };
      ranges: Array<{
        type: string;
        events: Array<{
          introduced?: string;
          fixed?: string;
        }>;
      }>;
    }>;
    references: Array<{
      type: string;
      url: string;
    }>;
    published: string;
    modified: string;
  }>;
}

export interface GitHubAdvisory {
  id: string;
  ghsa_id: string;
  cve_id?: string;
  title: string;
  description: string;
  severity: string;
  cvss_score?: number;
  published_at: string;
  updated_at: string;
  package: {
    name: string;
    ecosystem: string;
  };
  vulnerable_version_range: string;
  patched_versions: string;
  references: string[];
}

export interface VulnerabilityDatabase {
  // Database operations interface
  saveVulnerability(vuln: VulnerabilityIntelligence): Promise<void>;
  findVulnerabilities(packages: PackageInfo[]): Promise<VulnerabilityIntelligence[]>;
  getNewVulnerabilities(since: string): Promise<VulnerabilityIntelligence[]>;
  updateRepositoryStatus(repo: RepositoryMonitoring): Promise<void>;
  getRepositoryStatus(repoId: string): Promise<RepositoryMonitoring | null>;
}

export interface VulnerabilityScanner {
  // Scanner operations interface
  scanGitHubAdvisories(ecosystems: string[]): Promise<GitHubAdvisory[]>;
  queryOSVDatabase(packages: PackageInfo[]): Promise<OSVResponse>;
  detectZeroDayVulnerabilities(): Promise<VulnerabilityIntelligence[]>;
  scanAllSources(): Promise<VulnerabilityIntelligence[]>;
}

export interface PackageAnalyzer {
  // Package analysis interface
  parseManifest(repoContext: RepositoryMonitoring): Promise<PackageInfo[]>;
  analyzePackageUsage(repoContext: RepositoryMonitoring, packages: string[]): Promise<PackageUsage[]>;
  findCriticalHits(repoContext: RepositoryMonitoring, vulnerabilities: VulnerabilityIntelligence[]): Promise<CriticalHit[]>;
}

// Email action types (extending existing)
export type EmailAction = 'ACK' | 'DEFER' | 'ASSIGN' | 'OPEN_PR';

export interface EmailActionRequest {
  action: EmailAction;
  vulnerabilityId: string;
  repositoryId: string;
  params?: {
    days?: number;
    assignee?: string;
    priority?: 'high' | 'medium' | 'low';
  };
  timestamp: string;
  userEmail: string;
}

// UI Dashboard types
export interface DashboardMetrics {
  activeThreats: number;
  knownExploited: number;
  awaitingAction: number;
  prsOpened: number;
  lastScanTime: string;
  nextScanTime: string;
}

export interface ThreatNode {
  id: string;
  packageName: string;
  version: string;
  threatScore: number;
  severity: string;
  isDirect: boolean;
  isExploited: boolean;
  affectedFiles: string[];
  position?: { x: number; y: number };
}

export interface DependencyGraph {
  nodes: ThreatNode[];
  edges: Array<{
    source: string;
    target: string;
    relationship: 'depends' | 'imports';
  }>;
  metrics: DashboardMetrics;
}