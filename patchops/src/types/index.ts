// Vulnerability data structure (input from monitoring system)
export interface Vulnerability {
  id: string;                    // CVE ID or advisory ID
  packageName: string;           // Affected package
  currentVersion: string;        // Version in our repo
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore?: number;           // CVSS score if available
  description: string;          // Vulnerability description
  affectedVersions: string;     // Semver range of affected versions
  fixedVersions: string;        // Semver range of fixed versions
  references: string[];         // URLs to advisories
}

// Repository context
export interface RepoContext {
  owner: string;
  repo: string;
  defaultBranch: string;
  packageManager: 'npm' | 'pip' | 'maven' | 'gradle';
  manifestPath: string;         // e.g., "package.json"
  lockfilePath?: string;        // e.g., "package-lock.json"
}

// Evidence that we are affected
export interface ImpactEvidence {
  isAffected: boolean;
  reason: string;
  importedInFiles: string[];    // Source files importing the package
  isDirectDependency: boolean;
  isTransitiveDependency: boolean;
}

// The patch plan (output from LLM analysis)
export interface PatchPlan {
  vulnerability: Vulnerability;
  evidence: ImpactEvidence;
  analysis: {
    threatScore: number;        // 0-100
    threatRationale: string;    // Human-readable explanation
    evidence: string;           // Why we are vulnerable
    recommendedVersion: string; // Specific version to upgrade to
    confidence: 'high' | 'medium' | 'low';
  };
  migration: {
    breakingChanges: string[];  // Predicted breaking changes
    migrationSteps: string[];   // Step-by-step upgrade guide
    testChecklist: string[];    // Tests to verify fix
    rollbackPlan: string;       // How to revert if issues
  };
  metadata: {
    generatedAt: string;
    llmModel: string;
    analysisTimeMs: number;
  };
}

// GitHub PR data
export interface PullRequest {
  number: number;
  title: string;
  body: string;
  branch: string;
  url: string;
  state: 'open' | 'closed';
}

// Action commands from email/webhook
export type ActionCommand = 'ACK' | 'DEFER' | 'ASSIGN' | 'OPEN_PR';

export interface ActionRequest {
  command: ActionCommand;
  vulnerabilityId: string;
  params?: {
    days?: number;              // For DEFER
    assignee?: string;          // For ASSIGN
  };
}

// GitHub file change
export interface FileChange {
  path: string;
  content: string;
  sha?: string;                 // Required for updates
}
