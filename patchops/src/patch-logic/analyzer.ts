import type { Vulnerability, RepoContext, ImpactEvidence, PatchPlan } from '../types/index.js';
import type { VulnerabilityIntelligence, PackageInfo, CriticalHit } from '../types/data-pipeline.js';
import { VulnerabilityDatabase } from '../data-pipeline/vulnerability-db.js';
import { PackageAnalyzer } from '../data-pipeline/package-analyzer.js';
import { logger } from '../utils/logger.js';
import { OPENROUTER_CONFIG } from '../config/index.js';
import * as semver from 'semver';

export class PatchAnalyzer {
  private useLLM: boolean;
  private vulnerabilityDb: VulnerabilityDatabase;
  private packageAnalyzer: PackageAnalyzer;

  constructor() {
    this.useLLM = !!OPENROUTER_CONFIG.apiKey && OPENROUTER_CONFIG.apiKey !== 'your_openrouter_key_here';
    this.vulnerabilityDb = new VulnerabilityDatabase();
    this.packageAnalyzer = new PackageAnalyzer();
    
    if (!this.useLLM) {
      logger.warn('⚠️  Running in MOCK mode - LLM features disabled');
      logger.info('   Set OPENROUTER_API_KEY in .env for real LLM analysis');
    }
  }

  /**
   * Main entry point: Analyze a vulnerability and generate a patch plan
   */
  async analyze(
    vulnerability: Vulnerability,
    context: RepoContext,
    importedFiles: string[] = []
  ): Promise<PatchPlan> {
    const startTime = Date.now();
    logger.info(`🔍 Analyzing ${vulnerability.id} for ${vulnerability.packageName}`);

    // Step 1: Determine impact evidence
    const evidence = this.analyzeImpact(vulnerability, importedFiles);

    // Step 2: Calculate threat score
    const threatScore = this.calculateThreatScore(vulnerability, evidence);

    // Step 3: Determine recommended version
    const recommendedVersion = this.determineRecommendedVersion(vulnerability);

    // Step 4: Generate analysis (LLM or mock)
    let analysis: PatchPlan['analysis'];
    let migration: PatchPlan['migration'];

    if (this.useLLM) {
      const llmResult = await this.callLLM(vulnerability, context, evidence, recommendedVersion);
      analysis = llmResult.analysis;
      migration = llmResult.migration;
    } else {
      const mockResult = this.generateMockAnalysis(vulnerability, evidence, recommendedVersion);
      analysis = mockResult.analysis;
      migration = mockResult.migration;
    }

    const endTime = Date.now();

    return {
      vulnerability,
      evidence,
      analysis,
      migration,
      metadata: {
        generatedAt: new Date().toISOString(),
        llmModel: this.useLLM ? OPENROUTER_CONFIG.model : 'mock',
        analysisTimeMs: endTime - startTime,
      },
    };
  }

  /**
   * Analyze if and how the vulnerability impacts the repository
   */
  private analyzeImpact(
    vulnerability: Vulnerability,
    importedFiles: string[]
  ): ImpactEvidence {
    const isImported = importedFiles.length > 0;
    const isDirect = true; // Simplified - would check lockfile in real implementation
    const isTransitive = !isDirect;

    let reason: string;
    if (isImported) {
      reason = `Package is imported in ${importedFiles.length} file(s): ${importedFiles.join(', ')}`;
    } else {
      reason = 'Package is a dependency but not directly imported in source files';
    }

    return {
      isAffected: isImported || isDirect,
      reason,
      importedInFiles: importedFiles,
      isDirectDependency: isDirect,
      isTransitiveDependency: isTransitive,
    };
  }

  /**
   * Calculate a threat score (0-100) based on multiple factors
   */
  private calculateThreatScore(
    vulnerability: Vulnerability,
    evidence: ImpactEvidence
  ): number {
    let score = 0;

    // Base score from CVSS or severity
    if (vulnerability.cvssScore) {
      score = vulnerability.cvssScore;
    } else {
      // Map severity to approximate CVSS
      const severityMap: Record<string, number> = {
        critical: 9.5,
        high: 8.0,
        medium: 5.5,
        low: 2.0,
      };
      score = severityMap[vulnerability.severity] || 5.0;
    }

    // Adjust based on impact evidence
    if (!evidence.isAffected) {
      score *= 0.3; // Reduce score if not actually imported
    } else if (evidence.importedInFiles.length > 5) {
      score *= 1.1; // Increase if widely used
    }

    // Cap at 100
    return Math.min(Math.round(score * 10), 100);
  }

  /**
   * Determine the best version to upgrade to
   */
  private determineRecommendedVersion(vulnerability: Vulnerability): string {
    const current = vulnerability.currentVersion;
    const fixedRange = vulnerability.fixedVersions;

    // Parse the fixed version range
    // Examples: ">=0.21.1", ">=4.17.21", ">=1.6.0"
    const minFixed = fixedRange.replace(/^[>=<^~]+/, '');
    
    // For demo purposes, return the minimum fixed version
    // In production, this would query npm/pypi for the latest secure version
    if (minFixed && semver.valid(minFixed)) {
      return minFixed;
    }

    // Fallback: bump patch version
    const bumped = semver.inc(current, 'patch');
    return bumped || current;
  }

  /**
   * Call OpenRouter API for LLM analysis
   */
  private async callLLM(
    vulnerability: Vulnerability,
    context: RepoContext,
    evidence: ImpactEvidence,
    recommendedVersion: string
  ): Promise<{ analysis: PatchPlan['analysis']; migration: PatchPlan['migration'] }> {
    logger.info('🤖 Calling OpenRouter API for LLM analysis...');
    
    const prompt = this.buildAnalysisPrompt(vulnerability, context, evidence, recommendedVersion);
    
    try {
      const response = await fetch(`${OPENROUTER_CONFIG.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENROUTER_CONFIG.apiKey}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://patchops.dev',
          'X-Title': 'PatchOps Security Analysis'
        },
        body: JSON.stringify({
          model: OPENROUTER_CONFIG.model,
          messages: [
            {
              role: 'system',
              content: 'You are a security expert analyzing vulnerabilities and creating patch plans. Respond with valid JSON only.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.3,
          max_tokens: 2000,
          response_format: { type: "json_object" }
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        logger.error(`OpenRouter API error details: ${errorText}`);
        throw new Error(`OpenRouter API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as {
        choices?: Array<{
          message?: {
            content?: string;
          };
        }>;
      };
      const content = data.choices?.[0]?.message?.content;
      
      if (!content) {
        throw new Error('No content received from OpenRouter API');
      }

      // Parse the JSON response
      const llmResult = JSON.parse(content);
      
      // Validate and structure the response
      const analysis: PatchPlan['analysis'] = {
        threatScore: llmResult.threatScore || this.calculateThreatScore(vulnerability, evidence),
        threatRationale: llmResult.threatRationale || this.generateThreatRationale(vulnerability, evidence),
        evidence: llmResult.evidence || evidence.reason,
        recommendedVersion,
        confidence: llmResult.confidence || (evidence.isAffected ? 'high' : 'medium'),
      };

      const migration: PatchPlan['migration'] = {
        breakingChanges: llmResult.breakingChanges || [],
        migrationSteps: llmResult.migrationSteps || [],
        testChecklist: llmResult.testChecklist || [],
        rollbackPlan: llmResult.rollbackPlan || `Revert to ${vulnerability.currentVersion} if issues occur`,
      };

      logger.info('✅ LLM analysis completed successfully');
      return { analysis, migration };
      
    } catch (error) {
      logger.error('❌ LLM analysis failed, falling back to mock:', error);
      // Fallback to mock analysis if LLM fails
      return this.generateMockAnalysis(vulnerability, evidence, recommendedVersion);
    }
  }

  /**
   * Generate mock analysis (used when LLM is unavailable)
   */
  private generateMockAnalysis(
    vulnerability: Vulnerability,
    evidence: ImpactEvidence,
    recommendedVersion: string
  ): { analysis: PatchPlan['analysis']; migration: PatchPlan['migration'] } {
    const isBreaking = semver.major(recommendedVersion) !== semver.major(vulnerability.currentVersion);
    
    const analysis: PatchPlan['analysis'] = {
      threatScore: this.calculateThreatScore(vulnerability, evidence),
      threatRationale: this.generateThreatRationale(vulnerability, evidence),
      evidence: evidence.reason,
      recommendedVersion,
      confidence: evidence.isAffected ? 'high' : 'medium',
    };

    const migration: PatchPlan['migration'] = {
      breakingChanges: isBreaking 
        ? [`Major version bump from ${vulnerability.currentVersion} to ${recommendedVersion} may include breaking changes`]
        : ['Patch version bump - should be backwards compatible'],
      migrationSteps: [
        `Update ${vulnerability.packageName} from ${vulnerability.currentVersion} to ${recommendedVersion}`,
        'Run npm install to update lockfile',
        'Run test suite to verify functionality',
        'Check for any deprecation warnings',
      ],
      testChecklist: [
        'Unit tests pass',
        'Integration tests pass',
        'No new console warnings',
        'Application starts successfully',
      ],
      rollbackPlan: `If issues occur, revert to ${vulnerability.currentVersion} by reverting the commit and running npm install`,
    };

    return { analysis, migration };
  }

  /**
   * Generate human-readable threat rationale
   */
  private generateThreatRationale(
    vulnerability: Vulnerability,
    evidence: ImpactEvidence
  ): string {
    const parts: string[] = [];
    
    parts.push(`${vulnerability.severity.toUpperCase()} severity vulnerability`);
    parts.push(`in ${vulnerability.packageName}@${vulnerability.currentVersion}`);
    
    if (evidence.isAffected) {
      parts.push('actively used in codebase');
      if (evidence.importedInFiles.length > 0) {
        parts.push(`(${evidence.importedInFiles.length} files)`);
      }
    } else {
      parts.push('(not directly imported)');
    }

    if (vulnerability.cvssScore && vulnerability.cvssScore > 7) {
      parts.push('High CVSS score indicates significant risk');
    }

    return parts.join('. ');
  }

  /**
   * Utility: Check if a version satisfies a range
   */
  static isVersionAffected(version: string, affectedRange: string): boolean {
    return semver.satisfies(version, affectedRange);
  }

  /**
   * Utility: Get version diff summary
   */
  static getVersionDiff(current: string, target: string): string {
    const diff = semver.diff(current, target);
    if (!diff) return 'same version';
    
    const diffMap: Record<string, string> = {
      major: '⚠️  MAJOR version change - breaking changes likely',
      minor: '✓ MINOR version change - new features, backwards compatible',
      patch: '✓ PATCH version change - bug fixes only',
      prerelease: '⚠️  Prerelease version - use with caution',
    };
    
    return diffMap[diff] || `${diff} version change`;
  }

  /**
   * NEW: Scan for newly discovered vulnerabilities in a repository
   */
  async scanForNewVulnerabilities(repoContext: RepoContext): Promise<CriticalHit[]> {
    logger.info(`🔍 Scanning for new vulnerabilities in ${repoContext.owner}/${repoContext.repo}...`);

    try {
      // Convert RepoContext to RepositoryMonitoring format
      const repoMonitoring = {
        repositoryId: `${repoContext.owner}/${repoContext.repo}`,
        owner: repoContext.owner,
        repo: repoContext.repo,
        defaultBranch: repoContext.defaultBranch,
        packageManager: repoContext.packageManager,
        manifestPath: repoContext.manifestPath || 'package.json',
        lockfilePath: repoContext.lockfilePath,
        scanInterval: 6,
        isActive: true,
        criticalHitCount: 0,
        totalPackages: 0
      };

      // Parse repository packages
      const packages = await this.packageAnalyzer.parseManifest(repoMonitoring);
      
      // Find vulnerabilities for these packages
      const vulnerabilities = await this.vulnerabilityDb.findVulnerabilities(packages);
      
      // Find Critical Hits only
      const criticalHits = await this.packageAnalyzer.findCriticalHits(repoMonitoring, vulnerabilities);
      
      const actualCriticalHits = criticalHits.filter(hit => hit.impactLevel === 'CRITICAL_HIT');
      logger.info(`🎯 Found ${actualCriticalHits.length} Critical Hits in ${repoContext.owner}/${repoContext.repo}`);
      
      return actualCriticalHits;
    } catch (error) {
      logger.error(`❌ Failed to scan for new vulnerabilities:`, error);
      return [];
    }
  }

  /**
   * ENHANCED: Check if package is actually used in repository
   */
  async validatePackageUsage(repoContext: RepoContext, packageNames: string[]): Promise<{
    [packageName: string]: {
      isImported: boolean;
      importFiles: string[];
      usageCount: number;
    }
  }> {
    logger.info(`🔍 Validating package usage for ${packageNames.length} packages...`);

    const repoMonitoring = {
      repositoryId: `${repoContext.owner}/${repoContext.repo}`,
      owner: repoContext.owner,
      repo: repoContext.repo,
      defaultBranch: repoContext.defaultBranch,
      packageManager: repoContext.packageManager,
      manifestPath: repoContext.manifestPath || 'package.json',
      lockfilePath: repoContext.lockfilePath,
      scanInterval: 6,
      isActive: true,
      criticalHitCount: 0,
      totalPackages: 0
    };

    const usageResults = await this.packageAnalyzer.analyzePackageUsage(repoMonitoring, packageNames);
    
    const usageMap: { [key: string]: any } = {};
    for (const usage of usageResults) {
      usageMap[usage.packageName] = {
        isImported: usage.isImported,
        importFiles: usage.importFiles,
        usageCount: usage.usageCount
      };
    }

    return usageMap;
  }

  /**
   * Convert CriticalHit to legacy Vulnerability format for compatibility
   */
  convertCriticalHitToVulnerability(criticalHit: CriticalHit): Vulnerability {
    return {
      id: criticalHit.vulnerability.id,
      packageName: criticalHit.vulnerability.packageName,
      currentVersion: criticalHit.packageInfo.version,
      severity: criticalHit.vulnerability.severity,
      cvssScore: criticalHit.vulnerability.cvssScore,
      description: criticalHit.vulnerability.description,
      affectedVersions: criticalHit.vulnerability.affectedVersions,
      fixedVersions: criticalHit.vulnerability.fixedVersions,
      references: criticalHit.vulnerability.references
    };
  }

  /**
   * Build analysis prompt for LLM
   */
  private buildAnalysisPrompt(
    vulnerability: Vulnerability,
    context: RepoContext,
    evidence: ImpactEvidence,
    recommendedVersion: string
  ): string {
    return `Analyze this security vulnerability and provide a detailed patch plan in JSON format:

VULNERABILITY:
- ID: ${vulnerability.id}
- Package: ${vulnerability.packageName}
- Current Version: ${vulnerability.currentVersion}
- Recommended Version: ${recommendedVersion}
- Severity: ${vulnerability.severity}
- CVSS Score: ${vulnerability.cvssScore || 'N/A'}
- Description: ${vulnerability.description}
- Affected Versions: ${vulnerability.affectedVersions}
- Fixed Versions: ${vulnerability.fixedVersions}

REPOSITORY CONTEXT:
- Owner: ${context.owner}
- Repository: ${context.repo}
- Package Manager: ${context.packageManager}
- Default Branch: ${context.defaultBranch}

IMPACT EVIDENCE:
- Is Affected: ${evidence.isAffected}
- Reason: ${evidence.reason}
- Imported in Files: ${evidence.importedInFiles.join(', ') || 'None'}
- Direct Dependency: ${evidence.isDirectDependency}
- Transitive Dependency: ${evidence.isTransitiveDependency}

Please respond with ONLY a JSON object in this exact format:
{
  "threatScore": <number 0-100>,
  "threatRationale": "<detailed explanation of threat level>",
  "evidence": "<summary of impact evidence>",
  "confidence": "<high|medium|low>",
  "breakingChanges": ["<list of potential breaking changes>"],
  "migrationSteps": ["<ordered list of migration steps>"],
  "testChecklist": ["<list of testing items>"],
  "rollbackPlan": "<detailed rollback instructions>"
}

Focus on:
1. Accurate threat assessment based on CVSS score and usage
2. Realistic breaking change analysis between versions
3. Practical migration steps for ${context.packageManager}
4. Comprehensive testing checklist
5. Clear rollback procedures`;
  }
}
