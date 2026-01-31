import * as cron from 'node-cron';
import { VulnerabilityIntelligenceScanner } from './vulnerability-scanner.js';
import { PackageAnalyzer } from './package-analyzer.js';
import { VulnerabilityDatabase } from './vulnerability-db.js';
import { PatchAnalyzer } from '../patch-logic/analyzer.js';
import { GitHubBot } from '../github-bot/client.js';
import type { 
  RepositoryMonitoring, 
  ScanResult, 
  CriticalHit,
  VulnerabilityIntelligence 
} from '../types/data-pipeline.js';
import { DATA_PIPELINE_CONFIG } from '../config/data-pipeline.js';
import { logger } from '../utils/logger.js';

export class VulnerabilityMonitor {
  private scanner: VulnerabilityIntelligenceScanner;
  private packageAnalyzer: PackageAnalyzer;
  private database: VulnerabilityDatabase;
  private patchAnalyzer: PatchAnalyzer;
  private github: GitHubBot;
  private isRunning: boolean = false;
  private scheduledTask?: cron.ScheduledTask;

  constructor() {
    this.scanner = new VulnerabilityIntelligenceScanner();
    this.packageAnalyzer = new PackageAnalyzer();
    this.database = new VulnerabilityDatabase();
    this.patchAnalyzer = new PatchAnalyzer();
    this.github = new GitHubBot();
  }

  /**
   * Start automated vulnerability monitoring
   */
  async startMonitoring(): Promise<void> {
    const intervalHours = DATA_PIPELINE_CONFIG.scanning.intervalHours;
    const cronExpression = `0 */${intervalHours} * * *`; // Every N hours
    
    logger.info(`🚀 Starting vulnerability monitoring (every ${intervalHours} hours)...`);

    // Initialize monitored repositories
    await this.initializeMonitoredRepositories();

    // Schedule periodic scans
    this.scheduledTask = cron.schedule(cronExpression, async () => {
      if (this.isRunning) {
        logger.warn('⚠️  Previous scan still running, skipping this cycle');
        return;
      }

      try {
        await this.performFullScan();
      } catch (error) {
        logger.error('❌ Scheduled scan failed:', error);
      }
    }, {
      scheduled: true,
      timezone: 'UTC'
    });

    // Run initial scan
    logger.info('🔍 Running initial vulnerability scan...');
    await this.performFullScan();

    logger.info(`✅ Vulnerability monitoring started - next scan in ${intervalHours} hours`);
  }

  /**
   * Stop automated monitoring
   */
  stopMonitoring(): void {
    if (this.scheduledTask) {
      this.scheduledTask.stop();
      logger.info('🛑 Vulnerability monitoring stopped');
    }
  }

  /**
   * Perform a full vulnerability scan across all monitored repositories
   */
  async performFullScan(): Promise<ScanResult[]> {
    if (this.isRunning) {
      throw new Error('Scan already in progress');
    }

    this.isRunning = true;
    const scanStartTime = new Date();
    logger.info('🔍 Starting comprehensive vulnerability scan...');

    try {
      // 1. Scan for new vulnerabilities from all sources
      const newVulnerabilities = await this.scanner.scanAllSources();
      logger.info(`📊 Found ${newVulnerabilities.length} vulnerabilities from intelligence sources`);

      // 2. Save vulnerabilities to database
      for (const vuln of newVulnerabilities) {
        await this.database.saveVulnerability(vuln);
      }

      // 3. Get all monitored repositories
      const repositories = await this.database.getMonitoredRepositories();
      logger.info(`🏢 Scanning ${repositories.length} monitored repositories...`);

      const scanResults: ScanResult[] = [];

      // 4. Scan each repository
      for (const repo of repositories) {
        try {
          const repoScanResult = await this.scanRepository(repo, newVulnerabilities);
          scanResults.push(repoScanResult);

        // Update repository status
        repo.lastScanned = new Date().toISOString();
        repo.criticalHitCount = repoScanResult.criticalHitsCount;
        repo.totalPackages = repoScanResult.packagesScanned;
        await this.database.updateRepositoryStatus(repo);

        } catch (error) {
          logger.error(`❌ Failed to scan repository ${repo.repositoryId}:`, error);
        }
      }

      const totalCriticalHits = scanResults.reduce((sum, result) => sum + result.criticalHitsCount, 0);
      const scanDuration = Date.now() - scanStartTime.getTime();

      logger.info(`✅ Full scan complete: ${totalCriticalHits} Critical Hits found across ${repositories.length} repositories in ${scanDuration}ms`);
      
      return scanResults;

    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Scan a single repository for vulnerabilities
   */
  async scanRepository(repo: RepositoryMonitoring, knownVulnerabilities?: VulnerabilityIntelligence[]): Promise<ScanResult> {
    const scanStarted = new Date().toISOString();
    logger.info(`🔍 Scanning repository: ${repo.repositoryId}...`);

    try {
      // 1. Parse repository packages
      const packages = await this.packageAnalyzer.parseManifest(repo);
      logger.debug(`📦 Found ${packages.length} packages in ${repo.repositoryId}`);

      // 2. Find vulnerabilities for these packages
      let vulnerabilities: VulnerabilityIntelligence[];
      if (knownVulnerabilities) {
        // Use provided vulnerabilities (from full scan)
        vulnerabilities = knownVulnerabilities;
      } else {
        // Query database for vulnerabilities
        vulnerabilities = await this.database.findVulnerabilities(packages);
      }

      // 3. Find Critical Hits
      const criticalHits = await this.packageAnalyzer.findCriticalHits(repo, vulnerabilities);
      
      // 4. Save critical hits to database
      await this.database.saveCriticalHits(repo.repositoryId, criticalHits);

      // 5. Trigger patch workflows for new Critical Hits
      const newCriticalHits = criticalHits.filter(hit => hit.impactLevel === 'CRITICAL_HIT');
      for (const criticalHit of newCriticalHits) {
        try {
          await this.triggerPatchWorkflow(repo, criticalHit);
        } catch (error) {
          logger.error(`❌ Failed to trigger patch workflow for ${criticalHit.vulnerability.id}:`, error);
        }
      }

      const scanCompleted = new Date().toISOString();
        const scanResult: ScanResult = {
          repositoryId: repo.repositoryId,
          scanStarted,
          scanCompleted,
          packagesScanned: packages.length,
          vulnerabilitiesFound: vulnerabilities.length,
          criticalHitsCount: newCriticalHits.length,
          lowPriority: criticalHits.length - newCriticalHits.length,
          newVulnerabilities: [], // Not tracking per-repo new vulns
          criticalHits: newCriticalHits
        };

      // 6. Save scan result
      await this.database.saveScanResult(scanResult);

      logger.info(`✅ Repository scan complete: ${repo.repositoryId} - ${newCriticalHits.length} Critical Hits`);
      return scanResult;

    } catch (error) {
      logger.error(`❌ Repository scan failed for ${repo.repositoryId}:`, error);
      
      // Return empty result on failure
      return {
        repositoryId: repo.repositoryId,
        scanStarted,
        scanCompleted: new Date().toISOString(),
        packagesScanned: 0,
        vulnerabilitiesFound: 0,
        criticalHitsCount: 0,
        lowPriority: 0,
        newVulnerabilities: [],
        criticalHits: []
      };
    }
  }

  /**
   * Trigger patch workflow for a Critical Hit
   */
  private async triggerPatchWorkflow(repo: RepositoryMonitoring, criticalHit: CriticalHit): Promise<void> {
    logger.info(`🚨 Triggering patch workflow for Critical Hit: ${criticalHit.vulnerability.id} in ${repo.repositoryId}`);

    try {
      // Convert to existing types for compatibility
      const vulnerability = {
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

      const context = {
        owner: repo.owner,
        repo: repo.repo,
        defaultBranch: repo.defaultBranch,
        packageManager: repo.packageManager,
        manifestPath: repo.manifestPath,
        lockfilePath: repo.lockfilePath
      };

      // Use existing patch analyzer
      const patchPlan = await this.patchAnalyzer.analyze(
        vulnerability,
        context,
        criticalHit.usage.importFiles
      );

      // Create PR if vulnerability is confirmed as affecting the repository
      if (patchPlan.evidence.isAffected) {
        const title = `Security: Update ${vulnerability.packageName} to fix ${vulnerability.id}`;
        const body = this.generatePRBody(patchPlan, criticalHit);

        const pr = await this.github.createPatchPR(
          context,
          vulnerability.packageName,
          patchPlan.analysis.recommendedVersion,
          title,
          body
        );

        logger.info(`✅ Created PR #${pr.number} for Critical Hit: ${criticalHit.vulnerability.id}`);
      } else {
        logger.info(`ℹ️  Skipping PR creation - vulnerability not confirmed as affecting repository`);
      }

    } catch (error) {
      logger.error(`❌ Patch workflow failed for ${criticalHit.vulnerability.id}:`, error);
      throw error;
    }
  }

  /**
   * Generate enhanced PR body with Critical Hit information
   */
  private generatePRBody(patchPlan: any, criticalHit: CriticalHit): string {
    const { vulnerability, evidence } = criticalHit;
    
    return `## 🚨 Critical Hit Detected: ${vulnerability.id}

### 📊 Threat Intelligence
- **Threat Score:** ${criticalHit.threatScore}/100
- **Impact Level:** ${criticalHit.impactLevel}
- **Source:** ${vulnerability.source}
- **Discovered:** ${new Date(vulnerability.discoveredAt).toLocaleDateString()}

### 🎯 Why This is a Critical Hit
${evidence.riskFactors.map(factor => `- ${factor}`).join('\n')}

### 📁 Affected Files
${criticalHit.usage.importFiles.map(file => `- \`${file}\``).join('\n')}

### 🔍 Evidence
**Manifest Proof:**
\`\`\`json
${evidence.manifestProof}
\`\`\`

**Usage Proof:**
${evidence.usageProof.map(proof => `- ${proof}`).join('\n')}

---

${patchPlan ? `
### 🛠️ Automated Patch Plan
${patchPlan.analysis.threatRationale}

**Recommended Version:** ${patchPlan.analysis.recommendedVersion}

#### Migration Steps
${patchPlan.migration.migrationSteps.map((step: string, i: number) => `${i + 1}. ${step}`).join('\n')}

#### Testing Checklist
${patchPlan.migration.testChecklist.map((item: string) => `- [ ] ${item}`).join('\n')}
` : ''}

---
🤖 **Automated by PatchOps Vulnerability Intelligence**  
📊 **Powered by Firecrawl + OSV.dev**  
🎯 **Critical Hit Detection Active**`;
  }

  /**
   * Initialize monitored repositories from configuration
   */
  private async initializeMonitoredRepositories(): Promise<void> {
    const configuredRepos = DATA_PIPELINE_CONFIG.scanning.monitoredRepositories;
    
    for (const repoString of configuredRepos) {
      const [owner, repo] = repoString.split('/');
      if (!owner || !repo) {
        logger.warn(`⚠️  Invalid repository format: ${repoString}`);
        continue;
      }

      const repositoryId = `${owner}/${repo}`;
      
      // Check if repository is already monitored
      const existing = await this.database.getRepositoryStatus(repositoryId);
      if (existing) {
        logger.debug(`✅ Repository already monitored: ${repositoryId}`);
        continue;
      }

      // Add new repository to monitoring
      const repoMonitoring: RepositoryMonitoring = {
        repositoryId,
        owner,
        repo,
        defaultBranch: 'main', // Default, will be updated on first scan
        packageManager: 'npm', // Default, will be detected
        manifestPath: 'package.json',
        lockfilePath: 'package-lock.json',
        scanInterval: DATA_PIPELINE_CONFIG.scanning.intervalHours,
        isActive: true,
        criticalHitCount: 0,
        totalPackages: 0
      };

      await this.database.updateRepositoryStatus(repoMonitoring);
      logger.info(`✅ Added repository to monitoring: ${repositoryId}`);
    }
  }

  /**
   * Manual scan trigger for specific repository
   */
  async scanRepositoryById(repositoryId: string): Promise<ScanResult> {
    const repo = await this.database.getRepositoryStatus(repositoryId);
    if (!repo) {
      throw new Error(`Repository not found: ${repositoryId}`);
    }

    return await this.scanRepository(repo);
  }

  /**
   * Get monitoring status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      scanInterval: DATA_PIPELINE_CONFIG.scanning.intervalHours,
      monitoredRepositories: DATA_PIPELINE_CONFIG.scanning.monitoredRepositories.length,
      nextScanTime: this.scheduledTask ? 'Scheduled' : 'Not scheduled',
      scannerStats: this.scanner.getStats()
    };
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    this.stopMonitoring();
    await this.database.close();
    logger.info('🧹 Vulnerability monitor cleanup complete');
  }
}