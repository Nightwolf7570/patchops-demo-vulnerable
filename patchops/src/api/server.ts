import { Hono } from 'hono';
import type { Context as HonoContext } from 'hono';
import { PatchAnalyzer } from '../patch-logic/analyzer.js';
import { GitHubBot } from '../github-bot/client.js';
import { VulnerabilityMonitor } from '../data-pipeline/scheduler.js';
import { VulnerabilityDatabase } from '../data-pipeline/vulnerability-db.js';
import type { Vulnerability, RepoContext, ActionRequest, PatchPlan } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { SERVER_CONFIG } from '../config/index.js';

export class PatchOpsServer {
  private app: Hono;
  private analyzer: PatchAnalyzer;
  private github: GitHubBot;
  private vulnerabilityMonitor: VulnerabilityMonitor;
  private vulnerabilityDb: VulnerabilityDatabase;
  private port: number;

  constructor() {
    this.app = new Hono();
    this.analyzer = new PatchAnalyzer();
    this.github = new GitHubBot();
    this.vulnerabilityMonitor = new VulnerabilityMonitor();
    this.vulnerabilityDb = new VulnerabilityDatabase();
    this.port = SERVER_CONFIG.port;

    this.setupRoutes();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (c) => c.json({ status: 'ok', timestamp: new Date().toISOString() }));

    // Web UI Dashboard
    this.app.get('/', async (c) => {
      try {
        const fs = await import('fs/promises');
        const path = await import('path');
        const dashboardPath = path.join(process.cwd(), '..', 'ui', 'dashboard.html');
        const html = await fs.readFile(dashboardPath, 'utf-8');
        return c.html(html);
      } catch (error) {
        return c.html(`
          <html>
            <head><title>PatchOps Dashboard</title></head>
            <body style="font-family: system-ui; padding: 2rem; background: #0f0f23; color: #cccccc;">
              <h1>🛡️ PatchOps Dashboard</h1>
              <p>Welcome to PatchOps - Autonomous Dependency Security</p>
              <h2>API Endpoints:</h2>
              <ul>
                <li><a href="/health" style="color: #00cc00;">/health</a> - System health</li>
                <li><a href="/dashboard" style="color: #00cc00;">/dashboard</a> - Dashboard data (JSON)</li>
                <li><a href="/monitoring/status" style="color: #00cc00;">/monitoring/status</a> - Monitoring status</li>
              </ul>
              <p><em>Dashboard HTML file not found. Using fallback interface.</em></p>
            </body>
          </html>
        `);
      }
    });

    // Analyze vulnerability (without creating PR)
    this.app.post('/analyze', async (c) => {
      try {
        const body = await c.req.json();
        const { vulnerability, context, importedFiles = [] } = body;

        logger.info(`📊 Analysis request: ${vulnerability.id}`);

        const plan = await this.analyzer.analyze(vulnerability, context, importedFiles);

        return c.json({
          success: true,
          plan,
        });
      } catch (error) {
        logger.error('Analysis failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Create PR from patch plan
    this.app.post('/create-pr', async (c) => {
      try {
        const body = await c.req.json();
        const { plan, context } = body as { plan: PatchPlan; context: RepoContext };

        logger.info(`🔀 Creating PR for ${plan.vulnerability.id}`);

        const pr = await this.createPatchPR(plan, context);

        return c.json({
          success: true,
          pr,
          message: `PR #${pr.number} created successfully`,
        });
      } catch (error) {
        logger.error('PR creation failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Full workflow: Analyze + Create PR
    this.app.post('/process-vulnerability', async (c) => {
      try {
        const body = await c.req.json();
        const { vulnerability, context, importedFiles = [] } = body;

        logger.info(`🚀 Processing vulnerability: ${vulnerability.id}`);

        // Step 1: Analyze
        const plan = await this.analyzer.analyze(vulnerability, context, importedFiles);

        if (!plan.evidence.isAffected) {
          return c.json({
            success: true,
            action: 'skipped',
            reason: 'Vulnerability does not affect this repository',
            plan,
          });
        }

        // Step 2: Create PR
        const pr = await this.createPatchPR(plan, context);

        return c.json({
          success: true,
          action: 'pr_created',
          pr,
          plan,
        });
      } catch (error) {
        logger.error('Processing failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Webhook endpoint for action commands
    this.app.post('/webhook', async (c) => {
      try {
        const action = await c.req.json() as ActionRequest;

        logger.info(`📨 Webhook received: ${action.command}`);

        switch (action.command) {
          case 'OPEN_PR':
            return this.handleOpenPR(c, action);
          
          case 'ACK':
            return c.json({ success: true, action: 'acknowledged' });
          
          case 'DEFER':
            return c.json({ 
              success: true, 
              action: 'deferred',
              days: action.params?.days || 7,
            });
          
          case 'ASSIGN':
            return c.json({
              success: true,
              action: 'assigned',
              assignee: action.params?.assignee,
            });
          
          default:
            return c.json({ success: false, error: 'Unknown command' }, 400);
        }
      } catch (error) {
        logger.error('Webhook processing failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Demo endpoint - process axios vulnerability
    this.app.post('/demo/axios', async (c) => {
      const demoVulnerability: Vulnerability = {
        id: 'CVE-2020-28168',
        packageName: 'axios',
        currentVersion: '0.19.0',
        severity: 'high',
        cvssScore: 7.5,
        description: 'Server-Side Request Forgery (SSRF) vulnerability in axios',
        affectedVersions: '<0.21.1',
        fixedVersions: '>=0.21.1',
        references: [
          'https://nvd.nist.gov/vuln/detail/CVE-2020-28168',
          'https://github.com/axios/axios/releases/tag/v0.21.1',
        ],
      };

      const demoContext: RepoContext = {
        owner: 'Nightwolf7570',
        repo: 'patchops-demo-vulnerable',
        defaultBranch: 'main',
        packageManager: 'npm',
        manifestPath: 'package.json',
        lockfilePath: 'package-lock.json',
      };

      try {
        logger.info('🎬 Running axios demo...');

        // Analyze
        const plan = await this.analyzer.analyze(demoVulnerability, demoContext, ['index.js']);

        // Create PR
        const pr = await this.createPatchPR(plan, demoContext);

        return c.json({
          success: true,
          message: 'Demo complete! PR created.',
          pr,
          plan: {
            threatScore: plan.analysis.threatScore,
            recommendedVersion: plan.analysis.recommendedVersion,
            breakingChanges: plan.migration.breakingChanges,
          },
        });
      } catch (error) {
        logger.error('Demo failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // NEW: Vulnerability Intelligence Endpoints

    // Start/stop vulnerability monitoring
    this.app.post('/monitoring/start', async (c) => {
      try {
        await this.vulnerabilityMonitor.startMonitoring();
        return c.json({
          success: true,
          message: 'Vulnerability monitoring started',
          status: this.vulnerabilityMonitor.getStatus()
        });
      } catch (error) {
        logger.error('Failed to start monitoring:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    this.app.post('/monitoring/stop', async (c) => {
      try {
        this.vulnerabilityMonitor.stopMonitoring();
        return c.json({
          success: true,
          message: 'Vulnerability monitoring stopped'
        });
      } catch (error) {
        logger.error('Failed to stop monitoring:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Get monitoring status
    this.app.get('/monitoring/status', async (c) => {
      try {
        const status = this.vulnerabilityMonitor.getStatus();
        const metrics = await this.vulnerabilityDb.getDashboardMetrics();
        
        return c.json({
          success: true,
          monitoring: status,
          metrics
        });
      } catch (error) {
        logger.error('Failed to get monitoring status:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Manual vulnerability scan
    this.app.post('/scan/repository/:owner/:repo', async (c) => {
      try {
        const { owner, repo } = c.req.param();
        const repositoryId = `${owner}/${repo}`;
        
        logger.info(`🔍 Manual scan requested for ${repositoryId}`);
        
        const result = await this.vulnerabilityMonitor.scanRepositoryById(repositoryId);
        
        return c.json({
          success: true,
          message: `Scan completed for ${repositoryId}`,
          result
        });
      } catch (error) {
        logger.error('Manual scan failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Get Critical Hits for repository
    this.app.get('/critical-hits/:owner/:repo', async (c) => {
      try {
        const { owner, repo } = c.req.param();
        const repoContext: RepoContext = {
          owner,
          repo,
          defaultBranch: 'main',
          packageManager: 'npm',
          manifestPath: 'package.json',
          lockfilePath: 'package-lock.json'
        };

        const criticalHits = await this.analyzer.scanForNewVulnerabilities(repoContext);
        
        return c.json({
          success: true,
          repository: `${owner}/${repo}`,
          criticalHits: criticalHits.length,
          threats: criticalHits.map(hit => ({
            id: hit.vulnerability.id,
            packageName: hit.vulnerability.packageName,
            severity: hit.vulnerability.severity,
            threatScore: hit.threatScore,
            impactLevel: hit.impactLevel,
            usageFiles: hit.usage.importFiles,
            riskFactors: hit.evidence.riskFactors
          }))
        });
      } catch (error) {
        logger.error('Failed to get Critical Hits:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Dashboard data endpoint
    this.app.get('/dashboard', async (c) => {
      try {
        const metrics = await this.vulnerabilityDb.getDashboardMetrics();
        const monitoringStatus = this.vulnerabilityMonitor.getStatus();
        const repositories = await this.vulnerabilityDb.getMonitoredRepositories();

        return c.json({
          success: true,
          dashboard: {
            metrics,
            monitoring: monitoringStatus,
            repositories: repositories.map(repo => ({
              id: repo.repositoryId,
              owner: repo.owner,
              repo: repo.repo,
              criticalHits: repo.criticalHitCount,
              totalPackages: repo.totalPackages,
              lastScanned: repo.lastScanned,
              isActive: repo.isActive
            }))
          }
        });
      } catch (error) {
        logger.error('Failed to get dashboard data:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Package usage validation endpoint
    this.app.post('/validate-usage', async (c) => {
      try {
        const body = await c.req.json();
        const { context, packages } = body;

        const usage = await this.analyzer.validatePackageUsage(context, packages);
        
        return c.json({
          success: true,
          usage
        });
      } catch (error) {
        logger.error('Package usage validation failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // Vulnerability intelligence search
    this.app.get('/vulnerabilities/search', async (c) => {
      try {
        const { package: packageName, ecosystem, severity } = c.req.query();
        
        // This is a simplified search - in production you'd want more sophisticated filtering
        const packages = packageName ? [{ 
          name: packageName, 
          version: '0.0.0', 
          ecosystem: ecosystem as any || 'npm',
          isDirect: true,
          isTransitive: false,
          manifestFile: 'package.json'
        }] : [];
        
        const vulnerabilities = await this.vulnerabilityDb.findVulnerabilities(packages);
        
        return c.json({
          success: true,
          vulnerabilities: vulnerabilities.map(vuln => ({
            id: vuln.id,
            packageName: vuln.packageName,
            ecosystem: vuln.ecosystem,
            severity: vuln.severity,
            cvssScore: vuln.cvssScore,
            description: vuln.description,
            isZeroDay: vuln.isZeroDay,
            exploitAvailable: vuln.exploitAvailable,
            discoveredAt: vuln.discoveredAt,
            source: vuln.source
          }))
        });
      } catch (error) {
        logger.error('Vulnerability search failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // NEW: Get latest package version from npm registry
    this.app.get('/api/package/:name/latest', async (c) => {
      try {
        const packageName = c.req.param('name');
        
        logger.debug(`📦 Fetching latest version for ${packageName}`);
        
        const response = await fetch(`https://registry.npmjs.org/${packageName}/latest`);
        
        if (!response.ok) {
          return c.json({
            success: false,
            error: `Package not found: ${packageName}`
          }, 404);
        }
        
        const data = await response.json() as any;
        
        return c.json({
          success: true,
          name: data.name,
          version: data.version,
          description: data.description
        });
      } catch (error) {
        logger.error('Failed to fetch package version:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });

    // NEW: Analyze repository endpoint
    this.app.post('/api/analyze-repository', async (c) => {
      try {
        const body = await c.req.json();
        const { repository, manifestPath, description } = body;
        
        // Parse owner/repo
        const [owner, repo] = repository.split('/');
        
        if (!owner || !repo) {
          return c.json({
            success: false,
            error: 'Invalid repository format. Use: owner/repo'
          }, 400);
        }

        logger.info(`🔍 Analyzing repository: ${repository}`);

        // Auto-detect manifest path if not provided
        let detectedManifestPath = manifestPath || 'package.json';
        let detectedLockfilePath = manifestPath 
          ? manifestPath.replace('package.json', 'package-lock.json')
          : 'package-lock.json';

        // If no manifest path provided, try common locations
        if (!manifestPath) {
          const commonPaths = [
            'package.json',
            'server/package.json',
            'Server/package.json',
            'backend/package.json',
            'api/package.json',
            'src/package.json',
            'app/package.json'
          ];

          logger.info(`🔍 Auto-detecting package.json location...`);
          
          for (const path of commonPaths) {
            try {
              const response = await fetch(
                `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
                {
                  headers: {
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'PatchOps'
                  }
                }
              );
              
              if (response.ok) {
                detectedManifestPath = path;
                detectedLockfilePath = path.replace('package.json', 'package-lock.json');
                logger.info(`✅ Found package.json at: ${path}`);
                break;
              }
            } catch (error) {
              // Continue to next path
            }
          }
        }

        const repoContext: RepoContext = {
          owner,
          repo,
          defaultBranch: 'main',
          packageManager: 'npm',
          manifestPath: detectedManifestPath,
          lockfilePath: detectedLockfilePath
        };

        logger.info(`📦 Using manifest path: ${detectedManifestPath}`);

        // Get all packages from the repository
        let allPackages: any[] = [];
        try {
          const packageAnalyzer = await import('../data-pipeline/package-analyzer.js');
          const analyzer = new packageAnalyzer.PackageAnalyzer();
          
          // Convert RepoContext to RepositoryMonitoring format
          const repoMonitoring = {
            repositoryId: `${owner}/${repo}`,
            owner,
            repo,
            defaultBranch: repoContext.defaultBranch,
            packageManager: repoContext.packageManager,
            manifestPath: detectedManifestPath,
            lockfilePath: detectedLockfilePath,
            scanInterval: 24,
            isActive: true,
            criticalHitCount: 0,
            totalPackages: 0
          };
          
          allPackages = await analyzer.parseManifest(repoMonitoring);
          logger.info(`✅ Found ${allPackages.length} total packages`);
        } catch (error) {
          logger.warn(`Failed to parse manifest: ${error}`);
        }

        // Scan for vulnerabilities
        let criticalHits: any[] = [];
        
        try {
          // Try using the monitoring system's scan
          const repositoryId = `${owner}/${repo}`;
          const scanResult = await this.vulnerabilityMonitor.scanRepositoryById(repositoryId);
          criticalHits = scanResult.criticalHits || [];
        } catch (scanError) {
          logger.warn(`Monitoring scan failed, trying direct analysis: ${scanError}`);
          
          // Fallback: Try direct analysis
          try {
            criticalHits = await this.analyzer.scanForNewVulnerabilities(repoContext);
          } catch (analysisError) {
            logger.warn(`Direct analysis also failed: ${analysisError}`);
            criticalHits = [];
          }
        }

        // Create a map of vulnerable packages
        const vulnerablePackages = new Map(
          criticalHits.map(hit => [hit.vulnerability.packageName, hit])
        );

        // Format all dependencies for UI (show top 10 most important)
        const dependencies = allPackages
          .slice(0, 20) // Show top 20 packages
          .map(pkg => {
            const hit = vulnerablePackages.get(pkg.name);
            if (hit) {
              // Package has vulnerability
              return {
                name: hit.vulnerability.packageName,
                version: hit.packageInfo.version,
                severity: hit.vulnerability.severity,
                score: hit.threatScore,
                cve: hit.vulnerability.id,
                isKev: hit.vulnerability.isKEV || hit.evidence.riskFactors.includes('KEV'),
                description: hit.vulnerability.description,
                fixedVersion: hit.vulnerability.fixedVersions,
                impactLevel: hit.impactLevel,
                usageFiles: hit.usage.importFiles
              };
            } else {
              // Package is clean
              return {
                name: pkg.name,
                version: pkg.version,
                severity: 'low',
                score: 0,
                cve: null,
                isKev: false,
                description: `${pkg.name} - No known vulnerabilities`,
                fixedVersion: null,
                impactLevel: 'LOW_PRIORITY',
                usageFiles: []
              };
            }
          });

        const kpis = {
          activeThreats: criticalHits.filter(h => h.vulnerability.severity === 'critical' || h.vulnerability.severity === 'high').length,
          kevCount: criticalHits.filter(h => h.vulnerability.isKEV || h.evidence.riskFactors.includes('KEV')).length,
          awaitingAction: criticalHits.length,
          prsOpened: 0,
          totalPackages: allPackages.length
        };

        const vulnerabilities = criticalHits.map(hit => ({
          package: hit.vulnerability.packageName,
          version: hit.packageInfo.version,
          cve: hit.vulnerability.id,
          severity: hit.vulnerability.severity,
          score: hit.threatScore,
          description: hit.vulnerability.description,
          fixedVersion: hit.vulnerability.fixedVersions,
          impactLevel: hit.impactLevel,
          usageFiles: hit.usage.importFiles,
          riskFactors: hit.evidence.riskFactors
        }));

        return c.json({
          success: true,
          repository,
          manifestPath: detectedManifestPath,
          description,
          kpis,
          dependencies,
          vulnerabilities,
          analyzedAt: new Date().toISOString()
        });

      } catch (error) {
        logger.error('Repository analysis failed:', error);
        return c.json({
          success: false,
          error: (error as Error).message,
        }, 500);
      }
    });
  }

  private async handleOpenPR(c: HonoContext, action: ActionRequest): Promise<Response> {
    // In a real implementation, this would look up the vulnerability by ID
    // and create the PR. For now, return a message directing to use the demo endpoint.
    return c.json({
      success: true,
      message: 'Use POST /demo/axios to create a PR for the axios vulnerability',
      action: 'info',
    });
  }

  private async createPatchPR(plan: PatchPlan, context: RepoContext) {
    const { vulnerability, analysis, migration } = plan;

    // Generate PR title
    const title = `Security: Update ${vulnerability.packageName} to ${analysis.recommendedVersion} (${vulnerability.id})`;

    // Generate PR body
    const body = this.generatePRBody(plan);

    // Create the PR
    return await this.github.createPatchPR(
      context,
      vulnerability.packageName,
      analysis.recommendedVersion,
      title,
      body
    );
  }

  private generatePRBody(plan: PatchPlan): string {
    const { vulnerability, analysis, migration, evidence, metadata } = plan;

    return `## 🔒 Security Patch: ${vulnerability.id}

### 📋 Vulnerability Details
- **Package:** ${vulnerability.packageName}
- **Current Version:** ${vulnerability.currentVersion}
- **Recommended Version:** ${analysis.recommendedVersion}
- **Severity:** ${vulnerability.severity.toUpperCase()}
- **Threat Score:** ${analysis.threatScore}/100

### 🎯 Impact Analysis
${evidence.isAffected ? '✅ **Repository is affected**' : '⚠️ **Repository may be affected**'}

${evidence.reason}

**Files importing this package:**
${evidence.importedInFiles.map(f => `- \`${f}\``).join('\n') || '- None detected'}

### 📊 Threat Assessment
${analysis.threatRationale}

**Confidence Level:** ${analysis.confidence.toUpperCase()}

### 🛠️ Migration Plan

#### Breaking Changes
${migration.breakingChanges.map(bc => `- ${bc}`).join('\n')}

#### Migration Steps
${migration.migrationSteps.map((step, i) => `${i + 1}. ${step}`).join('\n')}

#### Testing Checklist
${migration.testChecklist.map(item => `- [ ] ${item}`).join('\n')}

#### Rollback Plan
${migration.rollbackPlan}

### 📚 References
${vulnerability.references?.map(ref => `- ${ref}`).join('\n') || '- No references provided'}

---
*Generated by PatchOps*  
*Analysis Time: ${metadata.analysisTimeMs}ms*  
*Model: ${metadata.llmModel}*  
*Generated: ${metadata.generatedAt}*
`;
  }

  public start(): void {
    // Node.js runtime
    import('@hono/node-server').then(({ serve }) => {
      serve({
        fetch: this.app.fetch,
        port: this.port,
      });

      logger.info(`🚀 PatchOps server running on http://localhost:${this.port}`);
      logger.info('   Core Endpoints:');
      logger.info('   - GET  /health              - Health check');
      logger.info('   - POST /analyze             - Analyze vulnerability');
      logger.info('   - POST /create-pr           - Create PR from plan');
      logger.info('   - POST /process-vulnerability - Full workflow');
      logger.info('   - POST /webhook             - Action webhook');
      logger.info('   - POST /demo/axios          - Run axios demo');
      logger.info('   Intelligence Endpoints:');
      logger.info('   - POST /monitoring/start    - Start vulnerability monitoring');
      logger.info('   - POST /monitoring/stop     - Stop vulnerability monitoring');
      logger.info('   - GET  /monitoring/status   - Get monitoring status');
      logger.info('   - POST /scan/repository/:owner/:repo - Manual repository scan');
      logger.info('   - GET  /critical-hits/:owner/:repo   - Get Critical Hits');
      logger.info('   - GET  /dashboard           - Dashboard data');
      logger.info('   - POST /validate-usage      - Validate package usage');
      logger.info('   - GET  /vulnerabilities/search - Search vulnerabilities');
    });
  }

  public getApp(): Hono {
    return this.app;
  }
}
