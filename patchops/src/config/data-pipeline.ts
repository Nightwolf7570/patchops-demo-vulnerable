import { config } from 'dotenv';

config();

// Data pipeline configuration
export const DATA_PIPELINE_CONFIG = {
  firecrawl: {
    apiKey: process.env.FIRECRAWL_API_KEY || '',
    maxCreditsPerScan: 50, // Conservative for free tier
    rateLimitDelay: 1000, // 1 second between requests
    retryAttempts: 3,
  },
  scanning: {
    intervalHours: parseInt(process.env.SCAN_INTERVAL_HOURS || '6', 10),
    monitoredRepositories: (process.env.MONITORED_REPOSITORIES || '').split(',').filter(Boolean),
    vulnerabilityDbPath: process.env.VULNERABILITY_DB_PATH || './data/vulnerabilities.db',
    enableZeroDayMonitoring: process.env.ENABLE_ZERO_DAY_MONITORING === 'true',
  },
  sources: {
    github: {
      baseUrl: 'https://github.com/advisories',
      ecosystems: ['npm', 'pip', 'maven', 'nuget'],
      maxPages: 10, // Limit for free tier
    },
    osv: {
      baseUrl: 'https://api.osv.dev/v1',
      batchSize: 10, // Batch queries for efficiency
    },
  },
  analysis: {
    criticalHitThreshold: 70, // Threat score threshold for Critical Hits
    zerodayAgeHours: 168, // 7 days to consider something "zero-day"
    importPatterns: {
      npm: [
        /import\s+.*\s+from\s+['"]([^'"]+)['"]/g,
        /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      ],
      pip: [
        /import\s+([^\s]+)/g,
        /from\s+([^\s]+)\s+import/g,
      ],
    },
  },
};

// Validate data pipeline configuration
export function validateDataPipelineConfig(): void {
  const { firecrawl, scanning } = DATA_PIPELINE_CONFIG;
  
  if (!firecrawl.apiKey) {
    console.warn('⚠️  FIRECRAWL_API_KEY not set. GitHub advisory scraping will be limited.');
  }
  
  if (scanning.monitoredRepositories.length === 0) {
    console.warn('⚠️  No repositories configured for monitoring. Set MONITORED_REPOSITORIES in .env.');
  }
  
  if (scanning.intervalHours < 1) {
    console.warn('⚠️  Scan interval too frequent. Minimum recommended: 1 hour.');
  }
}