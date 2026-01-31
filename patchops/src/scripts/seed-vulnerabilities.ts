import { VulnerabilityDatabase } from '../data-pipeline/vulnerability-db.js';
import type { VulnerabilityIntelligence } from '../types/data-pipeline.js';
import { logger } from '../utils/logger.js';

/**
 * Seed database with known vulnerabilities for testing
 */
async function seedVulnerabilities() {
  logger.info('🌱 Seeding vulnerability database...');
  
  const db = new VulnerabilityDatabase();
  
  const knownVulnerabilities: VulnerabilityIntelligence[] = [
    {
      id: 'CVE-2020-28168',
      packageName: 'axios',
      ecosystem: 'npm',
      severity: 'high',
      cvssScore: 7.5,
      affectedVersions: '<0.21.1',
      fixedVersions: '>=0.21.1',
      description: 'Server-Side Request Forgery (SSRF) vulnerability in axios allows attackers to bypass proxy restrictions',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-28168',
        'https://github.com/axios/axios/releases/tag/v0.21.1'
      ],
      source: 'NVD',
      discoveredAt: '2020-11-06T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: true,
      isKEV: true
    },
    {
      id: 'CVE-2021-23337',
      packageName: 'lodash',
      ecosystem: 'npm',
      severity: 'high',
      cvssScore: 7.2,
      affectedVersions: '<4.17.21',
      fixedVersions: '>=4.17.21',
      description: 'Command injection vulnerability in lodash template function',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
        'https://github.com/lodash/lodash/releases/tag/4.17.21'
      ],
      source: 'NVD',
      discoveredAt: '2021-02-15T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: true,
      isKEV: false
    },
    {
      id: 'CVE-2020-7598',
      packageName: 'minimist',
      ecosystem: 'npm',
      severity: 'high',
      cvssScore: 7.5,
      affectedVersions: '<1.2.2',
      fixedVersions: '>=1.2.2',
      description: 'Prototype pollution vulnerability in minimist',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-7598'
      ],
      source: 'NVD',
      discoveredAt: '2020-03-11T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: false,
      isKEV: false
    },
    {
      id: 'CVE-2022-24999',
      packageName: 'express',
      ecosystem: 'npm',
      severity: 'medium',
      cvssScore: 6.1,
      affectedVersions: '<4.17.3',
      fixedVersions: '>=4.17.3',
      description: 'Open redirect vulnerability in express',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2022-24999'
      ],
      source: 'NVD',
      discoveredAt: '2022-02-16T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: false,
      isKEV: false
    },
    {
      id: 'CVE-2021-3918',
      packageName: 'json-schema',
      ecosystem: 'npm',
      severity: 'critical',
      cvssScore: 9.8,
      affectedVersions: '<0.4.0',
      fixedVersions: '>=0.4.0',
      description: 'Prototype pollution vulnerability in json-schema',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-3918'
      ],
      source: 'NVD',
      discoveredAt: '2021-11-13T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: true,
      isKEV: false
    },
    {
      id: 'CVE-2021-23343',
      packageName: 'path-parse',
      ecosystem: 'npm',
      severity: 'high',
      cvssScore: 7.5,
      affectedVersions: '<1.0.7',
      fixedVersions: '>=1.0.7',
      description: 'Regular expression denial of service (ReDoS) in path-parse',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-23343'
      ],
      source: 'NVD',
      discoveredAt: '2021-05-04T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: false,
      isKEV: false
    },
    {
      id: 'CVE-2020-8203',
      packageName: 'lodash',
      ecosystem: 'npm',
      severity: 'high',
      cvssScore: 7.4,
      affectedVersions: '<4.17.19',
      fixedVersions: '>=4.17.19',
      description: 'Prototype pollution vulnerability in lodash',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-8203'
      ],
      source: 'NVD',
      discoveredAt: '2020-07-15T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: true,
      isKEV: false
    },
    {
      id: 'CVE-2022-0155',
      packageName: 'follow-redirects',
      ecosystem: 'npm',
      severity: 'medium',
      cvssScore: 5.9,
      affectedVersions: '<1.14.7',
      fixedVersions: '>=1.14.7',
      description: 'Exposure of sensitive information in follow-redirects',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2022-0155'
      ],
      source: 'NVD',
      discoveredAt: '2022-01-10T00:00:00Z',
      isZeroDay: false,
      exploitAvailable: false,
      isKEV: false
    }
  ];
  
  try {
    for (const vuln of knownVulnerabilities) {
      await db.saveVulnerability(vuln);
      logger.info(`✅ Saved: ${vuln.id} - ${vuln.packageName}`);
    }
    
    logger.info(`🎉 Successfully seeded ${knownVulnerabilities.length} vulnerabilities`);
    
    // Verify
    const testPackages = [
      { name: 'axios', version: '0.19.0', ecosystem: 'npm' as const, isDirect: true, isTransitive: false, manifestFile: 'package.json' },
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm' as const, isDirect: true, isTransitive: false, manifestFile: 'package.json' }
    ];
    
    const found = await db.findVulnerabilities(testPackages);
    logger.info(`🔍 Verification: Found ${found.length} vulnerabilities for test packages`);
    
    await db.close();
  } catch (error) {
    logger.error('❌ Failed to seed vulnerabilities:', error);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  seedVulnerabilities()
    .then(() => {
      logger.info('✅ Seeding complete');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('❌ Seeding failed:', error);
      process.exit(1);
    });
}

export { seedVulnerabilities };
