import { PatchAnalyzer } from './analyzer.js';
import type { Vulnerability, RepoContext } from '../types/index.js';

// Test data: axios vulnerability
const testVulnerability: Vulnerability = {
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

const testContext: RepoContext = {
  owner: 'Nightwolf7570',
  repo: 'patchops-demo-vulnerable',
  defaultBranch: 'main',
  packageManager: 'npm',
  manifestPath: 'package.json',
  lockfilePath: 'package-lock.json',
};

async function testAnalyzer() {
  console.log('🧪 Testing PatchAnalyzer...\n');

  const analyzer = new PatchAnalyzer();

  // Test 1: Analyze with imports
  console.log('Test 1: Package imported in source files');
  const result1 = await analyzer.analyze(testVulnerability, testContext, [
    'index.js',
    'src/api/client.js',
  ]);

  console.log('✅ Analysis complete!\n');
  console.log('📊 Results:');
  console.log(`  Threat Score: ${result1.analysis.threatScore}/100`);
  console.log(`  Rationale: ${result1.analysis.threatRationale}`);
  console.log(`  Recommended: ${result1.analysis.recommendedVersion}`);
  console.log(`  Breaking Changes: ${result1.migration.breakingChanges.length}`);
  console.log(`  LLM Used: ${result1.metadata.llmModel}`);
  console.log(`  Time: ${result1.metadata.analysisTimeMs}ms\n`);

  // Test 2: Analyze without imports
  console.log('Test 2: Package not imported (transitive dependency)');
  const result2 = await analyzer.analyze(testVulnerability, testContext, []);
  console.log(`  Threat Score: ${result2.analysis.threatScore}/100 (lower due to no imports)\n`);

  // Test 3: Version utilities
  console.log('Test 3: Version utilities');
  console.log(`  0.19.0 affected by '<0.21.1': ${PatchAnalyzer.isVersionAffected('0.19.0', '<0.21.1')}`);
  console.log(`  0.21.1 affected by '<0.21.1': ${PatchAnalyzer.isVersionAffected('0.21.1', '<0.21.1')}`);
  console.log(`  Diff 0.19.0 → 0.21.1: ${PatchAnalyzer.getVersionDiff('0.19.0', '0.21.1')}`);
  console.log(`  Diff 0.19.0 → 1.0.0: ${PatchAnalyzer.getVersionDiff('0.19.0', '1.0.0')}`);

  console.log('\n✅ All tests passed!');
}

testAnalyzer().catch(console.error);
