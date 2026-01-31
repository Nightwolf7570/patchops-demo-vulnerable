import { GitHubBot } from './client.js';
import type { RepoContext } from '../types/index.js';

const testContext: RepoContext = {
  owner: 'Nightwolf7570',
  repo: 'patchops-demo-vulnerable',
  defaultBranch: 'main',
  packageManager: 'npm',
  manifestPath: 'package.json',
  lockfilePath: 'package-lock.json',
};

async function testGitHubBot() {
  console.log('🧪 Testing GitHubBot...\n');

  const bot = new GitHubBot();

  // Test 1: Get repo info
  console.log('Test 1: Get repository info');
  try {
    const repo = await bot.getRepo(testContext);
    console.log(`  ✅ Repo found: ${repo.full_name}`);
    console.log(`     Default branch: ${repo.default_branch}`);
    console.log(`     Stars: ${repo.stargazers_count}`);
  } catch (error) {
    console.error(`  ❌ Error: ${(error as Error).message}`);
    return;
  }

  // Test 2: Get package.json content
  console.log('\nTest 2: Get package.json');
  try {
    const fileData = await bot.getFileContent(testContext, 'package.json');
    if (fileData) {
      const pkg = JSON.parse(fileData.content);
      console.log(`  ✅ package.json found`);
      console.log(`     Dependencies: ${Object.keys(pkg.dependencies || {}).join(', ')}`);
      console.log(`     axios version: ${pkg.dependencies?.axios}`);
      console.log(`     lodash version: ${pkg.dependencies?.lodash}`);
    } else {
      console.log('  ❌ package.json not found');
    }
  } catch (error) {
    console.error(`  ❌ Error: ${(error as Error).message}`);
  }

  // Test 3: Get index.js content
  console.log('\nTest 3: Get index.js (source file)');
  try {
    const fileData = await bot.getFileContent(testContext, 'index.js');
    if (fileData) {
      console.log(`  ✅ index.js found (${fileData.content.length} bytes)`);
      console.log(`     First 100 chars: ${fileData.content.substring(0, 100)}...`);
    } else {
      console.log('  ❌ index.js not found');
    }
  } catch (error) {
    console.error(`  ❌ Error: ${(error as Error).message}`);
  }

  console.log('\n✅ GitHubBot tests complete!');
  console.log('\n📝 Next: Run full integration test to create a PR');
  console.log('   Command: npm run test:integration');
}

testGitHubBot().catch(console.error);
