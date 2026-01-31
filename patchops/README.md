# PatchOps — Autonomous Dependency Guardian

An end-to-end system that automatically detects vulnerabilities in your dependencies, generates concrete patch plans with evidence, and creates pull requests to fix them.

## 🎯 What It Does

**Input:** A vulnerability (CVE/advisory) + your repository  
**Output:** A pull request with:
- Updated dependency version
- Detailed security analysis
- Migration plan with breaking change warnings
- Testing checklist
- Rollback instructions

## 🚀 Quick Start

### 1. Clone & Install
```bash
cd patchops
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your GitHub token (already set for demo)
```

### 3. Run Demo
```bash
npm run demo
```

This will:
- Analyze the axios vulnerability in the demo repo
- Generate a patch plan
- Create a PR with the fix

### 4. Start API Server
```bash
npm run dev
```

Server runs on `http://localhost:3000`

## 📡 API Endpoints

### Health Check
```bash
curl http://localhost:3000/health
```

### Analyze Vulnerability
```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability": {
      "id": "CVE-2020-28168",
      "packageName": "axios",
      "currentVersion": "0.19.0",
      "severity": "high",
      "description": "SSRF vulnerability",
      "affectedVersions": "<0.21.1",
      "fixedVersions": ">=0.21.1"
    },
    "context": {
      "owner": "Nightwolf7570",
      "repo": "patchops-demo-vulnerable",
      "defaultBranch": "main",
      "packageManager": "npm"
    },
    "importedFiles": ["index.js"]
  }'
```

### Full Workflow (Analyze + Create PR)
```bash
curl -X POST http://localhost:3000/process-vulnerability \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability": { ... },
    "context": { ... },
    "importedFiles": ["index.js"]
  }'
```

### Quick Demo
```bash
curl -X POST http://localhost:3000/demo/axios
```

## 🏗️ Architecture

```
┌─────────────────┐
│  Vulnerability  │
│    Input        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ PatchAnalyzer   │────▶│   LLM (Mocked)  │
│                 │     │                 │
│ • Impact check  │     │ • Evidence      │
│ • Threat score  │     │ • Migration     │
│ • Version diff  │     │ • Breaking chg  │
└────────┬────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│   PatchPlan     │
│                 │
│ • Evidence      │
│ • Threat score  │
│ • Fix version   │
│ • Test list     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│   GitHubBot     │────▶│   GitHub API    │
│                 │     │                 │
│ • Create branch │     │ • Branch        │
│ • Update files  │     │ • Commit        │
│ • Create PR     │     │ • PR            │
└─────────────────┘     └─────────────────┘
```

## 📁 Project Structure

```
patchops/
├── src/
│   ├── patch-logic/
│   │   ├── analyzer.ts      # LLM-powered patch analysis
│   │   └── test-analyzer.ts # Test suite
│   ├── github-bot/
│   │   ├── client.ts        # GitHub API wrapper
│   │   └── test-bot.ts      # Connectivity tests
│   ├── api/
│   │   └── server.ts        # Hono API server
│   ├── types/
│   │   └── index.ts         # TypeScript interfaces
│   ├── config/
│   │   └── index.ts         # Configuration
│   ├── utils/
│   │   └── logger.ts        # Logging utility
│   └── index.ts             # CLI entry point
├── .env                     # Environment variables
└── package.json
```

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | ✅ Yes | GitHub Personal Access Token with `repo` scope |
| `BOT_NAME` | ❌ No | Bot display name (default: "PatchBot") |
| `BOT_EMAIL` | ❌ No | Bot email for commits (default: "patchbot@patchops.dev") |
| `OPENROUTER_API_KEY` | ❌ No | For real LLM analysis (mocked if not set) |
| `PORT` | ❌ No | Server port (default: 3000) |
| `LOG_LEVEL` | ❌ No | debug, info, warn, error (default: info) |

### GitHub Token Permissions
Your token needs:
- `repo` scope (full repository access)
- For creating PRs in the demo repo

### 🤖 Setting Up PatchBot Identity

By default, PRs will be branded with "[PatchBot]" in the title and show the bot name in descriptions. For **true bot identity** (where GitHub shows PRs/commits as coming from a bot user):

**Option 1: Dedicated Bot Account (Recommended)**
1. Create a new GitHub account (e.g., "YourOrg-PatchBot")
2. Generate a Personal Access Token from that account
3. Use that token in your `.env` file
4. PRs will appear as authored by the bot account

**Option 2: GitHub App (Production)**
For production use, create a GitHub App:
1. Go to Settings → Developer settings → GitHub Apps
2. Create new app with `contents:write` and `pull_requests:write` permissions
3. Install app on your repositories
4. Use App authentication instead of PAT

**Current Setup:**
- PR titles: `[PatchBot] Security: Update axios to 0.21.1 (CVE-2020-28168)`
- Commit messages: `[PatchBot] Security: Update package.json`
- Commit author: Uses BOT_NAME and BOT_EMAIL from .env

## 🧪 Testing

### Unit Tests
```bash
npm test
```

### Manual Tests
```bash
# Test analyzer
npx tsx src/patch-logic/test-analyzer.ts

# Test GitHub connectivity
npx tsx src/github-bot/test-bot.ts

# Run full demo
npm run demo
```

## 🎨 Demo Repository

**URL:** https://github.com/Nightwolf7570/patchops-demo-vulnerable

Contains intentionally vulnerable dependencies:
- `axios@0.19.0` (CVE-2020-28168 - SSRF)
- `lodash@4.17.15` (CVE-2019-10744 - Prototype Pollution)

## 🔄 Workflow

### 1. Detection (External)
Your vulnerability monitoring system (OSV, GitHub Advisories, etc.) detects a new CVE.

### 2. Analysis
PatchOps analyzes:
- Is the package in your repo?
- Is it actually imported/used?
- What's the threat score?
- What version should we upgrade to?
- What might break?

### 3. Action
Creates a PR with:
- Version bump in package.json
- Detailed security report
- Migration guide
- Testing checklist

### 4. Review
Human reviews the PR, runs tests, merges if safe.

## 🛣️ Roadmap

### Current (MVP)
- ✅ Single repo support
- ✅ npm/package.json support
- ✅ Mocked LLM analysis
- ✅ GitHub PR creation
- ✅ Basic threat scoring

### Next Steps
- [ ] Real LLM integration (OpenRouter)
- [ ] Multiple package managers (pip, maven)
- [ ] Lockfile updates (package-lock.json)
- [ ] Email notifications (Resend)
- [ ] Webhook actions (ACK, DEFER, ASSIGN)
- [ ] Dependency graph visualization
- [ ] Batch processing (multiple CVEs)
- [ ] CI/CD integration

## 📚 Example PR Output

See: https://github.com/Nightwolf7570/patchops-demo-vulnerable/pull/1

```markdown
## 🔒 Security Patch: CVE-2020-28168

### 📋 Vulnerability Details
- **Package:** axios
- **Current Version:** 0.19.0
- **Recommended Version:** 0.21.1
- **Severity:** HIGH
- **Threat Score:** 75/100

### 🎯 Impact Analysis
✅ **Repository is affected**

Package is imported in 1 file(s): index.js

### 📊 Threat Assessment
HIGH severity vulnerability in axios@0.19.0 actively used in codebase...

### 🛠️ Migration Plan

#### Breaking Changes
- Patch version bump - should be backwards compatible

#### Migration Steps
1. Update axios from 0.19.0 to 0.21.1
2. Run npm install to update lockfile
3. Run test suite to verify functionality

#### Testing Checklist
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] No new console warnings
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a PR

## 📄 License

MIT License - see LICENSE file

## 🆘 Support

- Open an issue for bugs
- Check the demo repo for examples
- Review the test files for usage patterns

---

**Built with:** TypeScript • Hono • Octokit • Semver

**Demo:** Try `npm run demo` to see it in action!
