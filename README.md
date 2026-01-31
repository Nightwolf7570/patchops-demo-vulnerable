# Recall-Radar / PatchOps

**Autonomous Dependency Guardian**

An end-to-end system that monitors vulnerabilities, analyzes impact on your repositories, generates concrete patch plans, and automatically creates pull requests to fix security issues.

## 🎯 What It Does

1. **Ingests** vulnerability data (CVEs, security advisories)
2. **Analyzes** impact on your specific repository
3. **Generates** detailed patch plans with evidence
4. **Creates** pull requests with version bumps and migration guides

## 🚀 Quick Start

```bash
cd patchops
npm install
npm run demo
```

This will analyze the axios vulnerability and create a real PR in the demo repository.

## 📁 Structure

- `patchops/` - Main application
  - `src/patch-logic/` - Vulnerability analysis & patch planning
  - `src/github-bot/` - GitHub API integration
  - `src/api/` - REST API server
- `patchops-demo-vulnerable/` - Test repository with vulnerable dependencies

## 📖 Documentation

See [patchops/README.md](patchops/README.md) for full documentation.

## 🎬 Demo

**Live PR Example:** https://github.com/Nightwolf7570/patchops-demo-vulnerable/pull/1

Run the demo script:
```bash
cd patchops
./demo.sh
```

## 🛠️ Built With

- TypeScript
- Hono (API server)
- Octokit (GitHub API)
- OpenRouter (LLM - mocked for demo)
- Semver (version analysis)

## 📄 License

MIT
