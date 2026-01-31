# PatchOps Demo - Vulnerable Repository

This repository intentionally contains vulnerable dependencies for testing PatchOps automation.

## ⚠️ Vulnerabilities Present

### axios@0.19.0
- **CVE-2019-10742**: Server-Side Request Forgery (SSRF) - HIGH severity
- **CVE-2020-28168**: SSRF via absolute URL in request path - HIGH severity
- **Affected**: All versions < 0.21.1

### lodash@4.17.15
- **CVE-2019-10744**: Prototype Pollution - CRITICAL severity
- **CVE-2020-8203**: Prototype Pollution in zipObjectDeep - HIGH severity
- **CVE-2021-23337**: Command Injection via template - CRITICAL severity
- **Affected**: All versions < 4.17.21

## 🎯 Purpose

This repo is used to demonstrate:
1. Vulnerability detection in dependencies
2. Impact analysis (checking if vulnerable packages are actually imported)
3. Automated patch plan generation
4. PR creation with version bumps

## 🚫 DO NOT USE IN PRODUCTION

This repository is for educational and testing purposes only.

## 📊 Current State

```
axios:    0.19.0  →  1.6.2  (latest)
lodash:   4.17.15 →  4.17.21 (latest secure)
```

---
*Generated for PatchOps Demo*
