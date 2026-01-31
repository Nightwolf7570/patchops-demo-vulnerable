#!/bin/bash

# PatchOps Demo Script
# This script demonstrates the full PatchOps workflow

set -e

echo "🎬 PatchOps Demo Script"
echo "======================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Check prerequisites${NC}"
echo "------------------------------"

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: Must run from patchops directory"
    exit 1
fi

echo "✅ In patchops directory"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  Creating .env file..."
    cp .env.example .env
    echo "✅ .env created (edit with your tokens)"
else
    echo "✅ .env file exists"
fi

echo ""
echo -e "${BLUE}Step 2: Install dependencies${NC}"
echo "------------------------------"

if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install --legacy-peer-deps
else
    echo "✅ Dependencies already installed"
fi

echo ""
echo -e "${BLUE}Step 3: Build project${NC}"
echo "------------------------------"

npm run build
echo "✅ Build complete"

echo ""
echo -e "${BLUE}Step 4: Run tests${NC}"
echo "------------------------------"

echo "🧪 Testing PatchAnalyzer..."
npx tsx src/patch-logic/test-analyzer.ts 2>&1 | grep -E "(Testing|Results|passed)" || true

echo ""
echo "🧪 Testing GitHubBot..."
npx tsx src/github-bot/test-bot.ts 2>&1 | grep -E "(Testing|Repo found|package.json|complete)" || true

echo ""
echo -e "${YELLOW}Step 5: Run FULL DEMO${NC}"
echo "------------------------------"
echo "This will:"
echo "  1. Analyze axios vulnerability (CVE-2020-28168)"
echo "  2. Generate patch plan"
echo "  3. Create a PR in the demo repo"
echo ""
echo -e "${GREEN}Press Enter to continue...${NC}"
read

echo "🚀 Running demo..."
npm run demo

echo ""
echo -e "${GREEN}✅ Demo complete!${NC}"
echo ""
echo "Check your PR at:"
echo "  https://github.com/Nightwolf7570/patchops-demo-vulnerable/pulls"
echo ""
echo "Next steps:"
echo "  1. Review the PR that was created"
echo "  2. Start the server: npm run dev"
echo "  3. Test API endpoints (see README.md)"
echo ""
