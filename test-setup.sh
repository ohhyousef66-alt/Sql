#!/bin/bash

# SQL Injection Scanner - Quick Test Script
# This script sets up the environment and tests the scanner

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║   SQL Injection Scanner - Quick Test Setup                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+"
    exit 1
fi
echo "✅ Node.js $(node --version) found"

# Check npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed"
    exit 1
fi
echo "✅ npm $(npm --version) found"

# Check git
if ! command -v git &> /dev/null; then
    echo "❌ git is not installed"
    exit 1
fi
echo "✅ git found"

echo ""
echo "📋 Project Status:"
npm run check > /dev/null 2>&1 && echo "✅ TypeScript compilation: PASS" || echo "❌ TypeScript compilation: FAIL"
echo ""

# Build the project
echo "🔨 Building project..."
npm run build > /dev/null 2>&1 && echo "✅ Build: SUCCESS" || echo "❌ Build: FAILED"
echo ""

echo "📦 Project is ready for testing!"
echo ""
echo "Next steps:"
echo "1. Set up PostgreSQL database"
echo "2. Configure DATABASE_URL environment variable"
echo "3. Run migrations: npm run db:push"
echo "4. Start dev server: npm run dev"
echo "5. Visit http://localhost:3000"
echo ""
echo "To test against testphp.vulnweb.com:"
echo "  POST http://localhost:3000/api/scans"
echo "  Body: {\"targetUrl\": \"http://testphp.vulnweb.com/artists.php\", \"scanMode\": \"sqli\", \"threads\": 10}"
echo ""
echo "See TESTING_GUIDE.md for detailed instructions"
