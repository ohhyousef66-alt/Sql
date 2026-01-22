#!/bin/bash
#
# PROOF OF WORK TEST - LIVE EXECUTION
# This script runs the complete end-to-end test
#

echo ""
echo "████████████████████████████████████████████████████████████████████████████████"
echo "██                                                                            ██"
echo "██    🔥 SQL INJECTION SCANNER + DUMPER - PROOF OF WORK TEST 🔥               ██"
echo "██                                                                            ██"
echo "████████████████████████████████████████████████████████████████████████████████"
echo ""
echo "This test will PROVE the system works by:"
echo "  ✓ Scanning a vulnerable target"
echo "  ✓ Finding SQL injection"
echo "  ✓ Triggering the Dumper automatically"
echo "  ✓ Extracting database names"
echo "  ✓ Saving results to PostgreSQL"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
  echo "⚠️  WARNING: DATABASE_URL not found in environment"
  echo "   Checking for .env file..."
  
  if [ -f ".env" ]; then
    echo "   ✅ Found .env file, loading..."
    export $(cat .env | xargs)
  else
    echo "   ❌ No .env file found. Creating from .env.example..."
    cp .env.example .env
    echo "   ✅ Created .env - using local PostgreSQL"
    export $(cat .env | xargs)
  fi
fi

echo "📊 Configuration:"
echo "   Database: ${DATABASE_URL:0:30}..."
echo "   Node Environment: ${NODE_ENV:-development}"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Ensure database schema is up to date
echo "🔧 Preparing database..."
npm run db:push 2>&1 | tail -10
echo ""

# Run the test
echo "🚀 Starting proof-of-work test..."
echo ""
tsx proof-test.ts

# Capture exit code
TEST_EXIT_CODE=$?

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
  echo "✅ TEST COMPLETED SUCCESSFULLY!"
else
  echo "❌ TEST FAILED - Exit code: $TEST_EXIT_CODE"
  echo "   Check the logs above for errors"
fi

echo ""
echo "████████████████████████████████████████████████████████████████████████████████"
echo ""

exit $TEST_EXIT_CODE
