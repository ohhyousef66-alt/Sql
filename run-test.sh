#!/bin/bash

echo "=========================================="
echo "🧪 VERIFICATION LOOP TEST"
echo "=========================================="
echo ""

# Start server in background
echo "🚀 Starting development server..."
npm run dev > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
echo "⏳ Waiting for server to initialize..."
sleep 8

# Run the test
echo ""
echo "=========================================="
echo "🎯 EXECUTING VERIFICATION LOOP TEST"
echo "=========================================="
echo ""

tsx test-verification-loop.ts

# Show results
echo ""
echo "=========================================="
echo "📊 TEST COMPLETE"
echo "=========================================="

# Kill server
kill $SERVER_PID 2>/dev/null

echo ""
echo "✅ Verification loop test finished!"
echo "Check the output above for database extraction proof."
