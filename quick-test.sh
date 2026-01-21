#!/bin/bash

echo "🚀 Testing Pipeline Integration"
echo "================================"
echo ""

# Create scan
echo "📊 Creating scan..."
RESPONSE=$(curl -s -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl":"http://testphp.vulnweb.com/artists.php?artist=1","scanMode":"sqli","threads":10}')

SCAN_ID=$(echo "$RESPONSE" | jq -r '.id')

if [ "$SCAN_ID" = "null" ] || [ -z "$SCAN_ID" ]; then
  echo "❌ Failed to create scan"
  echo "$RESPONSE"
  exit 1
fi

echo "✅ Scan created: ID=$SCAN_ID"
echo ""

# Wait for scan to progress
echo "⏳ Waiting 60 seconds for scan to progress..."
sleep 60

# Check status
echo ""
echo "📋 Checking scan status..."
STATUS=$(curl -s "http://localhost:5000/api/scans/$SCAN_ID" | jq -r '.status')
PROGRESS=$(curl -s "http://localhost:5000/api/scans/$SCAN_ID" | jq -r '.progress')
VULNS=$(curl -s "http://localhost:5000/api/scans/$SCAN_ID" | jq -r '.vulnerabilitiesFound')

echo "Status: $STATUS"
echo "Progress: $PROGRESS%"
echo "Vulnerabilities Found: $VULNS"
echo ""

# Get vulnerabilities
echo "🔍 Fetching vulnerabilities..."
curl -s "http://localhost:5000/api/scans/$SCAN_ID/vulnerabilities" | jq '.[] | {type, parameter, confidence}' | head -20
echo ""

# Check enumeration results
echo "📚 Checking enumeration results..."
ENUM_RESULTS=$(curl -s "http://localhost:5000/api/scans/$SCAN_ID/enumeration")
DB_COUNT=$(echo "$ENUM_RESULTS" | jq '. | length')

echo "Databases found: $DB_COUNT"

if [ "$DB_COUNT" -gt 0 ]; then
  echo ""
  echo "✅ SUCCESS! Enumeration found databases:"
  echo "$ENUM_RESULTS" | jq '.[] | {databaseName, dbType, tableCount}'
else
  echo "⚠️  No enumeration results yet"
  echo ""
  echo "📋 Checking logs for pipeline activity..."
  curl -s "http://localhost:5000/api/scans/$SCAN_ID/logs" | jq -r '.[] | select(.message | contains("Pipeline") or contains("Confirmation") or contains("Database")) | "\(.level): \(.message)"' | tail -20
fi

echo ""
echo "================================"
echo "Test complete. Scan ID: $SCAN_ID"
