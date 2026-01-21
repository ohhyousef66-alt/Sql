#!/bin/bash

# اختبار تكامل نظام Pipeline مع Scanner

echo "======================================"
echo "🚀 اختبار تكامل Pipeline"
echo "======================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# تحقق من أن الـ server يعمل
echo "${YELLOW}⏳ جاري التحقق من الـ Server...${NC}"
if ! curl -s http://localhost:5000/api/scans > /dev/null 2>&1; then
  echo "${RED}❌ Server لا يعمل. قم بتشغيل: npm run dev${NC}"
  exit 1
fi
echo "${GREEN}✅ Server يعمل${NC}"
echo ""

# Test 1: Single Scan
echo "======================================"
echo "${YELLOW}📊 Test 1: Single Scan${NC}"
echo "======================================"

TARGET="http://testphp.vulnweb.com/artists.php?artist=1"
echo "Target: $TARGET"

# Create scan
echo "${YELLOW}⏳ إنشاء Scan...${NC}"
SCAN_RESPONSE=$(curl -s -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d "{\"targetUrl\": \"$TARGET\", \"scanMode\": \"sqli\", \"threads\": 10}")

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.id')

if [ "$SCAN_ID" = "null" ] || [ -z "$SCAN_ID" ]; then
  echo "${RED}❌ فشل إنشاء Scan${NC}"
  echo "$SCAN_RESPONSE"
  exit 1
fi

echo "${GREEN}✅ Scan ID: $SCAN_ID${NC}"
echo ""

# انتظر قليلاً
echo "${YELLOW}⏳ انتظار بدء الـ Scan (30 ثانية)...${NC}"
sleep 30

# تحقق من الحالة
echo "${YELLOW}⏳ التحقق من حالة الـ Scan...${NC}"
SCAN_STATUS=$(curl -s http://localhost:5000/api/scans/$SCAN_ID | jq -r '.status')
echo "Status: $SCAN_STATUS"
echo ""

# انتظر حتى يكتمل الـ Scan (أو timeout بعد 5 دقائق)
echo "${YELLOW}⏳ انتظار اكتمال الـ Scan...${NC}"
TIMEOUT=300
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
  SCAN_STATUS=$(curl -s http://localhost:5000/api/scans/$SCAN_ID | jq -r '.status')
  
  if [ "$SCAN_STATUS" = "completed" ] || [ "$SCAN_STATUS" = "failed" ]; then
    break
  fi
  
  echo "Status: $SCAN_STATUS (${ELAPSED}s elapsed)"
  sleep 10
  ELAPSED=$((ELAPSED + 10))
done

echo ""
echo "${YELLOW}⏳ الحالة النهائية: $SCAN_STATUS${NC}"
echo ""

# عرض الـ Logs
echo "======================================"
echo "${YELLOW}📋 Scan Logs${NC}"
echo "======================================"
curl -s http://localhost:5000/api/scans/$SCAN_ID/logs | jq -r '.[] | "\(.level | ascii_upcase): \(.message)"' | tail -20
echo ""

# عرض الثغرات
echo "======================================"
echo "${YELLOW}🔍 Vulnerabilities Found${NC}"
echo "======================================"
VULNS=$(curl -s http://localhost:5000/api/scans/$SCAN_ID/vulnerabilities)
VULN_COUNT=$(echo $VULNS | jq '. | length')
echo "Count: $VULN_COUNT"

if [ "$VULN_COUNT" -gt 0 ]; then
  echo "${GREEN}✅ وُجدت ثغرات!${NC}"
  echo $VULNS | jq -r '.[] | "- \(.type): \(.parameter) (Confidence: \(.confidence)%)"' | head -5
else
  echo "${RED}⚠️  لم تُوجد ثغرات${NC}"
fi
echo ""

# عرض نتائج الـ Enumeration
echo "======================================"
echo "${YELLOW}📚 Enumeration Results${NC}"
echo "======================================"
ENUM_RESULTS=$(curl -s http://localhost:5000/api/scans/$SCAN_ID/enumeration)
ENUM_COUNT=$(echo $ENUM_RESULTS | jq '. | length')

if [ "$ENUM_COUNT" -gt 0 ]; then
  echo "${GREEN}✅ Enumeration نجح!${NC}"
  echo "Databases found: $ENUM_COUNT"
  echo ""
  echo $ENUM_RESULTS | jq -r '.[] | "📊 Database: \(.databaseName) (\(.dbType))\n   Tables: \(.tableCount)"'
  echo ""
  
  # عرض تفاصيل أول جدول
  echo "${YELLOW}📋 Table Details (First Database):${NC}"
  echo $ENUM_RESULTS | jq -r '.[0].tables[] | "  - \(.tableName) (\(.columnCount) columns)"' | head -5
else
  echo "${YELLOW}⚠️  لم تُوجد نتائج Enumeration${NC}"
  echo "يمكن أن يكون Enumeration معطلاً أو لم يكتمل بعد"
fi
echo ""

# ملخص
echo "======================================"
echo "${GREEN}✨ ملخص الاختبار${NC}"
echo "======================================"
echo "Scan ID: $SCAN_ID"
echo "Status: $SCAN_STATUS"
echo "Vulnerabilities: $VULN_COUNT"
echo "Enumeration Results: $ENUM_COUNT databases"
echo ""

if [ "$VULN_COUNT" -gt 0 ] && [ "$ENUM_COUNT" -gt 0 ]; then
  echo "${GREEN}✅ الاختبار نجح بالكامل!${NC}"
  exit 0
elif [ "$VULN_COUNT" -gt 0 ]; then
  echo "${YELLOW}⚠️  Vulnerabilities وُجدت لكن Enumeration لم يعمل${NC}"
  echo "راجع الـ Logs أعلاه لمعرفة السبب"
  exit 1
else
  echo "${RED}❌ الاختبار فشل - لم تُوجد ثغرات${NC}"
  exit 1
fi
