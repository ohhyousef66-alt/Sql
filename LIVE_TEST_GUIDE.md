# 🔬 LIVE TEST EXECUTION GUIDE

## Prerequisites
- Server must be running: `npm run dev`
- PostgreSQL database connected (Railway)

---

## 🎯 TEST 1: Automated Full Cycle Test

This test will automatically execute a complete scan and show all logs.

### Run Command:
```bash
tsx test-verification-loop.ts
```

### What It Does:
1. Creates a scan targeting a known vulnerable site
2. Runs the VulnerabilityScanner
3. Captures all logs including verification loop
4. Shows extracted database names
5. Verifies data persistence in Railway PostgreSQL

### Expected Output:
```
================================================================================
🧪 VERIFICATION LOOP - PROOF OF CONCEPT TEST
================================================================================

📋 Test Configuration:
   Target URL: http://testphp.vulnweb.com/artists.php?artist=1
   Scan Mode: sqli
   Threads: 10

1️⃣ Creating scan record...
   ✅ Scan created with ID: X

2️⃣ Initializing VulnerabilityScanner...
   ✅ Scanner initialized

3️⃣ Starting scan (this will take 2-5 minutes)...
   📡 Watching for verification loop logs...
--------------------------------------------------------------------------------

[Scanner logs will appear here showing:]
- Testing parameter: artist with payload: ...
- 🔬 [Verification Loop] SQLi detected - Testing with Dumper BEFORE reporting
- 🔍 [Dumper Verification] Attempting to extract database name...
- ✅ [Verification Loop] VERIFIED - Dumper extracted data: Database: acuart
- ✅ [Verification Loop] Vulnerability REPORTED after successful verification
- 🛑 [Stop-on-Success] Target is verified vulnerable - STOPPING scan

--------------------------------------------------------------------------------
4️⃣ Scan completed! Fetching results...

================================================================================
📊 SCAN RESULTS
================================================================================

📈 Scan Status:
   Status: completed
   Progress: 100%
   Completion Reason: Target verified vulnerable - stopped after first confirmed finding

🎯 Summary:
   Critical: 1
   High: 0
   Medium: 0
   Confirmed: 1
   Potential: 0

🔒 VERIFIED VULNERABILITIES:
--------------------------------------------------------------------------------

   Type: Error-based SQL Injection
   Severity: CRITICAL
   Parameter: artist
   Confidence: 95%
   Verification: confirmed

   Evidence:
      MySQL error detected in response
      
      ✅ VERIFIED by Dumper: Database: acuart, Version: 5.7.33

   ✅ DUMPER VERIFICATION: SUCCESS
   📊 Extracted Database: acuart
--------------------------------------------------------------------------------

📜 VERIFICATION LOOP LOGS:
--------------------------------------------------------------------------------
   [10:30:15] [INFO] 🔬 [Verification Loop] SQLi detected on artist - Testing with Dumper BEFORE reporting...
   [10:30:16] [INFO] 🔍 [Dumper Verification] Attempting to extract database name...
   [10:30:17] [INFO] ✅ [Verification Loop] VERIFIED - Dumper extracted data: Database: acuart, Version: 5.7.33
   [10:30:17] [INFO] ✅ [Verification Loop] Vulnerability REPORTED after successful verification
   [10:30:17] [INFO] 🛑 [Stop-on-Success] Target is verified vulnerable - STOPPING scan for this target

================================================================================
💾 DATABASE PERSISTENCE CHECK
================================================================================

✅ Vulnerabilities successfully saved to Railway PostgreSQL
   Record Count: 1
   Scan ID: X

✅ Extracted databases found in Railway PostgreSQL:
   - Database: acuart
     Type: mysql
     Method: error-based
     Table Count: 0

================================================================================
🏁 TEST VERDICT
================================================================================

   ✅ Scan execution completed
   ✅ Verification loop logs found
   ✅ 1 verified vulnerability(ies) found
   ✅ Data persisted to Railway PostgreSQL

🎉 SUCCESS: Verification loop is working correctly!
   - Scanner detected vulnerabilities
   - Dumper automatically verified them
   - Extracted data saved to database
   - Zero false positives

================================================================================
```

---

## 🧪 TEST 2: Unit Test (Quick Verification)

This test checks if all components are properly integrated without running a live scan.

### Run Command:
```bash
tsx test-unit-verification.ts
```

### What It Checks:
- ✅ VulnerabilityScanner has verifyWithDumper method
- ✅ DataDumpingEngine has getCurrentDatabaseInfo method
- ✅ Railway PostgreSQL connection working
- ✅ Batch route uses unified engine
- ✅ reportVuln includes verification loop

### Expected Output:
```
================================================================================
🧪 UNIT TEST - Verification Loop Logic
================================================================================

Test 1: Checking if VulnerabilityScanner has verifyWithDumper method...
   ✅ verifyWithDumper method found in VulnerabilityScanner

Test 2: Checking if DataDumpingEngine has getCurrentDatabaseInfo...
   ✅ getCurrentDatabaseInfo method found in DataDumpingEngine

Test 3: Testing Railway PostgreSQL connection...
   ✅ Database connected - found X existing scans

Test 4: Verifying batch route implementation...
   ✅ Batch route marked as unified
   ✅ Batch route uses VulnerabilityScanner

Test 5: Checking reportVuln for verification loop...
   ✅ reportVuln calls verifyWithDumper
   ✅ Verification Loop logging present
   ✅ Stop-on-Success logic present

================================================================================
📊 UNIT TEST SUMMARY
================================================================================

All critical components have been verified.
The verification loop should be functional.
```

---

## 🌐 TEST 3: Manual API Test

Test the scanner via REST API.

### Step 1: Start Server
```bash
npm run dev
```

### Step 2: Create Scan
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php?artist=1",
    "scanMode": "sqli",
    "threads": 10
  }'
```

**Response:**
```json
{
  "id": 1,
  "targetUrl": "http://testphp.vulnweb.com/artists.php?artist=1",
  "status": "pending",
  "scanMode": "sqli"
}
```

### Step 3: Monitor Scan (wait 2-3 minutes)
```bash
# Check scan status
curl http://localhost:3000/api/scans/1

# Watch logs in real-time
watch -n 2 'curl -s http://localhost:3000/api/scans/1/logs | tail -n 20'
```

**Look for these log entries:**
- `🔬 [Verification Loop] SQLi detected`
- `🔍 [Dumper Verification] Attempting to extract database name`
- `✅ [Verification Loop] VERIFIED`
- `🛑 [Stop-on-Success]`

### Step 4: Check Vulnerabilities
```bash
curl http://localhost:3000/api/scans/1/vulnerabilities | jq
```

**Expected:**
```json
[
  {
    "id": 1,
    "scanId": 1,
    "type": "Error-based SQL Injection",
    "severity": "critical",
    "parameter": "artist",
    "evidence": "MySQL error detected\n\n✅ VERIFIED by Dumper: Database: acuart, Version: 5.7.33",
    "verificationStatus": "confirmed"
  }
]
```

### Step 5: Verify Database Persistence
```bash
# Check extracted databases
curl http://localhost:3000/api/scans/1/enumeration | jq
```

**Expected:**
```json
[
  {
    "id": 1,
    "databaseName": "acuart",
    "dbType": "mysql",
    "extractionMethod": "error-based",
    "tableCount": 0
  }
]
```

---

## 🔍 Verification Checklist

After running the tests, verify:

- [ ] Scan completes successfully
- [ ] Logs contain "🔬 [Verification Loop]" messages
- [ ] Vulnerabilities include "✅ VERIFIED by Dumper" in evidence
- [ ] Database name is extracted (e.g., "acuart")
- [ ] Data is persisted to Railway PostgreSQL
- [ ] Stop-on-success triggers after first verified vuln
- [ ] No false positives reported

---

## 🚨 If Tests Fail

### Issue: No Verification Loop Logs

**Check:**
```bash
grep -r "verifyWithDumper" server/scanner/index.ts
```

**Should find:** The method definition and call in reportVuln

**Fix:** Ensure the verification loop code is properly integrated in [server/scanner/index.ts](./server/scanner/index.ts)

---

### Issue: Dumper Fails to Extract

**Check logs for:**
```
❌ [Verification Loop] DISCARDED - Dumper could not verify
```

**Possible causes:**
- Target is not actually vulnerable
- WAF blocking extraction queries
- Network timeout

**Fix:** Try a different known vulnerable URL or check network connectivity

---

### Issue: Database Not Persisted

**Check:**
```bash
echo $DATABASE_URL
```

**Should show:** PostgreSQL connection string for Railway

**Fix:** Ensure DATABASE_URL environment variable is set correctly

---

## 📊 Success Criteria

The verification loop is working correctly if you see:

1. ✅ Scanner detects SQLi (error/boolean/time-based)
2. ✅ Dumper is automatically triggered
3. ✅ Database name is extracted (e.g., "acuart", "shop_db", etc.)
4. ✅ Vulnerability is reported with extraction proof
5. ✅ Data is saved to Railway PostgreSQL
6. ✅ Scan stops after first verified vulnerability

---

## 🎉 Expected Final Output

When everything works correctly, you'll see:

```
🎉 SUCCESS: Verification loop is working correctly!
   - Scanner detected vulnerabilities
   - Dumper automatically verified them
   - Extracted data saved to database
   - Zero false positives
```

**Database Record:**
```sql
SELECT * FROM vulnerabilities WHERE scan_id = 1;
-- Shows vulnerability with "VERIFIED by Dumper" in evidence

SELECT * FROM extracted_databases WHERE scan_id = 1;
-- Shows extracted database: acuart
```

---

## 📞 Support

If tests still fail after following this guide, check:
- [CLEAN_CORE_PROTOCOL.md](./CLEAN_CORE_PROTOCOL.md) - Implementation details
- [server/scanner/index.ts](./server/scanner/index.ts) - Line 390-570 for verification loop
- [server/scanner/data-dumping-engine.ts](./server/scanner/data-dumping-engine.ts) - Line 90-130 for dumper logic
