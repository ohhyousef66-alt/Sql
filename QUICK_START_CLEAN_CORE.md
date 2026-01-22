# 🚀 QUICK START - Clean Core Protocol

## ⚡ 3-Minute Verification

### Step 1: Start the Scanner
```bash
npm run dev
```

### Step 2: Test Single URL
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl":"http://testphp.vulnweb.com/artists.php?artist=1","scanMode":"sqli","threads":10}'
```

### Step 3: Verify Logs
```bash
# Wait 30 seconds, then check logs
curl -s http://localhost:3000/api/scans/1/logs | tail -n 30

# Look for these key messages:
✅ "🔬 [Verification Loop] SQLi detected - Testing with Dumper"
✅ "✅ [Verification Loop] VERIFIED - Dumper extracted data"
✅ "🛑 [Stop-on-Success] Target is verified vulnerable"
```

---

## 📋 What to Expect

### ✅ **Correct Behavior (New System):**

1. **Detection Phase:**
   ```
   [Scanner] Testing parameter: artist with payload: 1' AND 1=1--
   [Scanner] MySQL error detected - potential SQLi
   ```

2. **Verification Phase:**
   ```
   🔬 [Verification Loop] SQLi detected on artist - Testing with Dumper BEFORE reporting
   🔍 [Dumper Verification] Attempting to extract database name...
   ✅ [Verification Loop] VERIFIED - Dumper extracted data: Database: acuart, Version: 5.7.33
   ```

3. **Reporting Phase:**
   ```
   ✅ [Verification Loop] Vulnerability REPORTED after successful verification
   🛑 [Stop-on-Success] Target is verified vulnerable - STOPPING scan
   ```

4. **Result:**
   ```json
   {
     "vulnerabilities": [
       {
         "type": "Error-based SQL Injection",
         "severity": "critical",
         "parameter": "artist",
         "evidence": "MySQL error detected\n\n✅ VERIFIED by Dumper: Database: acuart, Version: 5.7.33"
       }
     ]
   }
   ```

---

### ❌ **Wrong Behavior (If Verification Loop Failed):**

If you see this, something is wrong:
```
[Scanner] Testing parameter: artist
[Scanner] MySQL error detected
[Scanner] Vulnerability reported  ← ❌ WRONG! Should verify first!
```

**Missing:** No "Verification Loop" or "Dumper" messages

**What this means:** Verification loop is not active

**Fix:** Check if `verifyWithDumper()` is being called in `reportVuln()`

---

## 🧪 Test Batch Scanning

### Test: 5 URLs with Unified Engine
```bash
curl -X POST http://localhost:3000/api/scans/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrls": [
      "http://testphp.vulnweb.com/artists.php?artist=1",
      "http://testphp.vulnweb.com/listproducts.php?cat=1",
      "http://testphp.vulnweb.com/showimage.php?file=test",
      "http://demo.testfire.net/bank/main.jsp",
      "http://demo.testfire.net/bank/login.jsp"
    ],
    "scanMode": "sqli",
    "threads": 10
  }'
```

### Verify Quality Match:
```bash
# Get parent scan ID from response
PARENT_ID=<response.parentScanId>

# Get child scans
curl -s http://localhost:3000/api/scans/$PARENT_ID/children

# For each child, verify logs show:
✅ "⚙️ [Quality Assurance] Using FULL scanning engine with ALL payloads"
✅ "🔬 [Verification Loop]" messages
✅ Same payload count as single scan
```

---

## 🔍 Health Check Commands

### 1. Check Active Scans
```bash
curl -s http://localhost:3000/api/scans | jq '.[] | {id, status, targetUrl}'
```

### 2. Check Scan Progress
```bash
SCAN_ID=1
curl -s http://localhost:3000/api/scans/$SCAN_ID | jq '{status, progress, summary}'
```

### 3. Check Vulnerabilities (Should Only Show Verified Ones)
```bash
curl -s http://localhost:3000/api/scans/$SCAN_ID/vulnerabilities | jq '.[] | {type, parameter, evidence}'
```

### 4. Check for False Positives
```bash
# If verification loop is working, this should find ZERO results
curl -s http://localhost:3000/api/scans/$SCAN_ID/logs | grep "DISCARDED"
# Example: "❌ [Verification Loop] DISCARDED - Dumper could not verify"
```

---

## 📊 Success Indicators

| Check | Command | Expected Result |
|-------|---------|-----------------|
| Verification Loop Active | `curl ... \| grep "Verification Loop"` | Multiple matches |
| Stop-on-Success Working | `curl ... \| jq '.summary.confirmed'` | Max value: 1 |
| No False Positives | Check evidence field | All contain "VERIFIED by Dumper" |
| Unified Engine | Check batch logs | Contains "Quality Assurance" message |

---

## 🚨 Troubleshooting

### Issue: No Vulnerabilities Found

**Check:**
```bash
curl -s http://localhost:3000/api/scans/1/logs | grep -i "error\|detected\|found"
```

**Possible causes:**
- Target is not vulnerable
- WAF blocking requests
- Network issues

---

### Issue: Vulnerabilities Without Verification

**Check:**
```bash
curl -s http://localhost:3000/api/scans/1/vulnerabilities | jq '.[] | .evidence'
```

**Expected:** ALL should contain "✅ VERIFIED by Dumper"

**If missing:** Verification loop is not running

**Fix:** Check `server/scanner/index.ts` - `reportVuln()` method

---

### Issue: Batch Scan Lower Quality

**Check:**
```bash
# Count payloads in single scan
curl -s http://localhost:3000/api/scans/1/logs | grep -c "Testing payload"

# Count payloads in batch child scan
curl -s http://localhost:3000/api/scans/3/logs | grep -c "Testing payload"
```

**Expected:** IDENTICAL counts

**If different:** Batch route might not be using unified engine

**Fix:** Check `server/routes.ts` - batch route should use `VulnerabilityScanner`

---

## 🎯 Quick Validation Checklist

After implementation, run these checks:

- [ ] Single URL scan shows "Verification Loop" logs
- [ ] Vulnerabilities have "VERIFIED by Dumper" in evidence
- [ ] Batch scan logs show "Quality Assurance" message
- [ ] Batch scan uses SAME payload count as single scan
- [ ] Stop-on-success limits to 1 confirmed vuln per target
- [ ] No compilation errors
- [ ] UI loads without errors

---

## 📞 Need Help?

**Documentation:**
- [CLEAN_CORE_PROTOCOL.md](./CLEAN_CORE_PROTOCOL.md) - Full architecture
- [TESTING_PROTOCOL.md](./TESTING_PROTOCOL.md) - Detailed testing
- [ARCHITECTURE_DIAGRAM.md](./ARCHITECTURE_DIAGRAM.md) - Visual flow

**Key Files:**
- `server/scanner/index.ts` - Verification loop implementation
- `server/routes.ts` - Unified batch scanning
- `server/scanner/data-dumping-engine.ts` - Dumper logic

---

## ✅ You're Ready!

If you see these logs after a scan:
```
🔬 [Verification Loop] SQLi detected
✅ VERIFIED - Dumper extracted data
🛑 [Stop-on-Success] Stopping scan
```

**Congratulations!** The Clean Core Protocol is working perfectly. 🎉
