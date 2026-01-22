# 🧪 Testing Guide - Clean Core Protocol

## Quick Test Commands

### 1️⃣ **Single URL Scan (Deep Mode)**
```bash
curl -X POST http://localhost:3000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php?artist=1",
    "scanMode": "sqli",
    "threads": 10
  }'
```

**Expected Behavior:**
- Scanner tests ALL SQL injection types (error, boolean, time, union)
- When SQLi detected → Dumper is triggered automatically
- Dumper attempts to extract database name
- **IF success:** Vulnerability reported with DB info
- **IF failure:** Detection discarded (no false positive)

---

### 2️⃣ **Batch Scan (5 URLs - Unified Engine)**
```bash
curl -X POST http://localhost:3000/api/scans/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrls": [
      "http://testphp.vulnweb.com/artists.php?artist=1",
      "http://testphp.vulnweb.com/listproducts.php?cat=1",
      "http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg",
      "http://demo.testfire.net/bank/main.jsp",
      "http://demo.testfire.net/bank/login.jsp"
    ],
    "scanMode": "sqli",
    "threads": 10
  }'
```

**Expected Behavior:**
- SAME scanning depth as single URL
- SAME payloads tested
- SAME verification loop for each URL
- Each URL scanned with full quality

---

### 3️⃣ **Monitor Scan Progress**
```bash
# Get scan details
curl http://localhost:3000/api/scans/1

# Get vulnerabilities (only verified ones will appear)
curl http://localhost:3000/api/scans/1/vulnerabilities

# Get scan logs (check for verification loop messages)
curl http://localhost:3000/api/scans/1/logs | grep "Verification Loop"
```

**Look for these log entries:**
```
🔬 [Verification Loop] SQLi detected on id - Testing with Dumper BEFORE reporting...
🔍 [Dumper Verification] Attempting to extract database name...
✅ [Verification Loop] VERIFIED - Dumper extracted data: Database: acuart, Version: 5.7.33
✅ [Verification Loop] Vulnerability REPORTED after successful verification
🛑 [Stop-on-Success] Target is verified vulnerable - STOPPING scan
```

Or if dumper fails:
```
❌ [Verification Loop] DISCARDED - Dumper could not verify: Dumper could not extract database name
```

---

## 🔍 Verification Checklist

### ✅ **Test: Batch vs Single Quality Match**

1. Run single URL scan → Note number of payloads tested
2. Run batch scan with same URL → Verify same payload count
3. Check logs for "Quality Assurance" message

**Command to check:**
```bash
# Count payloads from single scan
curl http://localhost:3000/api/scans/1/logs | grep -c "Testing payload"

# Count payloads from batch child scan
curl http://localhost:3000/api/scans/3/logs | grep -c "Testing payload"

# These numbers should be IDENTICAL
```

---

### ✅ **Test: Verification Loop Active**

1. Start scan on vulnerable target
2. Monitor logs in real-time
3. Verify dumper is called BEFORE vulnerability is reported

**Command:**
```bash
# Watch logs live
watch -n 1 'curl -s http://localhost:3000/api/scans/1/logs | tail -n 20'
```

**Expected sequence:**
1. `Testing parameter: id with payload: 1' AND 1=1--`
2. `🔬 [Verification Loop] SQLi detected - Testing with Dumper`
3. `🔍 [Dumper Verification] Attempting to extract database name`
4. `✅ VERIFIED - Dumper extracted data`
5. `Vulnerability REPORTED`

**Wrong sequence (old behavior):**
1. `Testing parameter: id`
2. `Vulnerability reported` ← **WRONG! Should verify first**

---

### ✅ **Test: Stop-on-Success**

1. Start scan on vulnerable target with multiple parameters
2. Watch for first verified vulnerability
3. Verify scan stops immediately after first success

**Command:**
```bash
curl http://localhost:3000/api/scans/1

# Check completionReason - should mention stop-on-success
```

**Expected:**
```json
{
  "status": "completed",
  "completionReason": "Target verified vulnerable - stopped after first confirmed finding",
  "summary": {
    "confirmed": 1  ← Only 1, not multiple
  }
}
```

---

## 🚨 Red Flags (Things That Should NOT Happen)

### ❌ **FALSE POSITIVES:**
```
Vulnerability reported WITHOUT dumper verification
→ Check logs for "Verification Loop" messages
→ If missing, verification loop is not active
```

### ❌ **QUALITY DEGRADATION:**
```
Batch scan has fewer payloads than single scan
→ Check logs for payload count
→ Both should test exact same payloads
```

### ❌ **MULTIPLE FINDINGS ON ONE TARGET:**
```
Single target reports 5+ SQL injection vulnerabilities
→ Stop-on-success not working
→ Should stop after FIRST verified finding
```

---

## 📊 Success Metrics

| Metric | Target | Command to Verify |
|--------|--------|-------------------|
| False Positive Rate | 0% | Count vulnerabilities that lack DB extraction proof |
| Batch Quality Match | 100% | Compare payload counts: single vs batch |
| Stop-on-Success | ✅ | Max 1 confirmed vuln per target |
| Verification Loop | ✅ | All confirmed vulns have "VERIFIED by Dumper" evidence |

---

## 🎯 Expected Test Results

### **Vulnerable Target (e.g., testphp.vulnweb.com):**
```json
{
  "id": 1,
  "vulnerabilities": [
    {
      "type": "Error-based SQL Injection",
      "severity": "critical",
      "parameter": "artist",
      "evidence": "MySQL error detected\n\n✅ VERIFIED by Dumper: Database: acuart, Version: 5.7.33",
      "verificationStatus": "confirmed"
    }
  ],
  "summary": {
    "confirmed": 1,
    "potential": 0
  }
}
```

### **Non-Vulnerable Target:**
```json
{
  "id": 2,
  "vulnerabilities": [],
  "summary": {
    "confirmed": 0,
    "potential": 0
  }
}
```

**Note:** Even if scanner detects "potential" SQLi, if dumper can't verify, it's discarded.

---

## 🔧 Debugging Tips

### **Issue: Verification Loop Not Triggering**

**Check:**
```bash
curl http://localhost:3000/api/scans/1/logs | grep "Verification Loop"
```

**If empty:** Look for errors in scanner logs
```bash
curl http://localhost:3000/api/scans/1/logs | grep -i "error"
```

### **Issue: Dumper Always Failing**

**Check dumper logs:**
```bash
curl http://localhost:3000/api/scans/1/logs | grep "Dumper Verification"
```

**Common causes:**
- Target blocking extraction queries
- Wrong DB type detection
- Timeout issues

### **Issue: Batch Scan Using "Lite" Mode**

**Verify Quality Assurance log:**
```bash
curl http://localhost:3000/api/scans/3/logs | grep "Quality Assurance"
```

**Expected:**
```
⚙️ [Quality Assurance] Using FULL scanning engine with ALL payloads
```

**If missing:** Batch route might not be using unified engine

---

## 🎉 Success Indicators

When everything is working correctly, you should see:

1. ✅ **Verification messages in logs:**
   ```
   🔬 [Verification Loop] SQLi detected
   ✅ VERIFIED - Dumper extracted data
   🛑 [Stop-on-Success] Stopping scan
   ```

2. ✅ **Vulnerabilities with proof:**
   ```
   evidence: "MySQL error detected\n\n✅ VERIFIED by Dumper: Database: acuart"
   ```

3. ✅ **Batch quality guarantee:**
   ```
   ⚙️ [Quality Assurance] Using FULL scanning engine with ALL payloads
   ```

4. ✅ **No false positives:**
   - All confirmed vulnerabilities have extraction proof
   - Potential findings are discarded if unverified

---

## 📞 Need Help?

Check the comprehensive documentation: [CLEAN_CORE_PROTOCOL.md](./CLEAN_CORE_PROTOCOL.md)
