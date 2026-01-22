# 🏗️ ARCHITECTURE DIAGRAM - Clean Core Protocol

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER SUBMITS TARGETS                            │
│                                                                          │
│  Option 1: Single URL          Option 2: Batch (1-50,000 URLs)         │
│  POST /api/scans               POST /api/scans/batch                    │
│  { targetUrl: "..." }          { targetUrls: ["...", "..."] }          │
└───────────────┬───────────────────────────────┬─────────────────────────┘
                │                                │
                ▼                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                     UNIFIED SCANNING ENGINE                                │
│                   VulnerabilityScanner Class                              │
│                                                                           │
│  ⚙️ SAME engine for ALL URLs - NO "lite" mode                            │
│  ⚙️ SAME payloads tested - NO reduced depth                              │
│  ⚙️ SAME quality guarantees                                               │
└─────────────────────────────┬─────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SCANNING PROCESS                                      │
│                                                                          │
│  1. Crawl & discover parameters                                         │
│  2. Test each parameter with ALL SQLi payloads                          │
│     ├─ Error-based SQLi                                                 │
│     ├─ Boolean-based SQLi                                               │
│     ├─ Time-based SQLi                                                  │
│     └─ Union-based SQLi                                                 │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│               🔬 POTENTIAL SQLi DETECTED                                 │
│                                                                          │
│  Traditional Scanner: Report immediately → FALSE POSITIVES ❌            │
│  Clean Core: PAUSE and verify → NO FALSE POSITIVES ✅                   │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│          🔍 VERIFICATION LOOP - The Core Innovation                      │
│                                                                          │
│  Step 1: PAUSE reporting (do NOT show in UI yet)                        │
│  Step 2: Trigger Dumper silently                                        │
│  Step 3: Attempt to extract database name                               │
│                                                                          │
│  ┌─────────────────────────────────────────────────┐                    │
│  │    DataDumpingEngine.getCurrentDatabaseInfo()   │                    │
│  │                                                  │                    │
│  │    Sends: database(), version(), user()         │                    │
│  │    Parses: HTML response with strict regex      │                    │
│  │    Returns: { currentDb, version, user }        │                    │
│  └─────────────────────────────────────────────────┘                    │
│                                                                          │
└──────────────────┬────────────────────────────────┬─────────────────────┘
                   │                                │
       ✅ SUCCESS │                                │ ❌ FAILURE
                   ▼                                ▼
┌───────────────────────────────────┐  ┌──────────────────────────────────┐
│     VERIFIED VULNERABILITY         │  │     DISCARD RESULT               │
│                                    │  │                                  │
│  ✅ Dumper extracted data:         │  │  ❌ Dumper failed to extract     │
│     Database: shop_db              │  │     data - likely false positive │
│     Version: MySQL 5.7.33          │  │                                  │
│     User: www-data                 │  │  ➡️ Do NOT report                │
│                                    │  │  ➡️ Continue scanning            │
│  ➡️ Report vulnerability with      │  │  ➡️ No UI notification           │
│     extraction proof               │  │                                  │
│  ➡️ Update evidence field          │  │  Result: ZERO false positives   │
│  ➡️ Show in UI (GREEN)             │  │                                  │
│                                    │  │                                  │
│  ⬇️ THEN...                        │  │                                  │
│                                    │  │                                  │
│  🛑 STOP-ON-SUCCESS:               │  │                                  │
│     Target is pwned - stop scan    │  │                                  │
│     No need to test more params    │  │                                  │
│                                    │  │                                  │
└────────────────────────────────────┘  └──────────────────────────────────┘
```

---

## 🔄 Flow Comparison

### ❌ **OLD ARCHITECTURE (Before)**

```
URL Input → Batch Scanner → Stage 1 → Stage 2 → Stage 3 → Stage 4 → Stage 5
              ↓                                                        ↓
       Mass Scanner                                              Report ALL
              ↓                                                   (+ False Positives)
        Lite Mode
     (Reduced Payloads)
```

**Problems:**
- Multiple scanning modes (single, batch, mass)
- Different quality levels (lite vs full)
- No verification - false positives reported
- Complex stage system
- Different code paths = bugs

---

### ✅ **NEW ARCHITECTURE (After)**

```
URL Input (1 or 50,000) → Unified Scanner → Detect SQLi → Verify with Dumper
                              ↓                              ↓
                        Full Quality                    Extract Data
                        ALL Payloads                         ↓
                                                    ┌────────┴────────┐
                                                    │                 │
                                                SUCCESS           FAILURE
                                                    │                 │
                                                Report           Discard
                                                    │
                                                STOP SCAN
                                             (Target Pwned)
```

**Benefits:**
- ONE scanner for all use cases
- SAME quality always
- Verification prevents false positives
- Simple architecture
- Single code path = reliable

---

## 🎯 Key Architectural Principles

### 1️⃣ **Unified Engine**
```typescript
// BEFORE: Different scanners for different modes
if (mode === "mass") {
  new MassScanner().scan() // Lite mode
} else if (mode === "batch") {
  new BatchScanner().scan() // Medium mode
} else {
  new VulnerabilityScanner().scan() // Full mode
}

// AFTER: ONE scanner for ALL
new VulnerabilityScanner(scanId, url, "sqli", threads).run()
// ↑ Same quality whether scanning 1 or 50,000 URLs
```

### 2️⃣ **Verification Loop**
```typescript
// BEFORE: Report immediately (false positives)
if (sqlInjectionDetected) {
  reportVulnerability() // ❌ Not verified!
}

// AFTER: Verify before reporting (zero false positives)
if (sqlInjectionDetected) {
  const verified = await verifyWithDumper(vulnerability)
  if (verified) {
    reportVulnerability() // ✅ Verified with data extraction!
  } else {
    discard() // ❌ Can't extract data = false positive
  }
}
```

### 3️⃣ **Stop-on-Success**
```typescript
// BEFORE: Scan everything (wasted time)
for (param in parameters) {
  testSQLi(param)
  if (vulnerable) {
    report(param) // Keep scanning...
  }
}
// Result: 10 vulnerabilities reported for same target

// AFTER: Stop after first verified finding
for (param in parameters) {
  testSQLi(param)
  if (vulnerable && verifiedByDumper) {
    report(param)
    stopScan() // ✅ Target is pwned - done!
    break
  }
}
// Result: 1 verified vulnerability = efficient
```

---

## 📊 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INPUT LAYER                                  │
├─────────────────────────────────────────────────────────────────────┤
│  • Single URL: http://target.com/page.php?id=1                      │
│  • Batch URLs: ["url1", "url2", ..., "url50000"]                    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SCAN ORCHESTRATION                              │
├─────────────────────────────────────────────────────────────────────┤
│  FOR EACH URL:                                                       │
│    scanId = createScan(url)                                         │
│    scanner = new VulnerabilityScanner(scanId, url, "sqli", threads)│
│    scanner.run()                                                     │
│                                                                      │
│  ⚙️ Queue: [Scan #1, Scan #2, ..., Scan #N]                         │
│  ⚙️ Each scan runs INDEPENDENTLY with FULL quality                  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   DETECTION ENGINE (SQLiModule)                      │
├─────────────────────────────────────────────────────────────────────┤
│  • Crawl target                                                      │
│  • Discover parameters (GET, POST, headers, cookies)                │
│  • For each parameter:                                               │
│    ├─ Test with error-based payloads                                │
│    ├─ Test with boolean-based payloads                              │
│    ├─ Test with time-based payloads                                 │
│    └─ Test with union-based payloads                                │
│                                                                      │
│  IF suspicious response detected:                                    │
│    → Trigger verification loop                                       │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│             VERIFICATION ENGINE (DataDumpingEngine)                  │
├─────────────────────────────────────────────────────────────────────┤
│  Input: Vulnerability candidate                                      │
│  ├─ URL: http://target.com/page.php?id=1'                          │
│  ├─ Parameter: id                                                    │
│  ├─ Payload: 1' AND 1=1--                                           │
│  └─ Evidence: MySQL error detected                                  │
│                                                                      │
│  Process:                                                            │
│  1. Create dumping context                                           │
│  2. Send extraction query: database()                                │
│  3. Parse response with strict regex                                 │
│  4. Return result                                                    │
│                                                                      │
│  Output:                                                             │
│  ├─ Success: { verified: true, extractedData: "DB: shop_db" }      │
│  └─ Failure: { verified: false, reason: "No data extracted" }      │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      OUTPUT LAYER                                    │
├─────────────────────────────────────────────────────────────────────┤
│  IF verified:                                                        │
│    ✅ Create vulnerability record                                    │
│    ✅ Update evidence with extraction proof                          │
│    ✅ Show in UI with green badge                                    │
│    ✅ Stop scanning this target                                      │
│                                                                      │
│  IF not verified:                                                    │
│    ❌ Discard result                                                 │
│    ❌ Log as false positive                                          │
│    ❌ Continue scanning                                              │
│    ❌ No UI notification                                             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🎉 Summary

**The Clean Core Protocol transforms the scanner from:**
- ❌ Complex multi-mode system → ✅ Simple unified engine
- ❌ False positives reported → ✅ Verified findings only
- ❌ Inconsistent quality → ✅ Guaranteed quality
- ❌ Wasted scanning time → ✅ Stop-on-success

**Result:** A "Heavy" scanner that scales - Quality over Speed.
