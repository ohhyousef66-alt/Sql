# SQL Injection Scanning Pipeline - Engineering Documentation

## Architecture Overview

This system implements a **professional staged pipeline** for SQL injection vulnerability testing and post-confirmation enumeration. It prioritizes **determinism, stability, and legal safety** over speed or payload tricks.

---

## Design Principles

1. **Determinism over Guessing** - Every decision based on explicit rules, not random logic
2. **Stability over Speed** - Adaptive pacing prevents overwhelming targets
3. **Methodology over Tricks** - Standards-based approach, not tool-specific payloads
4. **Safety by Default** - Enumeration and data preview DISABLED unless explicitly enabled
5. **Resumable by Design** - Checkpointing allows recovery from interruptions
6. **Auditability** - Complete trail of all actions for legal compliance

---

## Pipeline Stages (Strict Order)

### 1. **Target Normalization**
**Purpose**: Parse and standardize target URL/request

**Outputs**:
- Normalized URL structure
- Query parameters
- Request method and headers
- Cookies and body data

**Gate**: None (entry point)

---

### 2. **Parameter Discovery**
**Purpose**: Identify all potentially injectable parameters

**Outputs**:
- Parameter names and locations (query, path, header, cookie, body)
- Parameter types (string, numeric, boolean, array)
- Injectability assessment per parameter

**Gate**: Target must be normalized

---

### 3. **Vulnerability Confirmation**
**Purpose**: Collect multiple independent confirmation signals

**Process**:
- Test various injection techniques
- Collect confirmation signals with evidence
- Feed signals to Confirmation Gate

**Outputs**:
- Confirmation signals (≥2 required)
- Evidence types (error messages, data extraction, behavioral changes)
- Overall confidence score

**Gate**: 
- Minimum 2 independent signals
- Different techniques (e.g., UNION + Error-based)
- Different evidence types
- Confidence ≥ HIGH (75)

**Critical**: If gate fails, pipeline STOPS. No enumeration allowed.

---

### 4. **Database Fingerprinting**
**Purpose**: Deterministically identify database type and version

**Process**:
- Execute fingerprint tests in decision tree order
- Match responses against expected patterns
- Determine database capabilities

**Outputs**:
- Database type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Version (if detectable)
- Supported features (UNION, error-based, time-based, stacked queries, information_schema)

**Gate**: Vulnerability must be confirmed

---

### 5. **Post-Confirmation Enumeration** (OPT-IN ONLY)
**Purpose**: Extract database schema information

**Critical Requirements**:
- **DISABLED BY DEFAULT**
- Requires explicit user consent
- User must acknowledge legal warnings
- Full audit trail maintained

**Sub-Phases**:
1. **Databases** - Enumerate database names
2. **Tables** - Enumerate tables per database
3. **Columns** - Enumerate columns per table
4. **Data Preview** - (REQUIRES ADDITIONAL CONSENT) Preview limited rows/columns

**Features**:
- Rate limiting with adaptive pacing
- Retry logic with exponential backoff
- Checkpointing for resume after interruption
- Configurable limits (databases, tables, columns, rows)

**Gate**: Database type must be identified, user consent required

---

### 6. **Reporting**
**Purpose**: Generate final report with findings

**Outputs**:
- Complete scan results
- Confirmation evidence
- Database fingerprint
- Enumeration results (if enabled)
- Audit trail

**Gate**: All enabled stages must complete

---

## Core Components

### Confirmation Gate

**Purpose**: Anti-false-positive system requiring multiple independent confirmation signals

**Configuration**:
```typescript
{
  minimumSignals: 2,              // At least 2 signals required
  minimumConfidence: HIGH (75),   // Confidence threshold
  requireDifferentTechniques: true,     // e.g., UNION + Error-based
  requireDifferentEvidenceTypes: true,  // e.g., error_message + union_data
  timeWindowMs: 60000            // Signals must be within 1 minute
}
```

**Decision Process**:
1. Collect confirmation signals from vulnerability testing
2. Verify signal count ≥ minimum
3. Verify technique diversity (if enabled)
4. Verify evidence diversity (if enabled)
5. Calculate weighted confidence score
6. PASS if all requirements met, otherwise BLOCK

**Why This Matters**: Prevents false positives from triggering enumeration

---

### Database Fingerprinter

**Purpose**: Deterministic database type identification using decision tree

**Process**:
1. Execute tests in priority order (most definitive first)
2. Match responses against expected patterns
3. Build confidence scores per database type
4. Select type with highest confidence
5. Extract version if available

**Database-Specific Tests**:
- **MySQL**: `VERSION()`, `@@version_comment`, `DATABASE()`
- **PostgreSQL**: `version()`, `current_database()`
- **MSSQL**: `@@VERSION`, `DB_NAME()`
- **Oracle**: `v$version`, `DUAL` table
- **SQLite**: `sqlite_version()`

**Capabilities Detection**: Automatically determines what techniques database supports

---

### Checkpoint Manager

**Purpose**: Enable resumable operations with granular progress tracking

**Features**:
- Tracks completed databases, tables, columns
- Auto-saves progress every 5 seconds
- Detects already-completed work units
- Survives process restarts

**Resume Logic**:
```typescript
if (checkpointManager.isDatabaseCompleted(dbName)) {
  skip(); // Don't re-enumerate
} else {
  enumerate();
  checkpointManager.markDatabaseCompleted(dbName);
}
```

**Why This Matters**: Long-running enumerations can safely resume after interruption

---

### Enumeration Engine

**Purpose**: Methodologically sound database enumeration with safety controls

**Design Principles**:
- **OPT-IN ONLY**: Will not execute unless explicitly enabled
- **Schema-first**: Default behavior is metadata only, not data
- **Rate-limited**: Configurable delays between requests
- **Retry-safe**: Exponential backoff on failures
- **Chunked**: Small resumable work units

**Configuration Example**:
```typescript
{
  enabled: false,                    // MUST BE FALSE BY DEFAULT
  schemaOnly: true,                  // Metadata only, no data
  databasesEnabled: false,
  tablesEnabled: false,
  columnsEnabled: false,
  dataPreviewEnabled: false,         // MUST BE FALSE BY DEFAULT
  maxDatabases: 50,
  maxTablesPerDatabase: 100,
  maxColumnsPerTable: 50,
  maxRowsPreview: 10,
  maxFieldsPreview: 5,
  requestDelayMs: 1000,              // 1 second between requests
  maxRetries: 3,
  timeoutMs: 10000
}
```

**Query Building**: Database-specific SQL generated based on fingerprint

**Retry Logic**:
- Attempt query with timeout
- If fails, exponential backoff (1s, 2s, 4s, 8s, max 30s)
- Track retry count in checkpoint
- Fail after max retries

---

### Adaptive Pacer

**Purpose**: Automatically adjust scanning speed based on target behavior

**Monitors**:
- Average response latency
- Error rate (failures / total requests)
- Response variance (consistency of timing)
- Consecutive errors and timeouts

**Actions**:
- **Increase Delay** (throttle) if:
  - Error rate > 30%
  - Average latency > 5 seconds
  - High response variance (> 2 seconds)
  
- **Decrease Delay** (speed up) if:
  - System stable (10+ consecutive successes)
  
- **Pause** (temporary halt) if:
  - 5+ consecutive errors
  - 3+ consecutive timeouts

**Adaptation**:
- Delay multiplied/divided by adaptation factor (default 1.5x)
- Respects min/max delay bounds
- Auto-resumes after pause with reset counters

**Why This Matters**: Prevents overwhelming targets, adapts to rate limiting, maintains stability

---

### Response Analyzer

**Purpose**: Noise-resilient comparison of HTTP responses

**Problem**: Raw string comparison breaks with:
- Timestamps (current time in page)
- Session IDs (unique per request)
- Ad blocks (random ads)
- Dynamic content (rotating banners)

**Solution**: Normalization pipeline
1. **Remove Timestamps** - Replace ISO dates, Unix timestamps, time strings
2. **Remove Session IDs** - Replace PHPSESSID, jsessionid, etc.
3. **Remove Dynamic Content** - Remove scripts, styles, comments, iframes
4. **Remove Ads** - Remove Google Analytics, DoubleClick, etc.
5. **Collapse Whitespace** - Normalize spacing

**Comparison Methods**:
- **Structural Fingerprint** - Hash of HTML tag structure
- **Semantic Tokens** - Meaningful words (filtered stopwords)
- **String Similarity** - Levenshtein distance on normalized text

**Weighted Similarity**:
```
Overall = (String * 0.5) + (Tokens * 0.3) + (Structure * 0.2)
```

**Usage**:
```typescript
const result = analyzer.compare(response1, response2, threshold=0.15);
if (result.isDifferent) {
  // Responses differ significantly
}
```

---

### Safety Controls Manager

**Purpose**: Legal and ethical safeguards

**Requirements**:
1. **Enumeration Consent**:
   - User must acknowledge all legal warnings:
     - "I have explicit written authorization to test this target"
     - "I understand that unauthorized access is illegal"
     - "I take full responsibility for all actions performed"
     - "I will not use extracted data for malicious purposes"
   
2. **Data Preview Consent** (additional):
   - Requires enumeration consent first
   - Additional warnings:
     - "I understand that data preview may expose sensitive information"
     - "I will handle any extracted data responsibly"
     - "I will not store or redistribute extracted data without authorization"

**Audit Trail**:
- Every action logged with timestamp
- User consent records preserved
- IP address and User-Agent captured (optional)
- Exportable to JSON for legal compliance

**Production Validation**:
```typescript
SafetyControlsManager.validateProductionConfig(config);
// Returns violations if config unsafe for production
```

**Why This Matters**: Legal protection, accountability, responsible disclosure

---

## State Management

### Immutable State Snapshots

**Principle**: Pipeline state is versioned and immutable

```typescript
interface PipelineState {
  scanId: string;
  targetUrl: string;
  currentStage: ScanStage;
  stages: Map<ScanStage, StageOutput>;  // Immutable snapshots
  checkpoint?: EnumerationCheckpoint;
  createdAt: Date;
  updatedAt: Date;
  version: number;  // Increments on each update
}
```

**Benefits**:
- Time-travel debugging
- Rollback capability
- Concurrent reads safe
- Audit trail built-in

### Per-Target Isolation

**Principle**: Each scan target has completely isolated state

**Rules**:
- No shared mutable memory between scans
- No shared caches or identifiers
- Independent checkpoints
- Separate audit trails

**Why This Matters**: Multi-target scans don't interfere with each other

---

## Progress Tracking (Real, Not Percentages)

**Problem**: Percentages are misleading when work is unpredictable

**Solution**: Expose real units

```typescript
interface RealProgress {
  currentStage: ScanStage;              // What stage we're in
  currentPhase?: EnumerationPhase;      // What enumeration phase (if applicable)
  completedWorkUnits: number;           // Databases/tables/columns completed
  totalWorkUnits: number;               // Total discovered
  remainingWorkUnits: number;           // Still to process
  estimatedOperationsRemaining: number; // Rough estimate of queries left
  lastActivity: string;                 // Human-readable last action
  activeOperations: string[];           // Currently executing
}
```

**Example Output**:
```
Current Stage: post_confirmation_enumeration
Current Phase: tables
Completed Work Units: 15
Total Work Units: 50
Remaining Work Units: 35
Estimated Operations Remaining: 350
Last Activity: Enumerating tables in database 'app_db'
Active Operations: ['enumerate_tables']
```

**Why This Matters**: Users know WHAT is happening and WHY, not just arbitrary %

---

## Failure Modes and Recovery

### Stage Failure
**Symptom**: Stage throws exception

**Response**:
1. Mark stage as FAILED
2. Store error in stage output
3. Block downstream stages
4. Emit `stage_failed` event
5. Allow user to inspect failure
6. Option to retry stage

### Confirmation Gate Failure
**Symptom**: Not enough signals or confidence too low

**Response**:
1. Block enumeration stages
2. Emit `gate_blocked` event
3. Provide recommendation:
   - `collect_more_signals` - Run more tests
   - `reject` - Not a real vulnerability

### Timeout/Freeze
**Symptom**: Stage not progressing

**Response**:
1. Watchdog detects stall (see Watchdog section)
2. Capture diagnostics
3. Save checkpoint
4. Graceful shutdown
5. User can resume from checkpoint

### Network Errors
**Symptom**: Connection failures during enumeration

**Response**:
1. Retry with exponential backoff
2. After max retries, mark work unit as failed
3. Continue to next work unit
4. Checkpoint saves progress
5. Failed units can be retried in resume

---

## Watchdog and Freeze Prevention

### Heartbeat System
**Principle**: Each stage must report heartbeat regularly

```typescript
class StageWatchdog {
  private lastHeartbeat: Date;
  private timeoutMs: number = 60000; // 1 minute
  
  beat(): void {
    this.lastHeartbeat = new Date();
  }
  
  isAlive(): boolean {
    return (Date.now() - this.lastHeartbeat.getTime()) < this.timeoutMs;
  }
}
```

**Usage**:
- Stage calls `watchdog.beat()` regularly
- Watchdog monitors from separate thread
- If no heartbeat for timeout period, declare stall

### Stalled Task Detection
**Indicators**:
- No heartbeat for > timeout
- No checkpoint updates for > 2x timeout
- No event emissions for > timeout

**Recovery**:
1. Log diagnostics (stack traces, memory usage, active promises)
2. Attempt graceful stage cancellation
3. Save current checkpoint
4. Mark stage as FAILED with reason "stalled"
5. Allow user to resume

### Circuit Breaker
**Purpose**: Prevent cascade failures

```typescript
if (consecutiveStageFailures >= 3) {
  pausePipeline();
  emitEvent("circuit_breaker_tripped");
  requireManualReset();
}
```

---

## Testing Strategy

### Internal Test Harness

**Purpose**: Validate each component independently

**Test Targets**:
- Local mock servers (NOT production sites)
- Controlled SQL injection labs
- Synthetic responses with known properties

**Test Cases**:

1. **Confirmation Gate**:
   - Single signal (should BLOCK)
   - Two signals, same technique (should BLOCK if diversity required)
   - Two signals, different techniques (should PASS)
   - Confidence too low (should BLOCK)

2. **Database Fingerprinter**:
   - Mock responses for each database type
   - Version extraction accuracy
   - Fallback to UNKNOWN on ambiguity

3. **Enumeration Engine**:
   - Rate limiting enforcement
   - Retry logic (simulate failures)
   - Checkpoint resume (interrupt mid-enumeration)
   - Proper SQL generation per database type

4. **Adaptive Pacer**:
   - Throttling on high error rate
   - Speeding up when stable
   - Pausing on consecutive failures
   - Resume after pause

5. **Response Analyzer**:
   - Timestamp removal
   - Session ID removal
   - Structural similarity
   - False positive rate (different responses marked similar)
   - False negative rate (similar responses marked different)

6. **Safety Controls**:
   - Enumeration blocked without consent
   - Data preview blocked without consent
   - Audit trail completeness

### Continuous Integration

**Requirements**:
- All tests pass before merge
- No hardcoded production targets
- Test coverage > 80%
- Performance benchmarks (no stage should freeze)

---

## Deployment Configuration

### Development
```typescript
{
  enumeration: {
    enabled: false,  // Manual opt-in per scan
    schemaOnly: true,
    requestDelayMs: 500,
  },
  pacing: {
    baseDelayMs: 500,
    adaptationFactor: 1.5,
  }
}
```

### Production (PUBLIC)
```typescript
{
  enumeration: {
    enabled: false,  // MUST BE FALSE
    dataPreviewEnabled: false,  // MUST BE FALSE
    requestDelayMs: 1000,  // Minimum 1 second
    maxDatabases: 50,
    maxTablesPerDatabase: 100,
    maxRowsPreview: 10,
  },
  pacing: {
    baseDelayMs: 2000,  // More conservative
    errorRateThreshold: 0.2,  // More sensitive
  },
  safety: {
    requireAllLegalWarnings: true,
    logAuditTrailToFile: true,
    auditRetentionDays: 90,
  }
}
```

**Validation**: Use `SafetyControlsManager.validateProductionConfig()` in CI

---

## API Usage Examples

### Basic Scan (Vulnerability Detection Only)

```typescript
import { PipelineController } from './scanner/pipeline';

const pipeline = new PipelineController({
  scanId: 'scan-123',
  targetUrl: 'https://example.com/page?id=1',
  enableEnumeration: false,  // No enumeration
});

// Subscribe to events
pipeline.on('stage_completed', (event) => {
  console.log(`✅ ${event.stage} completed`);
});

pipeline.on('gate_blocked', (event) => {
  console.warn(`⛔ Confirmation gate blocked:`, event.data);
});

// Execute pipeline
const result = await pipeline.execute();

console.log('Final state:', result);
console.log('Audit trail:', pipeline.getAuditTrail());
```

### Scan with Enumeration (Opt-In)

```typescript
const pipeline = new PipelineController({
  scanId: 'scan-456',
  targetUrl: 'https://example.com/page?id=1',
  enableEnumeration: true,
  userConsent: {
    acknowledgedWarnings: [
      "I have explicit written authorization to test this target",
      "I understand that unauthorized access is illegal",
      "I take full responsibility for all actions performed",
      "I will not use extracted data for malicious purposes",
    ],
    metadata: {
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0...',
    },
  },
});

const result = await pipeline.execute();
```

### Monitor Real Progress

```typescript
const progressInterval = setInterval(() => {
  const progress = pipeline.getRealProgress();
  
  console.log(`
Stage: ${progress.currentStage}
Phase: ${progress.currentPhase || 'N/A'}
Completed: ${progress.completedWorkUnits} / ${progress.totalWorkUnits}
Remaining: ${progress.remainingWorkUnits}
Estimated Operations: ${progress.estimatedOperationsRemaining}
Last Activity: ${progress.lastActivity}
Active: ${progress.activeOperations.join(', ')}
  `);
}, 5000);  // Every 5 seconds
```

---

## Performance Characteristics

### Expected Timings (Approximate)

- **Target Normalization**: < 100ms
- **Parameter Discovery**: 100ms - 1s
- **Vulnerability Confirmation**: 5s - 30s (depends on payload count)
- **Database Fingerprinting**: 1s - 5s
- **Enumeration** (if enabled):
  - Databases: 10s - 2min
  - Tables (per database): 30s - 5min
  - Columns (per table): 10s - 1min
- **Reporting**: < 500ms

**Total** (without enumeration): ~30s - 2min
**Total** (with full enumeration): 10min - 1hour (depends on schema size)

### Resource Usage

- **Memory**: ~50MB per scan (isolated state)
- **CPU**: Low (mostly I/O bound)
- **Network**: Adaptive (starts at 1 req/sec, throttles if needed)

### Scalability

- **Concurrent Scans**: Limited by network bandwidth and memory
- **Recommended**: 10-50 concurrent scans depending on hardware
- **Queue-based**: For >50 targets, use multi-target scheduler (see next section)

---

## Multi-Target Scanning (Queue-Based Scheduler)

**Status**: Planned (not yet implemented in this phase)

**Design**:
```typescript
class MultiTargetScheduler {
  private queue: PipelineController[];
  private maxConcurrent: number;
  private active: Map<string, PipelineController>;
  
  async addTarget(config: PipelineConfig): Promise<void> {
    const pipeline = new PipelineController(config);
    this.queue.push(pipeline);
    this.processQueue();
  }
  
  private async processQueue(): Promise<void> {
    while (this.active.size < this.maxConcurrent && this.queue.length > 0) {
      const pipeline = this.queue.shift()!;
      this.active.set(pipeline.config.scanId, pipeline);
      
      pipeline.execute()
        .finally(() => {
          this.active.delete(pipeline.config.scanId);
          this.processQueue();
        });
    }
  }
}
```

**Features**:
- Fair resource distribution
- One slow target doesn't block others
- Per-target isolation maintained
- Global progress tracking

---

## Security Considerations

### What This System DOES

✅ Detect SQL injection vulnerabilities with high confidence
✅ Identify database type and capabilities
✅ Enumerate schema (databases, tables, columns) WITH CONSENT
✅ Provide limited data preview WITH EXPLICIT CONSENT
✅ Maintain audit trail for legal compliance
✅ Adapt to target behavior to avoid overwhelming
✅ Recover from interruptions

### What This System DOES NOT DO

❌ Automatically dump entire databases
❌ Exfiltrate data without user consent
❌ Bypass authentication or authorization
❌ Perform denial-of-service attacks
❌ Exploit vulnerabilities beyond SQL injection
❌ Store extracted data permanently (in-memory only)
❌ Share data with third parties

### Legal Warnings

⚠️ **UNAUTHORIZED USE IS ILLEGAL**

This tool is intended ONLY for:
- Authorized penetration testing
- Security research with explicit permission
- Educational purposes in controlled environments

Users MUST:
- Have written authorization before scanning
- Acknowledge legal warnings
- Take full responsibility for their actions
- Comply with all applicable laws

---

## Maintenance and Extension

### Adding New Database Types

1. Update `DatabaseType` enum in `types.ts`
2. Add fingerprint tests in `DatabaseFingerprinter.initializeTests()`
3. Add capability detection in `DatabaseFingerprinter.getCapabilities()`
4. Add query builders in `EnumerationEngine` for each phase
5. Add tests in test harness

### Adding New Injection Techniques

1. Update `InjectionTechnique` enum in `types.ts`
2. Implement technique tester (returns `ConfirmationSignal`)
3. Integrate into Stage 3 (Vulnerability Confirmation)
4. Add tests for new technique

### Customizing Safety Controls

**DO**:
- Adjust rate limits for specific environments
- Add additional legal warnings
- Extend audit trail with custom fields

**DO NOT**:
- Remove consent requirements
- Disable audit logging
- Enable enumeration by default in production

---

## Troubleshooting

### "Confirmation gate blocked"

**Cause**: Not enough independent confirmation signals

**Solution**:
- Run more varied tests (different techniques)
- Check if responses actually differ (not false positives)
- Review confirmation signals collected
- Consider if target is actually vulnerable

### "Enumeration not allowed"

**Cause**: No user consent or enumeration disabled

**Solution**:
- Enable enumeration in config: `enableEnumeration: true`
- Provide user consent with acknowledged warnings
- Verify safety controls allow it: `safetyControls.isEnumerationAllowed()`

### "Stage stalled"

**Cause**: Watchdog detected no progress

**Solution**:
- Check network connectivity
- Check if target blocking requests
- Review checkpoint to see where it stopped
- Resume from checkpoint after resolving issue

### "Rate limiting detected"

**Cause**: Adaptive pacer detected high error rate or slow responses

**Solution**:
- System is working correctly (auto-throttling)
- Wait for pacing to stabilize
- Consider increasing base delay in config
- Check if target has rate limiting (expected behavior)

---

## Conclusion

This system represents a **professional, legally-sound, methodologically-rigorous approach** to SQL injection testing and post-confirmation enumeration.

**Key Differentiators**:
- Staged pipeline with hard gates (not ad-hoc testing)
- Confirmation requirements (not guessing)
- Deterministic database fingerprinting (not random)
- Opt-in enumeration with consent (not automatic)
- Resumable operations (not restart-from-scratch)
- Adaptive pacing (not fixed speed)
- Safety controls and audit trails (not unchecked)

**Intended Use**: Authorized security testing by professionals

**Not Intended**: Automated exploitation of unauthorized targets

---

## References

- OWASP SQL Injection Testing Guide
- CWE-89: SQL Injection
- PTES (Penetration Testing Execution Standard)
- Responsible Disclosure Guidelines

---

**Document Version**: 1.0
**Last Updated**: 2026-01-21
**Maintained By**: SQL Injection Scanner Engineering Team
