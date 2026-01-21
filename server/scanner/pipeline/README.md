# SQL Injection Scanning Pipeline

A **professional, staged pipeline** for SQL injection vulnerability detection and post-confirmation enumeration with built-in safety controls, resumable operations, and adaptive pacing.

## ⚠️ Legal Warning

**UNAUTHORIZED USE OF THIS TOOL IS ILLEGAL**

This tool is intended ONLY for:
- ✅ Authorized penetration testing with written permission
- ✅ Security research in controlled environments
- ✅ Educational purposes with proper authorization

You MUST have explicit authorization before scanning any target. Unauthorized access to computer systems is illegal in most jurisdictions.

---

## 🎯 Key Features

### ✅ **Safety First**
- Enumeration **DISABLED by default**
- Data preview **DISABLED by default**
- Explicit user consent required
- Complete audit trail
- Legal warnings enforcement

### 🔒 **Anti-False-Positive**
- Confirmation gate requires **multiple independent signals**
- Different technique types required (e.g., UNION + Error-based)
- Confidence scoring system
- Blocks downstream stages if not confirmed

### 🔍 **Deterministic Fingerprinting**
- Decision tree-based database identification
- Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- Capability detection per database type
- Version extraction when available

### 📍 **Resumable Operations**
- Checkpoint system saves progress
- Resume after interruption
- Granular tracking (database, table, column level)
- Never restart from scratch

### 🐢 **Adaptive Pacing**
- Automatically throttles on high error rates
- Speeds up when system stable
- Pauses on consecutive failures
- Prevents overwhelming targets

### 📊 **Real Progress Tracking**
- No misleading percentages
- Shows: current stage, completed work units, remaining operations
- Human-readable activity descriptions
- Real-time event streaming

---

## 📋 Pipeline Stages

```
1. Target Normalization
   ↓
2. Parameter Discovery
   ↓
3. Vulnerability Confirmation
   ↓ (Confirmation Gate - requires ≥2 signals)
4. Database Fingerprinting
   ↓
5. Post-Confirmation Enumeration (OPT-IN)
   ↓
6. Reporting
```

Each stage MUST complete successfully before next stage can execute.

---

## 🚀 Quick Start

### Basic Scan (Detection Only)

```typescript
import { PipelineController } from './scanner/pipeline';

const pipeline = new PipelineController({
  scanId: 'scan-123',
  targetUrl: 'https://example.com/page?id=1',
  enableEnumeration: false,  // No enumeration
});

// Execute
const result = await pipeline.execute();
console.log('Result:', result);
```

### Scan with Enumeration (Requires Consent)

```typescript
import { PipelineController, SafetyControlsManager } from './scanner/pipeline';

// Get legal warnings that must be acknowledged
const warnings = SafetyControlsManager.getLegalWarnings();
console.log('You must acknowledge:', warnings);

const pipeline = new PipelineController({
  scanId: 'scan-456',
  targetUrl: 'https://authorized-target.com/page?id=1',
  enableEnumeration: true,
  userConsent: {
    acknowledgedWarnings: warnings,  // ALL warnings required
    metadata: {
      ipAddress: '192.168.1.100',
      userAgent: 'MyScanner/1.0',
    },
  },
});

const result = await pipeline.execute();
```

### Monitor Progress

```typescript
pipeline.on('stage_started', (event) => {
  console.log(`▶️  Started: ${event.stage}`);
});

pipeline.on('stage_completed', (event) => {
  console.log(`✅ Completed: ${event.stage}`);
});

pipeline.on('gate_blocked', (event) => {
  console.warn(`⛔ Gate blocked:`, event.data.decision.reasons);
});

// Get real-time progress
setInterval(() => {
  const progress = pipeline.getRealProgress();
  console.log(`
    Stage: ${progress.currentStage}
    Completed: ${progress.completedWorkUnits}/${progress.totalWorkUnits}
    Remaining: ${progress.remainingWorkUnits}
    Activity: ${progress.lastActivity}
  `);
}, 5000);
```

---

## 🔧 Configuration

### Enumeration Config

```typescript
interface EnumerationConfig {
  enabled: boolean;                 // MUST BE FALSE BY DEFAULT
  schemaOnly: boolean;              // true = metadata only, false = include data
  databasesEnabled: boolean;        // Enumerate databases
  tablesEnabled: boolean;           // Enumerate tables
  columnsEnabled: boolean;          // Enumerate columns
  dataPreviewEnabled: boolean;      // MUST BE FALSE BY DEFAULT
  
  // Limits
  maxDatabases: number;             // Max databases to enumerate
  maxTablesPerDatabase: number;     // Max tables per database
  maxColumnsPerTable: number;       // Max columns per table
  maxRowsPreview: number;           // Max rows in data preview
  maxFieldsPreview: number;         // Max fields in data preview
  
  // Pacing
  requestDelayMs: number;           // Delay between requests
  maxRetries: number;               // Max retry attempts
  timeoutMs: number;                // Request timeout
}
```

### Production-Safe Defaults

```typescript
{
  enabled: false,                   // ✅ DISABLED
  schemaOnly: true,                 // ✅ No data by default
  dataPreviewEnabled: false,        // ✅ DISABLED
  maxDatabases: 50,
  maxTablesPerDatabase: 100,
  maxColumnsPerTable: 50,
  maxRowsPreview: 10,
  maxFieldsPreview: 5,
  requestDelayMs: 1000,             // 1 second delay
  maxRetries: 3,
  timeoutMs: 10000,
}
```

### Validate Production Config

```typescript
import { SafetyControlsManager } from './scanner/pipeline';

const validation = SafetyControlsManager.validateProductionConfig(config);

if (!validation.safe) {
  console.error('❌ Config not safe for production:');
  validation.violations.forEach(v => console.error(`  - ${v}`));
}
```

---

## 📚 Component Documentation

### Confirmation Gate

Requires **multiple independent confirmation signals** before allowing enumeration:

```typescript
import { ConfirmationGate, ConfirmationSignal, ConfidenceLevel, InjectionTechnique } from './scanner/pipeline';

const gate = new ConfirmationGate({
  minimumSignals: 2,
  minimumConfidence: ConfidenceLevel.HIGH,
  requireDifferentTechniques: true,
  requireDifferentEvidenceTypes: true,
});

// Add signals from testing
gate.addSignal({
  technique: InjectionTechnique.UNION_BASED,
  payload: "' UNION SELECT NULL-- -",
  responseTimeMs: 150,
  evidenceType: "union_data",
  evidence: "Column count: 3",
  confidence: ConfidenceLevel.HIGH,
  timestamp: new Date(),
});

gate.addSignal({
  technique: InjectionTechnique.ERROR_BASED,
  payload: "' AND EXTRACTVALUE(1,1)-- -",
  responseTimeMs: 120,
  evidenceType: "error_message",
  evidence: "XPATH syntax error",
  confidence: ConfidenceLevel.HIGH,
  timestamp: new Date(),
});

// Evaluate
const decision = gate.evaluate();
if (decision.passed) {
  console.log('✅ Gate passed:', decision.reasons);
} else {
  console.log('❌ Gate blocked:', decision.reasons);
}
```

### Database Fingerprinter

Deterministically identifies database type:

```typescript
import { DatabaseFingerprinter } from './scanner/pipeline';

const fingerprinter = new DatabaseFingerprinter();

// Provide executor function
const executor = async (payload: string) => {
  // Execute SQL and return response
  const response = await executeSQL(payload);
  return response;
};

const fingerprint = await fingerprinter.fingerprint(executor);

console.log('Database Type:', fingerprint.type);       // mysql
console.log('Version:', fingerprint.version);          // 8.0.0
console.log('Confidence:', fingerprint.confidence);    // 100 (CONFIRMED)
console.log('Capabilities:', fingerprint.capabilities);
```

### Checkpoint Manager

Enable resumable operations:

```typescript
import { CheckpointManager, InMemoryCheckpointStorage, EnumerationPhase } from './scanner/pipeline';

const storage = new InMemoryCheckpointStorage();
const manager = new CheckpointManager(storage);

// Initialize
await manager.initialize('scan-123', EnumerationPhase.DATABASES);

// Mark progress
manager.markDatabaseCompleted('app_db');
manager.markTableCompleted('app_db.users');

// Check if already done
if (manager.isDatabaseCompleted('app_db')) {
  console.log('⏭️  Skipping already completed database');
}

// Get progress
const progress = manager.getProgress();
console.log('Completed databases:', progress.completedDatabases);
```

### Adaptive Pacer

Automatic speed adjustment:

```typescript
import { AdaptivePacer } from './scanner/pipeline';

const pacer = new AdaptivePacer({
  baseDelayMs: 1000,
  minDelayMs: 100,
  maxDelayMs: 30000,
  errorRateThreshold: 0.3,  // Throttle if >30% errors
  latencyThresholdMs: 5000,  // Throttle if >5s latency
});

// Before each request
await pacer.wait();

// After each request
pacer.recordResponse(
  latencyMs: 150,
  success: true,
  error: undefined,
  isTimeout: false
);

// Check metrics
const metrics = pacer.calculateMetrics();
console.log('Average latency:', metrics.averageLatencyMs);
console.log('Error rate:', metrics.errorRate);
console.log('Should throttle:', metrics.shouldThrottle);
```

### Response Analyzer

Noise-resilient comparison:

```typescript
import { ResponseAnalyzer } from './scanner/pipeline';

const analyzer = new ResponseAnalyzer();

// Normalize responses
const norm1 = analyzer.normalize(response1);
console.log('Removed elements:', norm1.removedElements);

// Compare responses
const comparison = analyzer.compare(response1, response2, threshold=0.15);
console.log('Similar:', comparison.similarity);
console.log('Different:', comparison.isDifferent);
console.log('Details:', comparison.details);

// Detect SQL errors
const sqlError = analyzer.detectSQLError(response);
if (sqlError.detected) {
  console.log('SQL Error Type:', sqlError.errorType);
  console.log('Evidence:', sqlError.evidence);
}
```

---

## 🧪 Testing

### Run Tests

```bash
npm test
```

### Test Coverage

```bash
npm run test:coverage
```

### Test Specific Component

```bash
npm test -- confirmation-gate
npm test -- database-fingerprinter
npm test -- enumeration-engine
```

---

## 📖 Full Documentation

See [ENGINEERING_DOCUMENTATION.md](./ENGINEERING_DOCUMENTATION.md) for:
- Architecture details
- Design principles
- Component specifications
- Failure modes and recovery
- Performance characteristics
- Security considerations
- Troubleshooting guide

---

## 🛡️ Security

### What This Tool Does

✅ Detect SQL injection vulnerabilities
✅ Identify database type and version
✅ Enumerate schema (WITH CONSENT)
✅ Limited data preview (WITH EXPLICIT CONSENT)
✅ Maintain audit trails

### What This Tool Does NOT Do

❌ Automatically dump databases
❌ Exfiltrate data without consent
❌ Bypass authentication
❌ Perform DoS attacks
❌ Store data permanently

### Responsible Use

- ✅ Get written authorization before testing
- ✅ Acknowledge all legal warnings
- ✅ Review audit trail
- ✅ Handle findings responsibly
- ✅ Follow responsible disclosure

---

## 📝 License

[Your License Here]

---

## 🤝 Contributing

Contributions welcome! Please:
1. Read engineering documentation
2. Follow existing patterns
3. Add tests for new features
4. Maintain safety-first principles
5. Update documentation

---

## ⚡ Performance

- **Detection Speed**: 30s - 2min (without enumeration)
- **Enumeration Speed**: 10min - 1hour (depends on schema size)
- **Memory**: ~50MB per scan
- **Concurrent Scans**: 10-50 recommended

---

## 🐛 Issues

Report issues with:
- Target URL (if authorized to share)
- Configuration used
- Error messages
- Audit trail export

---

## 📞 Support

- Documentation: `ENGINEERING_DOCUMENTATION.md`
- Examples: See `Quick Start` section
- Issues: GitHub Issues

---

**Built with safety, stability, and methodology in mind.**
