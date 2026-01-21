# 🛠️ دليل المطور - Developer Guide

## نظرة عامة (Overview)

هذا دليل شامل للمطورين الذين يعملون على مشروع SQL Scanner. يحتوي على جميع المعلومات اللازمة للبدء والتطوير والصيانة.

---

## 📁 هيكل المشروع (Project Structure)

```
Sql/
├── client/                    # React frontend
│   ├── src/
│   │   ├── components/       # UI components
│   │   ├── hooks/           # Custom React hooks
│   │   └── lib/             # Utilities
│   └── public/              # Static assets
│
├── server/                   # Express.js backend
│   ├── scanner/             # Scanner engine (CORE)
│   │   ├── index.ts         # Main scanner orchestration
│   │   ├── modules/         # Scan modules (SQLi, XSS, etc.)
│   │   ├── crawler.ts       # URL discovery
│   │   ├── defense-awareness.ts  # WAF detection
│   │   ├── adaptive-testing.ts   # Adaptive concurrency
│   │   ├── execution-control.ts  # Scan execution
│   │   └── payload-repository.ts # Payload management
│   │
│   ├── utils/               # Utilities (NEW)
│   │   ├── structured-logger.ts   # Professional logging
│   │   ├── retry-with-backoff.ts  # Retry logic
│   │   ├── input-validation.ts    # Input validation
│   │   └── rate-limiter.ts        # Rate limiting
│   │
│   ├── routes.ts            # API routes
│   ├── storage.ts           # Database layer
│   ├── db.ts                # Database connection
│   └── index.ts             # Server entry point
│
├── scanner_cli/             # Python CLI scanner
│   ├── main.py              # CLI entry point
│   ├── detector.py          # SQL error detection
│   └── reporter.py          # Report generation
│
├── shared/                  # Shared code (client + server)
│   └── routes.ts            # API route definitions
│
└── docs/                    # Documentation
    ├── FIXES_APPLIED.md
    ├── COMPREHENSIVE_IMPROVEMENTS.md
    ├── FINAL_UPDATES_LOG.md
    └── DEVELOPER_GUIDE.md (هذا الملف)
```

---

## 🚀 البدء السريع (Quick Start)

### المتطلبات الأساسية:
```bash
- Node.js 20+
- Python 3.11+
- PostgreSQL 15+
- Docker (اختياري)
```

### التثبيت:

```bash
# 1. Clone repository
git clone <repo-url>
cd Sql

# 2. Install dependencies
npm install

# 3. Setup database (Docker)
docker-compose up -d

# 4. Create .env file
cat > .env << EOF
DATABASE_URL=postgresql://scanner:scanner_password_dev@localhost:5432/sqli_scanner
NODE_ENV=development
LOG_TO_FILE=true
LOG_FILE_PATH=./logs/app.log
EOF

# 5. Generate database schema
npm run db:push

# 6. Start development server
npm run dev
```

الخادم يعمل الآن على: `http://localhost:5000`

---

## 🏗️ البنية المعمارية (Architecture)

### 1. Scanner Engine Flow

```
User Request
    ↓
API Route (/api/scans)
    ↓
VulnerabilityScanner.run()
    ↓
┌─────────────────────────────────────┐
│  Phase 1: Crawling                  │
│  - URL discovery                    │
│  - Parameter extraction             │
│  - Form detection                   │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 2: Baseline Establishment    │
│  - Normal responses                 │
│  - Response time baselines          │
│  - DOM tree hashes                  │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 3: Error-Based Testing       │
│  - SQL syntax errors                │
│  - Database-specific errors         │
│  - Verbose error extraction         │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 4: Boolean-Blind Testing     │
│  - True/False conditions            │
│  - DOM comparison                   │
│  - Binary search                    │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 5: Time-Based Testing        │
│  - SLEEP() payloads                 │
│  - Statistical timing analysis      │
│  - Adaptive delays                  │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 6: Verification              │
│  - Confirm findings                 │
│  - False positive reduction         │
│  - Severity assessment              │
└─────────────────────────────────────┘
    ↓
Results stored in Database
```

### 2. Adaptive Concurrency System

```typescript
Initial Concurrency: 10 workers
    ↓
Monitor Performance:
- Success rate
- Response times
- Error rates
    ↓
Adjust Concurrency:
- Increase if: success rate > 80%, low errors
- Decrease if: errors > 20%, timeouts
- Hard limit: MAX 100 workers
    ↓
Repeat until scan complete
```

### 3. Defense Awareness Flow

```typescript
Request → Analyze Response
    ↓
WAF Detected?
    ├─ No → Continue normally
    └─ Yes → Apply bypass strategies:
              - Change User-Agent
              - Rotate X-Forwarded-For
              - Apply payload tamping
              - Use encoding strategies
    ↓
Rate Limit Detected?
    ├─ No → Continue
    └─ Yes → Adaptive pacing:
              - Slow down requests
              - Wait before continuing
              - Circuit breaker if blocked
```

---

## 🔑 المكونات الأساسية (Core Components)

### 1. VulnerabilityScanner (server/scanner/index.ts)

**المسؤولية**: Orchestration للفحص الكامل

```typescript
class VulnerabilityScanner {
  constructor(scanId, targetUrl, scanType, threads) {
    // Initialize all modules
  }
  
  async run() {
    // 1. Setup
    await this.setup();
    
    // 2. Crawl
    await this.crawl();
    
    // 3. Establish baseline
    await this.establishBaseline();
    
    // 4. Test for vulnerabilities
    await this.testVulnerabilities();
    
    // 5. Verify findings
    await this.verifyFindings();
    
    // 6. Generate report
    await this.generateReport();
  }
}
```

**الميزات الرئيسية**:
- ✅ Timeout protection (1 hour max)
- ✅ Progress tracking
- ✅ Graceful cancellation
- ✅ Error recovery
- ✅ Real-time metrics

---

### 2. SQLiModule (server/scanner/modules/sqli.ts)

**المسؤولية**: اختبار SQL Injection

```typescript
class SQLiModule {
  async testAllPayloadClasses(params) {
    // Test in order:
    // 1. Error-based (fast)
    // 2. Boolean-blind (medium)
    // 3. Time-based (slow)
    // 4. Union-based (special)
    // 5. Stacked queries (advanced)
  }
  
  async testErrorBasedClass(param) {
    // Send error payloads
    // Detect SQL errors in response
    // Confirm vulnerability
  }
  
  async testBooleanBlindClass(param) {
    // Send true/false payloads
    // Compare DOM tree hashes
    // Binary search for data extraction
  }
  
  async testTimeBlindClass(param) {
    // Send SLEEP() payloads
    // Measure response times
    // Statistical timing analysis
  }
}
```

**الميزات الرئيسية**:
- ✅ 3000+ payloads
- ✅ Database-specific detection
- ✅ Context-aware payloads
- ✅ WAF bypass strategies
- ✅ False positive reduction

---

### 3. Crawler (server/scanner/crawler.ts)

**المسؤولية**: اكتشاف URLs و Parameters

```typescript
class Crawler {
  async parallelCrawl() {
    // Parallel queue-based crawling
    // Extract:
    // - Links (<a href>)
    // - Forms (<form>)
    // - JavaScript URLs
    // - API endpoints
    // - WebSocket endpoints
  }
  
  async analyzeJsFiles() {
    // Parse JavaScript files
    // Extract:
    // - API routes
    // - Dynamic routes
    // - Hidden parameters
    // - Auth tokens
  }
}
```

**الميزات الرئيسية**:
- ✅ Parallel crawling (10 concurrent)
- ✅ JavaScript analysis
- ✅ Form workflow detection
- ✅ API endpoint discovery
- ✅ Parameter extraction

---

### 4. DefenseAwareness (server/scanner/defense-awareness.ts)

**المسؤولية**: اكتشاف وتجاوز WAF

```typescript
class DefenseAwareness {
  analyzeResponse(response) {
    // Detect:
    // - Cloudflare
    // - AWS WAF
    // - ModSecurity
    // - Imperva
    // - Akamai
    // - Rate limits
    // - IP blocks
  }
  
  handleWAFOffensive(wafVendor) {
    // Apply bypass:
    // - Header rotation
    // - IP rotation (X-Forwarded-For)
    // - Payload tamping
    // - Encoding strategies
  }
}
```

**الميزات الرئيسية**:
- ✅ 10+ WAF vendors detected
- ✅ Automatic bypass strategies
- ✅ Adaptive pacing
- ✅ Circuit breaker
- ✅ Offensive mode (no mandatory pauses)

---

## 🛠️ الأدوات الجديدة (New Utilities)

### 1. Structured Logger

```typescript
import { globalLogger } from './server/utils/structured-logger';

const logger = globalLogger.createChild('MyModule');

// Log levels
logger.debug('Debug message', { key: 'value' });
logger.info('Info message', { scanId: 123 });
logger.warn('Warning message');
logger.error('Error message', error, { context: 'data' });
logger.critical('Critical error', error);

// Features:
// - Color-coded console output
// - File logging (./logs/app.log)
// - Trace ID support
// - Context data
// - Automatic log rotation
```

---

### 2. Retry with Backoff

```typescript
import { retryWithBackoff, retryOnNetworkError } from './server/utils/retry-with-backoff';

// Simple retry (3 attempts)
const data = await retryWithBackoff(
  () => fetchDataFromAPI(),
  { maxRetries: 3, baseDelay: 1000 }
);

// Network errors only
const response = await retryOnNetworkError(
  () => makeHttpRequest(),
  { maxRetries: 5, baseDelay: 2000 }
);

// Circuit breaker
const breaker = new CircuitBreaker(() => callExternalService(), {
  failureThreshold: 5,
  resetTimeout: 60000,
});
const result = await breaker.execute();
```

---

### 3. Input Validation

```typescript
import { validateScanRequest, validateBatchScan } from './server/utils/input-validation';

// Validate scan request
const validation = validateScanRequest(req.body);
if (!validation.valid) {
  return res.status(400).json({ errors: validation.errors });
}

// Use validated data
const { targetUrl, threads, scanMode } = validation.validated;

// As middleware
app.post('/api/scans', validateScanRequestMiddleware, async (req, res) => {
  // req.body is now validated
});
```

---

### 4. Rate Limiting

```typescript
import { 
  scanCreationRateLimit, 
  batchScanRateLimit,
  fileUploadRateLimit 
} from './server/utils/rate-limiter';

// Apply to routes
app.post('/api/scans', scanCreationRateLimit, async (req, res) => {
  // Max 10 scans per 15 minutes per IP
});

app.post('/api/scans/batch', batchScanRateLimit, async (req, res) => {
  // Max 3 batch scans per hour per IP
});

app.post('/api/mass-scan/upload', fileUploadRateLimit, async (req, res) => {
  // Max 5 uploads per 10 minutes per IP
});
```

---

## 📊 قاعدة البيانات (Database Schema)

```typescript
// Scans table
scans {
  id: serial primary key
  targetUrl: text
  scanMode: text
  status: text  // pending, scanning, completed, failed, cancelled
  progress: integer  // 0-100
  currentPhase: text
  startTime: timestamp
  endTime: timestamp
  threads: integer
  isParent: boolean
  parentId: integer (foreign key to scans)
  
  // Performance metrics
  adaptiveConcurrency: integer
  payloadsTested: integer
  rps: decimal
  activeWorkers: integer
  parametersDiscovered: integer
  parametersTested: integer
  vulnerabilitiesFound: integer
}

// Vulnerabilities table
vulnerabilities {
  id: serial primary key
  scanId: integer (foreign key to scans)
  type: text  // sqli, xss, etc.
  severity: text  // critical, high, medium, low
  url: text
  parameter: text
  payload: text
  evidence: text
  method: text
  remediation: text
  cwe: text
  cvss: decimal
  detectionMethod: text
  confirmedAt: timestamp
}

// Scan logs table
scanLogs {
  id: serial primary key
  scanId: integer (foreign key to scans)
  level: text  // debug, info, warn, error
  message: text
  timestamp: timestamp
  context: jsonb
}

// Traffic logs table
trafficLogs {
  id: serial primary key
  scanId: integer (foreign key to scans)
  url: text
  method: text
  requestHeaders: jsonb
  requestBody: text
  responseStatus: integer
  responseHeaders: jsonb
  responseBody: text
  responseTime: integer
  timestamp: timestamp
}
```

---

## 🧪 الاختبار (Testing)

### اختبار الوحدة (Unit Tests)

```typescript
// server/scanner/__tests__/sqli.test.ts
import { describe, it, expect } from 'vitest';
import { SQLiModule } from '../modules/sqli';

describe('SQLiModule', () => {
  it('should detect MySQL errors', async () => {
    const module = new SQLiModule();
    const result = await module.testPayload({
      url: 'http://example.com',
      param: 'id',
      payload: "' OR '1'='1",
    });
    
    expect(result.vulnerable).toBe(true);
    expect(result.dbType).toBe('mysql');
  });
});
```

### اختبار التكامل (Integration Tests)

```typescript
// server/__tests__/api.test.ts
import request from 'supertest';
import app from '../index';

describe('API Endpoints', () => {
  it('should create a scan', async () => {
    const response = await request(app)
      .post('/api/scans')
      .send({
        targetUrl: 'http://testphp.vulnweb.com',
        scanMode: 'sqli',
        threads: 10,
      });
    
    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('id');
  });
});
```

---

## 🐛 التنقيح (Debugging)

### تفعيل DEBUG logging:

```bash
# في .env
NODE_ENV=development

# سيطبع جميع debug messages
```

### مراقبة اللوغات:

```bash
# Real-time logs
tail -f ./logs/app.log

# Search logs
grep "ERROR" ./logs/app.log

# JSON parsing
cat ./logs/app.log | jq '.level=="ERROR"'
```

### استخدام Chrome DevTools:

```bash
node --inspect server/index.ts
# ثم افتح chrome://inspect
```

---

## 📈 مراقبة الأداء (Performance Monitoring)

### مقاييس مهمة:

```typescript
// متاح في /api/scans/:id
{
  "progress": 20,  // 0-100
  "currentPhase": "error_based_sql",
  "adaptiveConcurrency": 100,  // عدد workers النشطة
  "payloadsTested": 3324,  // عدد payloads المختبرة
  "rps": 2.7,  // requests per second
  "parametersDiscovered": 42,  // parameters found
  "parametersTested": 28,  // parameters tested
  "vulnerabilitiesFound": 0  // vulnerabilities
}
```

### تحسين الأداء:

```typescript
// 1. تقليل threads إذا كان RPS مرتفع جداً
scan.threads = 50;  // بدلاً من 100

// 2. زيادة timeout إذا كان الهدف بطيء
scan.timeout = 120000;  // 2 minutes

// 3. تقليل depth للفحص الأسرع
scan.depth = 3;  // بدلاً من 8
```

---

## 🔒 الأمان (Security)

### أفضل الممارسات:

```typescript
// 1. استخدم Input Validation دائماً
const validation = validateScanRequest(data);
if (!validation.valid) {
  throw new ValidationError(validation.errors);
}

// 2. طبق Rate Limiting على جميع endpoints
app.use('/api', apiRateLimit);

// 3. Sanitize جميع المدخلات
const clean = sanitizeString(userInput);

// 4. استخدم Environment Variables للأسرار
const dbUrl = process.env.DATABASE_URL;

// 5. امنع localhost في production
if (process.env.NODE_ENV === 'production') {
  if (url.includes('localhost')) {
    throw new Error('Cannot scan localhost in production');
  }
}
```

---

## 📚 موارد إضافية (Additional Resources)

- **FIXES_APPLIED.md**: جميع الإصلاحات المطبقة
- **COMPREHENSIVE_IMPROVEMENTS.md**: التحسينات المقترحة
- **FINAL_UPDATES_LOG.md**: سجل التحديثات النهائية
- **TEST_RESULTS.md**: نتائج الاختبارات
- **TESTING_GUIDE.md**: دليل الاختبار

---

## 🤝 المساهمة (Contributing)

### قبل إرسال Pull Request:

```bash
# 1. اختبر الكود
npm run test

# 2. تأكد من عدم وجود أخطاء TypeScript
npm run check

# 3. Format الكود
npm run format

# 4. اختبر محلياً
npm run dev
# ثم اختبر يدوياً

# 5. توثيق التغييرات
# أضف entry في CHANGELOG.md
```

---

## 📞 الدعم (Support)

إذا واجهت أي مشاكل:

1. تحقق من اللوغات: `tail -f ./logs/app.log`
2. تحقق من حالة قاعدة البيانات: `docker ps`
3. راجع الوثائق في `/docs`
4. افتح issue على GitHub

---

**تم إنشاؤه بواسطة**: GitHub Copilot (Claude Sonnet 4.5)  
**آخر تحديث**: ${new Date().toISOString()}
