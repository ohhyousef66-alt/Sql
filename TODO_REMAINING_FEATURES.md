# الميزات المتبقية - TODO

## 1. حفظ Progress باستمرار (Database Persistence) 💾

### المشكلة:
حالياً، عند إعادة تحميل الصفحة، يضيع كل التقدم.

### الحل المطلوب:

#### أ) إضافة جداول Database:

```sql
-- جدول Sessions للفحص الجماعي
CREATE TABLE mass_scan_sessions (
  id SERIAL PRIMARY KEY,
  started_at TIMESTAMP NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMP,
  status VARCHAR(50) NOT NULL DEFAULT 'running', -- running, paused, completed, failed
  total_targets INTEGER NOT NULL,
  completed_targets INTEGER NOT NULL DEFAULT 0,
  vulnerable_targets INTEGER NOT NULL DEFAULT 0,
  clean_targets INTEGER NOT NULL DEFAULT 0,
  concurrency INTEGER NOT NULL DEFAULT 50,
  threads INTEGER NOT NULL DEFAULT 10,
  targets TEXT[] NOT NULL, -- array of URLs
  settings JSONB -- Additional settings
);

-- جدول Results لكل موقع
CREATE TABLE mass_scan_results (
  id SERIAL PRIMARY KEY,
  session_id INTEGER NOT NULL REFERENCES mass_scan_sessions(id),
  target_id INTEGER NOT NULL,
  url TEXT NOT NULL,
  scan_id INTEGER REFERENCES scans(id),
  status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, scanning, vulnerable, clean, error
  vulnerabilities_found INTEGER NOT NULL DEFAULT 0,
  payloads_tested INTEGER NOT NULL DEFAULT 0,
  payloads_total INTEGER NOT NULL DEFAULT 0,
  dump_verified BOOLEAN NOT NULL DEFAULT FALSE,
  error_message TEXT,
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mass_scan_results_session ON mass_scan_results(session_id);
CREATE INDEX idx_mass_scan_results_status ON mass_scan_results(status);
```

#### ب) تعديل `mass-scanner.ts`:

```typescript
class MassScanner {
  private sessionId?: number;

  async start(targets: string[]) {
    // Create session في Database
    this.sessionId = await storage.createMassScanSession({
      total_targets: targets.length,
      concurrency: this.concurrency,
      threads: this.threads,
      targets: targets,
    });

    // Start scanning with progress tracking
    await this.scanBatch(targets);
  }

  private async saveProgress(result: MassScanResult) {
    if (!this.sessionId) return;

    // Save/update result in database
    await storage.upsertMassScanResult({
      session_id: this.sessionId,
      target_id: result.targetId,
      url: result.url,
      scan_id: result.scanId,
      status: result.status,
      vulnerabilities_found: result.vulnerabilitiesFound,
      payloads_tested: result.payloadsTestصد || 0,
      dump_verified: result.status === "vulnerable",
    });

    // Update session statistics
    const stats = await this.getSessionStats(this.sessionId);
    await storage.updateMassScanSession(this.sessionId, stats);
  }

  async resume(sessionId: number) {
    // Load session from database
    const session = await storage.getMassScanSession(sessionId);
    const results = await storage.getMassScanResults(sessionId);

    // Continue scanning pending targets
    const pending = results.filter(r => r.status === 'pending');
    // ...resume logic
  }
}
```

#### ج) تعديل UI:

```tsx
// في MassScan.tsx
useEffect(() => {
  // Check for incomplete sessions on mount
  const checkForIncompleteSessions = async () => {
    const res = await fetch("/api/mass-scan/sessions?status=running");
    const sessions = await res.json();
    
    if (sessions.length > 0) {
      // Show dialog: "لديك فحص غير مكتمل. استئناف؟"
      setShowResumeDialog(true);
      setIncompleteSession(sessions[0]);
    }
  };

  checkForIncompleteSessions();
}, []);

const handleResume = async () => {
  const res = await fetch(`/api/mass-scan/resume/${incompleteSession.id}`, {
    method: "POST"
  });
  // Continue polling...
};
```

#### د) API Endpoints جديدة:

```typescript
// GET /api/mass-scan/sessions?status=running
app.get("/api/mass-scan/sessions", async (req, res) => {
  const { status } = req.query;
  const sessions = await storage.getMassScanSessions(status);
  res.json(sessions);
});

// GET /api/mass-scan/sessions/:id
app.get("/api/mass-scan/sessions/:id", async (req, res) => {
  const session = await storage.getMassScanSession(Number(req.params.id));
  const results = await storage.getMassScanResults(session.id);
  res.json({ session, results });
});

// POST /api/mass-scan/resume/:id
app.post("/api/mass-scan/resume/:id", async (req, res) => {
  const sessionId = Number(req.params.id);
  massScanner.resume(sessionId);
  res.json({ message: "Resuming scan" });
});
```

---

## 2. Payload Counter لكل موقع 📊

### المشكلة:
المستخدم لا يعرف تقدم الفحص الحقيقي لكل موقع.

### الحل المطلوب:

#### أ) تعديل `VulnerabilityScanner`:

```typescript
class VulnerabilityScanner {
  private totalPayloads = 0;
  private testedPayloads = 0;

  async run() {
    // Calculate total payloads
    this.totalPayloads = this.calculateTotalPayloads();

    // During scanning, update counter
    for (const payload of payloads) {
      await this.testPayload(payload);
      this.testedPayloads++;
      
      // Save progress every 10 payloads
      if (this.testedPayloads % 10 === 0) {
        await this.saveProgress();
      }
    }
  }

  private calculateTotalPayloads(): number {
    // Error-based: ~100 payloads
    // Union-based: ~200 payloads
    // Boolean-based: ~300 payloads
    // Time-based: ~150 payloads
    return 750; // approximate total
  }

  async getProgress() {
    return {
      totalPayloads: this.totalPayloads,
      testedPayloads: this.testedPayloads,
      percentage: (this.testedPayloads / this.totalPayloads) * 100,
      currentStage: this.currentStage,
    };
  }

  private async saveProgress() {
    await storage.updateScanProgress(this.scanId, {
      payloads_tested: this.testedPayloads,
      payloads_total: this.totalPayloads,
    });
  }
}
```

#### ب) إضافة أعمدة في `scans` table:

```sql
ALTER TABLE scans ADD COLUMN payloads_tested INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN payloads_total INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN current_stage VARCHAR(100);
```

#### ج) تعديل UI:

```tsx
// في MassScan.tsx - Results Table
<TableCell>
  {result.status === "scanning" && result.payloadsProgress ? (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <Progress 
          value={(result.payloadsProgress.tested / result.payloadsProgress.total) * 100} 
          className="w-20"
        />
        <span className="text-xs text-muted-foreground">
          {result.payloadsProgress.tested}/{result.payloadsProgress.total}
        </span>
      </div>
      <div className="text-xs text-muted-foreground">
        {result.payloadsProgress.currentStage}
      </div>
    </div>
  ) : (
    <span className="text-muted-foreground">-</span>
  )}
</TableCell>
```

#### د) Polling للـ Progress:

```typescript
// في MassScan.tsx
const pollProgress = async () => {
  const interval = setInterval(async () => {
    const res = await fetch("/api/mass-scan/progress");
    const progress = await res.json();

    // Update results with payload progress
    setResults(prev => prev.map(r => {
      const updated = progress.results.find(p => p.targetId === r.id);
      if (updated && updated.status === "scanning") {
        return {
          ...r,
          status: updated.status,
          payloadsProgress: {
            tested: updated.payloadsTested || 0,
            total: updated.payloadsTotal || 1500,
            currentStage: updated.currentStage || "Initializing",
          }
        };
      }
      return r;
    }));

    if (!scanning) clearInterval(interval);
  }, 3000); // every 3 seconds
};
```

---

## 3. UI Improvements

### Real-time Progress Indicator:
```tsx
// في Success Box وجدول النتائج
{result.status === "scanning" && (
  <div className="flex items-center gap-2 text-sm">
    <Loader2 className="w-3 h-3 animate-spin" />
    <span>
      {result.payloadsProgress?.currentStage || "Scanning..."}
    </span>
    <Badge variant="outline">
      {result.payloadsProgress?.tested || 0} / {result.payloadsProgress?.total || "?"}
    </Badge>
  </div>
)}
```

### Resume Dialog:
```tsx
<Dialog open={showResumeDialog} onOpenChange={setShowResumeDialog}>
  <DialogContent>
    <DialogHeader>
      <DialogTitle>استئناف الفحص</DialogTitle>
      <DialogDescription>
        لديك فحص غير مكتمل من {new Date(incompleteSession.started_at).toLocaleString('ar')}
        <br />
        التقدم: {incompleteSession.completed_targets} / {incompleteSession.total_targets}
      </DialogDescription>
    </DialogHeader>
    <DialogFooter>
      <Button variant="outline" onClick={() => setShowResumeDialog(false)}>
        إلغاء
      </Button>
      <Button onClick={handleResume}>
        استئناف الفحص
      </Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

---

## 📋 خطة التنفيذ

### Priority 1 (Critical):
1. ✅ **إضافة جداول Database** (mass_scan_sessions, mass_scan_results)
2. ✅ **تعديل storage.ts** (add methods)
3. ✅ **تعديل mass-scanner.ts** (save progress)
4. ✅ **API endpoints** (sessions, resume)

### Priority 2 (High):
5. ✅ **Payload counter** في VulnerabilityScanner
6. ✅ **Progress tracking** كل 10 payloads
7. ✅ **UI updates** لعرض payload progress

### Priority 3 (Medium):
8. ✅ **Resume dialog** في UI
9. ✅ **Auto-load** incomplete sessions
10. ✅ **Visual progress** indicators

---

## 🎯 النتيجة المتوقعة

بعد تنفيذ هذه الميزات:

1. **لا يضيع التقدم أبداً** - كل شيء محفوظ في Database
2. **شفافية كاملة** - المستخدم يشاهد كل payload يُختبر
3. **استئناف سلس** - يمكن إيقاف وإعادة تشغيل الفحص بسهولة
4. **معلومات دقيقة** - "Testing payload 245/1500 - Error-based technique"

---

**الوقت المقدر للتنفيذ**: 3-4 ساعات
**الأولوية**: High (لكن النظام يعمل بدونها حالياً)
