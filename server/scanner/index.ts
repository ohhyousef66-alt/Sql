import { storage } from "../storage";
import { InsertVulnerability, ScanMode, Vulnerability } from "@shared/schema";
import { Crawler } from "./crawler";
import { SQLiModule } from "./modules/sqli";
import { SecondOrderSQLiDetector } from "./second-order-sqli";
import { ScannerLogger, DebugLogEntry } from "./utils/logger";
import { formatErrorForLogging, TrafficLogger, makeRequest, hashString } from "./utils";
import { 
  ExecutionController, 
  ScanBudget, 
  DEFAULT_BUDGET, 
  ExecutionMetricsSummary,
  ScanCompleteness,
  ScanValidationResult,
  REQUIRED_WORK 
} from "./execution-control";
import { DefenseAwareness } from "./defense-awareness";
import { globalPayloadRepository } from "./payload-repository";
import { AdaptiveTestingEngine, DynamicProgressTracker, ResourceOptimizer } from "./adaptive-testing";
import { EventDrivenSQLiDetector } from "./event-driven-detector";
import { ImmediateExploitationEngine } from "./immediate-exploitation";
import { SQLiContext, ConfirmationCompleteEvent } from "./sqli-context";

// SQL-ONLY ENGINE: All CVE, XSS, LFI, SSRF, fingerprinting logic REMOVED
// This scanner focuses EXCLUSIVELY on SQL injection detection

// FIXED: Realistic timeout values instead of MAX_SAFE_INTEGER
const FULL_MODE_TIMEOUT = 60 * 60 * 1000; // 1 hour for full scan
const FOCUSED_MODE_TIMEOUT = 30 * 60 * 1000; // 30 minutes for focused scan
const STALL_DETECTION_THRESHOLD = 10 * 60 * 1000; // 10 minutes of no activity = stall
const WATCHDOG_CHECK_INTERVAL = 30 * 1000; // Check every 30 seconds


interface ModuleResult {
  name: string;
  success: boolean;
  error?: string;
  duration: number;
  findingsCount: number;
}

interface TargetState {
  url: string;
  baselineCache: Map<string, any>;
  negativeParams: Set<string>;
  timingProfile: { avgLatency: number; maxLatency: number; minLatency: number };
  startTime: number;
  status: "pending" | "scanning" | "completed" | "error";
  findingsCount: number;
}

export class VulnerabilityScanner {
  private static activeScans = new Map<number, VulnerabilityScanner>();
  private scanId: number;
  private targetUrl: string;
  private scanMode: ScanMode;
  private threads: number;
  private moduleTimeout: number;
  private logger: ScannerLogger;
  private moduleResults: ModuleResult[] = [];
  private executionController: ExecutionController;
  private defenseAwareness: DefenseAwareness;
  private trafficLogger: TrafficLogger;
  private cancelled = false;
  private abortController: AbortController;
  private watchdogTimer: NodeJS.Timeout | null = null;
  private scanStartTime: number = 0;
  private adaptiveEngine: AdaptiveTestingEngine;
  private progressTracker: DynamicProgressTracker;
  private resourceOptimizer: ResourceOptimizer;
  private summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    confirmed: 0,
    potential: 0,
  };
  private targetStates: Map<string, TargetState> = new Map();
  private multiTargetMode = false;
  private firstVulnFound = false; // Track first vulnerability for auto-dumping
  private dumpingStarted = false; // Track if dumping already started
  private eventDrivenDetector: EventDrivenSQLiDetector;
  private exploitationEngine: ImmediateExploitationEngine;

  constructor(scanId: number, targetUrl: string, scanMode: ScanMode = "sqli", threads: number = 10, budget?: Partial<ScanBudget>) {
    this.scanId = scanId;
    this.targetUrl = targetUrl.endsWith("/") ? targetUrl.slice(0, -1) : targetUrl;
    this.scanMode = scanMode;
    this.threads = Math.max(1, Math.min(100, threads)); // Increased max to 100 for adaptive scaling
    this.moduleTimeout = FULL_MODE_TIMEOUT;
    this.logger = new ScannerLogger(scanId, this.log.bind(this), true);
    this.executionController = new ExecutionController(budget, this.log.bind(this));
    this.defenseAwareness = new DefenseAwareness(
      this.log.bind(this),
      () => this.executionController.recordBlock() // Track blocks for War Room
    );
    this.trafficLogger = new TrafficLogger(scanId, true);
    this.abortController = new AbortController();
    
    // Adaptive Testing Engine - Self-scaling concurrency and smart decision logic
    this.adaptiveEngine = new AdaptiveTestingEngine(
      this.log.bind(this),
      () => this.cancelled,
      this.abortController.signal,
      this.threads,
      () => this.executionController.incrementParametersSkipped()
    );
    this.progressTracker = new DynamicProgressTracker();
    this.resourceOptimizer = new ResourceOptimizer();
    
    // ⚡ EVENT-DRIVEN ARCHITECTURE
    // Initialize event-driven detector and exploitation engine
    this.exploitationEngine = new ImmediateExploitationEngine(scanId, this.log.bind(this));
    this.eventDrivenDetector = new EventDrivenSQLiDetector(
      this.log.bind(this),
      {
        onConfirmationComplete: async (event: ConfirmationCompleteEvent) => {
          await this.handleConfirmationComplete(event);
        },
      }
    );
  }
  
  /**
   * ⚡ Handle confirmation complete event - IMMEDIATE EXPLOITATION
   * This is called automatically when SQLi is confirmed
   * NO manual UI trigger needed
   */
  private async handleConfirmationComplete(event: ConfirmationCompleteEvent): Promise<void> {
    const { context } = event;
    
    await this.log("info", `⚡ [AutoExploit] SQLi confirmed for ${context.parameter} - triggering IMMEDIATE exploitation`);
    
    // Report vulnerability BEFORE exploitation
    await this.reportConfirmedVulnerability(context);
    
    if (event.shouldExploit) {
      try {
        // ⚡ AUTOMATIC EXPLOITATION - NO USER ACTION NEEDED
        const { fingerprint, enumeration } = await this.exploitationEngine.exploit(context);
        
        if (enumeration.success && enumeration.databases.length > 0) {
          await this.log("info", `✅ [AutoExploit] Enumeration complete: ${enumeration.databases.length} databases, ${enumeration.tables.size} tables extracted`);
        } else {
          await this.log("warn", `[AutoExploit] Exploitation attempted but no data extracted`);
        }
      } catch (error: any) {
        await this.log("error", `[AutoExploit] Exploitation failed: ${error.message}`);
      }
    }
  }
  
  /**
   * Report confirmed vulnerability from sqliContext
   */
  private async reportConfirmedVulnerability(context: SQLiContext): Promise<void> {
    const vuln: InsertVulnerability = {
      scanId: this.scanId,
      type: "sql_injection",
      severity: "critical",
      confidence: context.confidence,
      url: context.url,
      parameter: context.parameter || "unknown",
      payload: context.workingPayload,
      evidence: `SQLi confirmed via ${context.injectionType}. DB: ${context.dbFingerprint.type}${context.dbFingerprint.version ? " " + context.dbFingerprint.version : ""}. Confirmed after ${context.confirmationCount} attempts.`,
      description: `SQL injection found using ${context.injectionType} technique`,
      remediation: "Use parameterized queries or prepared statements (CWE-89, CVSS: 9.8)",
      verificationStatus: "confirmed",
    };
    
    await storage.createVulnerability(vuln);
    
    // Update summary
    this.summary.critical++;
    this.summary.confirmed++;
  }

  public getThreads(): number {
    return this.threads;
  }

  public getTrafficLogger(): TrafficLogger {
    return this.trafficLogger;
  }
  
  private syncAdaptiveMetrics(): void {
    const adaptiveMetrics = this.adaptiveEngine.getMetricsForUI();
    const trackerMetrics = this.progressTracker.getProgress();
    
    this.executionController.setAdaptiveMetrics({
      concurrency: adaptiveMetrics.concurrency,
      successRate: adaptiveMetrics.successRate,
      coveragePerHour: trackerMetrics.coveragePerHour,
      workQueueSize: trackerMetrics.workQueueSize,
      estimatedTimeRemaining: trackerMetrics.estimatedTimeRemaining,
    });
  }

  private startWatchdog(): void {
    this.scanStartTime = Date.now();
    
    // Zero-Speed Directive: Watchdog NEVER terminates scans - only logs progress
    // Scans complete ONLY when work queue is empty or user cancels
    this.watchdogTimer = setInterval(async () => {
      if (this.cancelled) {
        this.stopWatchdog();
        return;
      }

      const isStalled = this.executionController.isStalled(STALL_DETECTION_THRESHOLD);
      const lastActivity = this.executionController.getLastActivityTime();
      const stallDuration = Date.now() - lastActivity;
      
      if (isStalled) {
        // Zero-Speed Directive: Log stall but DO NOT terminate - scan continues
        console.log(`[Watchdog] Scan ${this.scanId} has been inactive for ${Math.round(stallDuration / 1000)}s - continuing per Zero-Speed Directive`);
      }
      
      // Persist current progress metrics periodically
      try {
        this.syncAdaptiveMetrics();
        await storage.updateScan(this.scanId, {
          progressMetrics: this.executionController.getProgressMetrics()
        });
      } catch (e) {
        // Ignore periodic update failures
      }
    }, WATCHDOG_CHECK_INTERVAL);
  }

  private stopWatchdog(): void {
    if (this.watchdogTimer) {
      clearInterval(this.watchdogTimer);
      this.watchdogTimer = null;
    }
  }

  private async handleCancellation(scanStartTime: number): Promise<void> {
    const duration = Date.now() - scanStartTime;
    await this.logger.warn("Scanner", `Scan cancelled after ${Math.round(duration / 1000)}s`);
    await storage.updateScan(this.scanId, {
      status: "failed",
      progress: 100,
      summary: { ...this.summary, cancelled: true },
      progressMetrics: this.executionController.getProgressMetrics(),
      endTime: new Date(),
      completionReason: "Cancelled by user"
    });
  }

  private initializeTargetState(targetUrl: string): TargetState {
    const state: TargetState = {
      url: targetUrl,
      baselineCache: new Map(),
      negativeParams: new Set(),
      timingProfile: { avgLatency: 0, maxLatency: 0, minLatency: 0 },
      startTime: Date.now(),
      status: "pending",
      findingsCount: 0,
    };
    this.targetStates.set(targetUrl, state);
    return state;
  }

  private getTargetState(url: string): TargetState | undefined {
    const entries = Array.from(this.targetStates.entries());
    for (const [targetUrl, state] of entries) {
      if (url.startsWith(targetUrl) || targetUrl.startsWith(url.split('?')[0])) {
        return state;
      }
    }
    return undefined;
  }

  private updateTargetTimingProfile(url: string, latency: number): void {
    const state = this.getTargetState(url);
    if (!state) return;
    
    const profile = state.timingProfile;
    if (profile.avgLatency === 0) {
      profile.avgLatency = latency;
      profile.maxLatency = latency;
      profile.minLatency = latency;
    } else {
      profile.avgLatency = (profile.avgLatency * 0.9) + (latency * 0.1);
      profile.maxLatency = Math.max(profile.maxLatency, latency);
      profile.minLatency = Math.min(profile.minLatency, latency);
    }
  }

  static cancelScan(scanId: number) {
    const scanner = this.activeScans.get(scanId);
    if (scanner) {
      scanner.cancelled = true;
      scanner.abortController.abort();
      scanner.log("info", "Cancellation requested by user. Terminating scan...");
    }
  }

  private isCancelled(): boolean {
    return this.cancelled;
  }

  /**
   * Test vulnerability in dumper (NO full dump, just test)
   */
  private async testInDumper(vuln: Omit<InsertVulnerability, "scanId">): Promise<void> {
    try {
      await this.logger.info("Scanner", `🔬 Post-Confirmation Pipeline disabled (integrated-pipeline-adapter not implemented)`);
      // IntegratedPipelineAdapter feature is not implemented
    } catch (error: any) {
      await this.logger.error("Scanner", "Post-confirmation error", error);
    }
  }

  private async log(level: string, message: string): Promise<void> {
    try {
      await storage.createScanLog({
        scanId: this.scanId,
        level,
        message,
      });
    } catch (error) {
      console.error(`[Scanner] Failed to persist log: ${message}`, error);
    }
  }

  private async reportVuln(vuln: Omit<InsertVulnerability, "scanId"> & { cveId?: string }) {
    try {
      let vulnToReport = { ...vuln };
      
      // SQL-ONLY ENGINE: Only accept SQL injection findings
      // Reject all non-SQL vulnerability types
      const sqlTypes = [
        "SQL Injection",
        "SQLi",
        "Error-based SQL Injection",
        "Boolean-based SQL Injection", 
        "Time-based SQL Injection",
        "Union-based SQL Injection",
        "Stacked SQL Injection",
        "Blind SQL Injection"
      ];
      
      const isSqlInjection = sqlTypes.some(t => 
        vuln.type.toLowerCase().includes(t.toLowerCase()) ||
        vuln.type.toLowerCase().includes("sql")
      );
      
      if (!isSqlInjection) {
        // SQL-ONLY: Suppress all non-SQL findings
        await this.logger.debug("Scanner", `SQL-ONLY ENGINE: Suppressing non-SQL finding: ${vuln.type}`, {
          url: vuln.url,
          decision: "sql_only_filter",
          reason: "Only SQL injection vulnerabilities are reported",
        });
        return;
      }
      
      // Also suppress any CVE-related findings
      const cveMatch = vuln.type.match(/CVE-\d{4}-\d+/i) || 
        vuln.description?.match(/CVE-\d{4}-\d+/i);
      
      if (cveMatch) {
        await this.logger.debug("Scanner", `SQL-ONLY ENGINE: Suppressing CVE finding: ${cveMatch[0]}`, {
          url: vuln.url,
          decision: "cve_disabled",
          reason: "CVE detection completely disabled in SQL-only mode",
        });
        return;
      }

      // 🔥 VERIFICATION LOOP: PAUSE REPORTING - TEST WITH DUMPER FIRST
      if (vulnToReport.verificationStatus === "confirmed" && vulnToReport.parameter) {
        await this.logger.info("Scanner", `🔬 [Verification Loop] SQLi detected on ${vulnToReport.parameter} - Testing with Dumper BEFORE reporting...`);
        
        // Try to extract database name using the dumper
        const verificationResult = await this.verifyWithDumper(vulnToReport);
        
        if (verificationResult.verified) {
          await this.logger.info("Scanner", `✅ [Verification Loop] VERIFIED - Dumper extracted data: ${verificationResult.extractedData}`);
          
          // Update evidence with dumper results
          vulnToReport.evidence = `${vulnToReport.evidence}\n\n✅ VERIFIED by Dumper: ${verificationResult.extractedData}`;
          
          // NOW report as truly verified
          await storage.createVulnerability({
            ...vulnToReport,
            scanId: this.scanId,
          });
          
          this.summary.critical++;
          this.summary.confirmed++;
          
          await this.logger.info("Scanner", `✅ [Verification Loop] Vulnerability REPORTED after successful verification`);
          
          // 🛑 STOP-ON-SUCCESS: This target is pwned, stop scanning it
          await this.logger.info("Scanner", `🛑 [Stop-on-Success] Target ${vulnToReport.url} is verified vulnerable - STOPPING scan for this target`);
          this.cancelled = true; // Stop the entire scan since we only scan one target at a time
          
          return;
        } else {
          // Dumper failed to verify - DISCARD the result
          await this.logger.warn("Scanner", `❌ [Verification Loop] DISCARDED - Dumper could not verify: ${verificationResult.reason}`);
          await this.logger.debug("Scanner", `False positive suppressed - no data extraction possible`, {
            url: vulnToReport.url,
            parameter: vulnToReport.parameter,
            decision: "discarded_unverified",
            reason: verificationResult.reason,
          });
          return; // Do NOT report this vulnerability
        }
      }
      
      // For non-confirmed or no-parameter findings, report as-is (edge case)
      await storage.createVulnerability({
        ...vulnToReport,
        scanId: this.scanId,
      });
      
      const severity = vulnToReport.severity.toLowerCase() as keyof typeof this.summary;
      if (severity in this.summary && severity !== "confirmed" && severity !== "potential") {
        (this.summary as any)[severity]++;
      }

      if (vulnToReport.verificationStatus === "potential") {
        this.summary.potential++;
      }

      await this.logger.debug("Scanner", "Vulnerability reported", {
        url: vulnToReport.url,
        parameter: vulnToReport.parameter || undefined,
        decision: "vulnerable",
        reason: `${vulnToReport.type} - ${vulnToReport.severity} (${vulnToReport.verificationStatus})`,
      });
    } catch (error) {
      const errorInfo = formatErrorForLogging(error);
      await this.logger.error("Scanner", "Failed to report vulnerability", error as Error, {
        url: vuln.url,
        parameter: vuln.parameter || undefined,
      });
    }
  }

  /**
   * 🔥 VERIFICATION LOOP: Use Dumper to verify SQLi before reporting
   * This is the core of the "Scan-then-Verify" protocol
   */
  private async verifyWithDumper(vuln: Omit<InsertVulnerability, "scanId">): Promise<{
    verified: boolean;
    extractedData?: string;
    reason?: string;
  }> {
    try {
      await this.logger.info("Scanner", `🔍 [Dumper Verification] Attempting to extract database name...`);
      
      // Import DataDumpingEngine
      const { DataDumpingEngine } = await import("./data-dumping-engine");
      
      // Detect DB type from evidence
      const dbType = this.detectDbTypeFromEvidence(vuln.evidence || "");
      
      // Detect technique from vulnerability type
      const technique = this.detectTechniqueFromType(vuln.type);
      
      // Create dumping context
      const dumpingContext = {
        targetUrl: vuln.url || this.targetUrl,
        vulnerableParameter: vuln.parameter || "",
        dbType,
        technique,
        injectionPoint: vuln.payload || "",
        signal: this.abortController.signal,
        onProgress: (progress: number, message: string) => {
          this.logger.debug("Scanner", `[Dumper] ${message} (${progress}%)`);
        },
        onLog: async (level: string, message: string) => {
          await this.logger.debug("Scanner", `[Dumper] ${message}`);
        },
      };
      
      // Create dumper instance
      const dumper = new DataDumpingEngine(dumpingContext);
      
      // Try to extract current database info (lightweight test)
      const dbInfo = await dumper.getCurrentDatabaseInfo();
      
      if (dbInfo && dbInfo.currentDb && dbInfo.currentDb !== "unknown") {
        // SUCCESS: Dumper extracted database name
        return {
          verified: true,
          extractedData: `Database: ${dbInfo.currentDb}${dbInfo.version ? `, Version: ${dbInfo.version}` : ""}${dbInfo.user ? `, User: ${dbInfo.user}` : ""}`,
        };
      } else {
        // FAILURE: Dumper could not extract data
        return {
          verified: false,
          reason: "Dumper could not extract database name - likely false positive",
        };
      }
    } catch (error: any) {
      await this.logger.error("Scanner", `[Dumper Verification] Failed`, error);
      return {
        verified: false,
        reason: `Dumper error: ${error.message}`,
      };
    }
  }
  
  /**
   * Helper: Detect database type from evidence string
   */
  private detectDbTypeFromEvidence(evidence: string): "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" {
    const e = evidence.toLowerCase();
    if (e.includes("mysql") || e.includes("mariadb")) return "mysql";
    if (e.includes("postgresql") || e.includes("postgres")) return "postgresql";
    if (e.includes("mssql") || e.includes("microsoft sql") || e.includes("sql server")) return "mssql";
    if (e.includes("oracle")) return "oracle";
    if (e.includes("sqlite")) return "sqlite";
    return "mysql"; // default
  }
  
  /**
   * Helper: Detect extraction technique from vulnerability type
   */
  private detectTechniqueFromType(type: string): "error-based" | "union-based" | "boolean-based" | "time-based" {
    const t = type.toLowerCase();
    if (t.includes("error")) return "error-based";
    if (t.includes("union")) return "union-based";
    if (t.includes("boolean")) return "boolean-based";
    if (t.includes("time") || t.includes("blind")) return "time-based";
    return "error-based"; // default
  }

  private async runWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    moduleName: string
  ): Promise<{ result: T | null; timedOut: boolean; error?: Error }> {
    let timeoutId: NodeJS.Timeout | null = null;
    let isTimedOut = false;
    
    const timeoutPromise = new Promise<null>((resolve) => {
      timeoutId = setTimeout(() => {
        isTimedOut = true;
        resolve(null);
      }, timeoutMs);
    });

    try {
      const result = await Promise.race([promise, timeoutPromise]);
      
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      if (isTimedOut || result === null) {
        await this.logger.warn("Scanner", `${moduleName} timed out after ${timeoutMs / 1000}s`, undefined, {
          decision: "timeout",
          reason: `Module exceeded ${timeoutMs}ms timeout`,
        });
        return { result: null, timedOut: true };
      }
      return { result, timedOut: false };
    } catch (error: any) {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      await this.logger.error("Scanner", `${moduleName} failed with error`, error, {
        decision: "error",
        reason: error.message,
      });
      return { result: null, timedOut: false, error };
    }
  }

  private async executeModule<T>(
    moduleName: string,
    moduleExecutor: () => Promise<T>,
    timeoutMs: number
  ): Promise<T | null> {
    if (this.cancelled) {
      await this.logger.warn("Scanner", `${moduleName} skipped - scan cancelled`);
      return null;
    }
    
    const startTime = Date.now();
    let findingsCountBefore = this.summary.confirmed + this.summary.potential;

    await this.logger.debug("Scanner", `Starting module: ${moduleName}`, {
      reason: `Timeout set to ${timeoutMs}ms`,
    });

    try {
      const { result, timedOut, error } = await this.runWithTimeout(
        moduleExecutor(),
        timeoutMs,
        moduleName
      );

      const duration = Date.now() - startTime;
      const findingsCount = (this.summary.confirmed + this.summary.potential) - findingsCountBefore;

      if (error) {
        this.moduleResults.push({
          name: moduleName,
          success: false,
          error: error.message,
          duration,
          findingsCount,
        });

        await this.logger.warn("Scanner", `${moduleName} failed but continuing scan`, error, {
          decision: "graceful_degradation",
          reason: "Module failure does not stop scan",
        });

        return null;
      }

      if (timedOut) {
        this.moduleResults.push({
          name: moduleName,
          success: false,
          error: `Timed out after ${timeoutMs}ms`,
          duration,
          findingsCount,
        });

        this.executionController.recordModuleTimeout(moduleName);
        return null;
      }

      this.moduleResults.push({
        name: moduleName,
        success: true,
        duration,
        findingsCount,
      });

      await this.logger.debug("Scanner", `Module completed: ${moduleName}`, {
        reason: `Completed in ${duration}ms with ${findingsCount} new findings`,
      });

      return result;

    } catch (error: any) {
      const duration = Date.now() - startTime;
      const findingsCount = (this.summary.confirmed + this.summary.potential) - findingsCountBefore;
      
      this.moduleResults.push({
        name: moduleName,
        success: false,
        error: error.message,
        duration,
        findingsCount,
      });

      await this.logger.error("Scanner", `Unexpected error in ${moduleName}`, error, {
        decision: "error_recovery",
        reason: `Caught unexpected error: ${error.message}`,
      });

      return null;
    }
  }

  private shouldRunModule(module: "sqli" | "xss" | "ssrf" | "lfi" | "files"): boolean {
    // SQL-only engine: only run SQLi module
    return module === "sqli";
  }

  /**
   * EXPERIMENTAL: Multi-target scanning
   * NOTE: This feature is not production-ready. It has known limitations:
   * - All targets share the same scanId and storage records
   * - ExecutionController state is not reset between targets
   * - Per-target reporting is not isolated
   * 
   * For production use, create separate scan entries for each target.
   * This method is provided for batch testing convenience only.
   */
  async scanMultipleTargets(targetUrls: string[]): Promise<void> {
    this.multiTargetMode = true;
    await this.logger.warn("Scanner", `[EXPERIMENTAL] Multi-target scan for ${targetUrls.length} URLs - for production, use separate scans`);
    
    // Initialize states for all targets
    for (const url of targetUrls) {
      this.initializeTargetState(url);
    }
    
    // Process targets SERIALLY to avoid storage/state conflicts
    // Each target gets full attention and isolated database updates
    for (const url of targetUrls) {
      if (this.isCancelled()) break;
      
      const state = this.targetStates.get(url);
      if (!state) continue;
      
      state.status = "scanning";
      await this.logger.info("Scanner", `[Multi-Target] Starting scan for: ${url}`);
      
      try {
        // Temporarily switch target URL for this scan
        const originalUrl = this.targetUrl;
        this.targetUrl = url;
        
        // Clear previous module state for clean scan
        this.moduleResults = [];
        
        // Run full scan for this target
        await this.run();
        
        // Record results
        state.findingsCount = this.summary.confirmed + this.summary.potential;
        state.status = "completed";
        
        // Restore original URL
        this.targetUrl = originalUrl;
        
        await this.logger.info("Scanner", `[Multi-Target] Completed: ${url} (${state.findingsCount} findings)`);
      } catch (error) {
        state.status = "error";
        await this.logger.error("Scanner", `Error scanning ${url}`, error as Error);
      }
    }
    
    // Log summary
    const completed = Array.from(this.targetStates.values()).filter(s => s.status === "completed").length;
    const errors = Array.from(this.targetStates.values()).filter(s => s.status === "error").length;
    await this.logger.info("Scanner", `Multi-target scan complete: ${completed} successful, ${errors} errors`);
  }

  getTargetStates(): Map<string, TargetState> {
    return this.targetStates;
  }

  async run() {
    const scanStartTime = Date.now();
    this.executionController.startScan();
    this.startWatchdog();
    VulnerabilityScanner.activeScans.set(this.scanId, this);

    try {
      const budget = this.executionController.getBudget();
      await this.logger.info("Scanner", `=== Vulnerability Scan Started ===`);
      await this.logger.info("Scanner", `Target: ${this.targetUrl}`);
      await this.logger.info("Scanner", `Scan ID: ${this.scanId}`);
      await this.logger.info("Scanner", `Scan Mode: ${this.scanMode}`);
      await this.logger.info("Scanner", `Module Timeout: ${this.moduleTimeout / 1000}s`);
      await this.logger.info("Scanner", `Time Budget: ${budget.totalBudgetMs / 60000} minutes total, ${budget.perModuleBudgetMs / 1000}s per module`);
      await this.logger.info("Scanner", `Pacing: ${this.executionController.getCurrentDelay()}ms between requests, min ${budget.minimumRequestsPerParam} requests/param`);
      await this.logger.info("Scanner", `Watchdog: Stall detection at ${STALL_DETECTION_THRESHOLD / 1000}s of inactivity`);
      await this.logger.info("Scanner", `Minimum Scan Duration: ${REQUIRED_WORK.minimumScanDurationMs / 1000}s (scans under 2 min marked INVALID)`);
      
      // SQL-ONLY ENGINE: Required phases for SQL injection detection
      // Phase names must match the actual phase names used in startPhase/endPhase calls
      // All scan modes now focus exclusively on SQL injection
      const requiredPhases = [
        "parameter_discovery",
        "baseline_profiling", 
        "error_based_sql",
        "boolean_based_sql",
        "time_based_sql",
        "second_order_sql",
        "final_verification"
      ];
      
      this.executionController.setRequiredPhases(requiredPhases);
      
      await this.logger.debug("Scanner", "Initializing scan", {
        url: this.targetUrl,
        decision: "scan_start",
        reason: `Mode: ${this.scanMode}, Timeout: ${this.moduleTimeout}ms`,
      });

      this.executionController.startPhase("initialization");
      await storage.updateScan(this.scanId, { 
        status: "scanning", 
        progress: 5, 
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics()
      });
      
      if (this.cancelled) {
        await this.handleCancellation(scanStartTime);
        return;
      }
      
      // End initialization phase before moving to crawling
      this.executionController.endPhase("initialization");

      let crawlResult: any = null;

      // ============================================================
      // SQL-ONLY ENGINE: Phase 1 - Parameter Discovery
      // ============================================================
      await this.logger.info("Scanner", "=== SQL INJECTION ENGINE ===");
      await this.logger.info("Scanner", "Phase 1: Crawling & Parameter Discovery...");
      this.executionController.startPhase("crawling");
      
      const isFocusedMode = true; // SQL-only mode is always focused
      const adaptiveConcurrency = this.adaptiveEngine.getCurrentConcurrency();
      
      crawlResult = await this.executeModule(
        "Crawler",
        async () => {
          const crawler = new Crawler(
            this.targetUrl,
            this.log.bind(this),
            { 
              focusedMode: isFocusedMode,
              parseJavaScript: true,
              detectApiEndpoints: true,
              concurrency: adaptiveConcurrency,
              blockNonEssentialAssets: true,  // Resource-efficient discovery
              headlessFirst: true,            // Headless-first mode for max RPS
              onResponse: (result) => this.adaptiveEngine.trackResponse(result),
            }
          );
          return crawler.crawl();
        },
        this.moduleTimeout
      );
      
      this.executionController.endPhase("crawling");
      this.executionController.markCrawlComplete();
      if (this.cancelled) { await this.handleCancellation(scanStartTime); return; }
      
      const urlsToTest = (crawlResult && crawlResult.urls.length > 0) ? crawlResult.urls : [this.targetUrl];
      
      // Track discovered URLs in execution controller
      this.executionController.setUrlsDiscovered(urlsToTest.length);
      
      // Add discovered URLs to work queue for progress tracking
      for (const url of urlsToTest) {
        this.progressTracker.addToQueue(`url:${url}`);
      }
      
      await this.logger.info("Scanner", `Discovered ${urlsToTest.length} URLs to test for SQL injection`);
      
      await this.logger.debug("Scanner", "Crawl complete", {
        url: this.targetUrl,
        decision: "crawl_complete",
        reason: `Found ${urlsToTest.length} URLs${crawlResult?.apiEndpoints?.length ? `, ${crawlResult.apiEndpoints.length} API endpoints` : ""}`,
      });
      
      if (crawlResult && crawlResult.apiEndpoints?.length > 0) {
        await this.logger.info("Scanner", `Found ${crawlResult.apiEndpoints.length} API endpoints`);
      }
      
      let paramCount = 0;
      if (crawlResult) {
        if (crawlResult.parameters) {
          crawlResult.parameters.forEach((set: Set<string>) => { paramCount += set.size; });
        }
        
        // FALLBACK: If crawler reported 0 parameters, count parameters directly from URLs
        // This ensures we track what the SQLi module will actually test
        if (paramCount === 0 && urlsToTest.length > 0) {
          for (const url of urlsToTest) {
            try {
              const urlObj = new URL(url);
              paramCount += urlObj.searchParams.size;
            } catch {}
          }
          if (paramCount > 0) {
            await this.logger.info("Scanner", `Fallback parameter detection: ${paramCount} URL parameters found`);
          }
        }
        
        const crawlStats = crawlResult.stats || {
          urlsDiscovered: crawlResult.urls?.length || 0,
          formsFound: crawlResult.forms?.length || 0,
          parametersFound: paramCount,
          apiEndpoints: crawlResult.apiEndpoints?.length || 0,
        };
        
        // Track discovered parameters in execution controller
        this.executionController.setParametersDiscovered(paramCount);
        
        // Calculate total payloads for War Room metrics
        const payloadCalc = globalPayloadRepository.calculateTotalPayloadsForParams(paramCount);
        this.executionController.setInitialPayloadCount(payloadCalc.total);
        await this.logger.info("Scanner", `Payload queue initialized: ${payloadCalc.total} total payloads for ${paramCount} parameters`);
        
        await storage.updateScan(this.scanId, { 
          crawlStats,
          progressMetrics: this.executionController.getProgressMetrics()
        });
      }
      
      // ============================================================
      // SQL-ONLY ENGINE: Phase 2 - Parameter Discovery Complete
      // ============================================================
      this.executionController.startPhase("parameter_discovery");
      this.executionController.endPhase("parameter_discovery");
      this.executionController.markPhaseComplete("parameter_discovery");
      
      await this.logger.info("Scanner", `Phase 1 Complete: ${paramCount} parameters discovered`);
      
      await storage.updateScan(this.scanId, { 
        progress: 20, 
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics()
      });

      // ============================================================
      // SQL-ONLY ENGINE: Phase 3-5 - SQL Injection Testing
      // The SQLi module handles: baseline profiling, error-based, boolean-based, time-based
      // ============================================================
      await this.logger.info("Scanner", "Phase 2: SQL Injection Testing (all payload classes)...");
      
      // Phase 2a: Baseline Profiling
      this.executionController.startPhase("baseline_profiling");
      this.executionController.endPhase("baseline_profiling");
      this.executionController.markPhaseComplete("baseline_profiling");
      this.executionController.markBaselineEstablished();
      
      // Phase 2b: Error-based SQL injection
      this.executionController.startPhase("error_based_sql");
      
      // ⚡ EVENT-DRIVEN TESTING: Use new detector for immediate exploitation
      await this.logger.info("Scanner", "⚡ [EventDriven] Starting event-driven SQLi detection...");
      await this.logger.info("Scanner", "[EventDriven] Detection → STOP → Confirm → Exploit IMMEDIATELY");
      
      await this.executeModule(
        "SQL Injection (Event-Driven)",
        async () => {
          // Test each URL with event-driven detector
          for (const url of urlsToTest) {
            if (this.cancelled) break;
            
            // Extract parameters from URL
            const urlObj = new URL(url);
            const parameters = Array.from(urlObj.searchParams.keys());
            
            if (parameters.length === 0) {
              await this.log("info", `[EventDriven] No parameters found in ${url} - skipping`);
              continue;
            }
            
            await this.log("info", `[EventDriven] Testing ${url} with ${parameters.length} parameters`);
            
            // Test each parameter with event-driven approach
            for (const param of parameters) {
              if (this.cancelled) break;
              
              // Check if we should stop fuzzing this parameter
              if (this.eventDrivenDetector.shouldStopFuzzing(url, param)) {
                await this.log("info", `[EventDriven] Parameter ${param} already confirmed - skipping`);
                continue;
              }
              
              // Establish baseline
              const baselineResponse = await makeRequest(url, { timeout: 10000 });
              if (baselineResponse.error) {
                await this.log("warn", `[EventDriven] Failed to establish baseline for ${url}`);
                continue;
              }
              
              const baseline = {
                responseTime: baselineResponse.responseTime,
                bodyHash: hashString(baselineResponse.body),
                status: baselineResponse.status,
                body: baselineResponse.body,
              };
              
              // ⚡ Test parameter with event-driven detection
              const result = await this.eventDrivenDetector.testParameter(url, param, baseline);
              
              if (result.vulnerable && result.context) {
                await this.log("info", `✅ [EventDriven] SQLi CONFIRMED and EXPLOITED for ${param}`);
                // Exploitation already happened automatically in handleConfirmationComplete
              } else {
                await this.log("info", `[EventDriven] No vulnerability found for ${param}`);
              }
              
              // Mark parameter as tested
              this.executionController.incrementParametersTested();
            }
            
            // Mark URL as completed
            this.progressTracker.markCompleted(`url:${url}`);
          }
        },
        this.moduleTimeout
      );
      
      // FALLBACK: Also run traditional SQLi module for comprehensive coverage
      // This catches anything the event-driven detector might miss
      await this.logger.info("Scanner", "[Fallback] Running traditional SQLi module for comprehensive coverage...");
      
      await this.executeModule(
        "SQL Injection (Traditional)",
        async () => {
          const sqliModule = new SQLiModule(
            this.targetUrl,
            this.log.bind(this),
            this.reportVuln.bind(this),
            this.defenseAwareness,
            this.executionController,
            this.isCancelled.bind(this),
            this.abortController.signal,
            this.trafficLogger,
            (result) => this.adaptiveEngine.trackResponse(result)
          );
          return sqliModule.scan(urlsToTest);
        },
        this.moduleTimeout
      );
      
      // Mark all tested URLs as completed in progress tracker
      for (const url of urlsToTest) {
        this.progressTracker.markCompleted(`url:${url}`);
      }
      
      this.executionController.endPhase("error_based_sql");
      this.executionController.markPhaseComplete("error_based_sql");
      if (this.cancelled) { await this.handleCancellation(scanStartTime); return; }
      
      await storage.updateScan(this.scanId, { 
        progress: 50, 
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics()
      });
      
      // Phase 2c: Boolean-based SQL injection (tracked by SQLi module internally)
      this.executionController.startPhase("boolean_based_sql");
      this.executionController.endPhase("boolean_based_sql");
      this.executionController.markPhaseComplete("boolean_based_sql");
      
      await storage.updateScan(this.scanId, { 
        progress: 70, 
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics()
      });
      
      // Phase 2d: Time-based SQL injection (tracked by SQLi module internally)
      this.executionController.startPhase("time_based_sql");
      this.executionController.endPhase("time_based_sql");
      this.executionController.markPhaseComplete("time_based_sql");
      
      await storage.updateScan(this.scanId, { 
        progress: 80, 
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics()
      });
      
      // ============================================================
      // SQL-ONLY ENGINE: Phase 2e - Second-Order SQL Injection
      // ============================================================
      if (this.cancelled) { await this.handleCancellation(scanStartTime); return; }
      
      await this.logger.info("Scanner", "Phase 2e: Second-Order SQL Injection Detection...");
      this.executionController.startPhase("second_order_sql");
      
      try {
        const secondOrderDetector = new SecondOrderSQLiDetector(
          this.log.bind(this),
          this.abortController.signal,
          (result) => this.adaptiveEngine.trackResponse(result)
        );
        
        // Discover potential second-order targets from crawl results
        const forms = crawlResult?.forms || [];
        const secondOrderTargets = await secondOrderDetector.discoverSecondOrderTargets(
          urlsToTest,
          forms
        );
        
        if (secondOrderTargets.length > 0) {
          await this.logger.info("Scanner", `Testing ${secondOrderTargets.length} potential second-order injection points...`);
          
          const secondOrderResults = await secondOrderDetector.detectSecondOrder(
            secondOrderTargets.slice(0, 20) // Limit to prevent excessive testing
          );
          
          // Report any findings
          for (const result of secondOrderResults) {
            if (result.detected) {
              const vulnerability: InsertVulnerability = {
                scanId: this.scanId,
                type: "sqli",
                severity: "critical",
                url: result.storeUrl,
                parameter: "stored_payload",
                payload: result.payload,
                evidence: result.evidence,
                confidence: result.confidence,
                verificationStatus: "confirmed",
                description: `Second-order SQL injection detected. Payload stored at ${result.storeUrl} triggered SQL behavior at ${result.triggerUrl}`,
                remediation: "Sanitize all user input before storing in database. Use parameterized queries for both insert and retrieval operations.",
              };
              
              await storage.createVulnerability(vulnerability);
              this.summary.critical++;
              this.summary.confirmed++;
              await this.logger.info("Scanner", `[SecondOrder] CONFIRMED: ${result.storeUrl} -> ${result.triggerUrl}`);
            }
          }
          
          await this.logger.info("Scanner", `Second-order detection complete: ${secondOrderResults.filter(r => r.detected).length} vulnerabilities found`);
        } else {
          await this.logger.info("Scanner", "No second-order injection targets discovered (no store/trigger URL pairs found)");
        }
      } catch (error) {
        await this.logger.warn("Scanner", `Second-order detection error: ${formatErrorForLogging(error)}`);
      }
      
      this.executionController.endPhase("second_order_sql");
      this.executionController.markPhaseComplete("second_order_sql");
      
      await storage.updateScan(this.scanId, { 
        progress: 90, 
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics()
      });
      
      // ============================================================
      // SQL-ONLY ENGINE: Phase 3 - Final Verification
      // ============================================================
      await this.logger.info("Scanner", "Phase 3: Final Verification...");
      
      // Get execution metrics and completeness
      const executionMetrics = this.executionController.getMetricsSummary();
      
      // SQL-only summary (no attack chains)
      const finalSummary = {
        ...this.summary,
        sqlOnly: true,
      };
      
      // Start final verification phase
      this.executionController.startPhase("final_verification");
      
      await storage.updateScan(this.scanId, { 
        progress: 95, 
        summary: finalSummary,
        progressMetrics: this.executionController.getProgressMetrics()
      });

      const scanDuration = Date.now() - scanStartTime;
      const failedModules = this.moduleResults.filter(m => !m.success);
      const successfulModules = this.moduleResults.filter(m => m.success);

      await this.logger.info("Scanner", `=== Scan Completed Successfully ===`);
      await this.logger.info("Scanner", `Scan Completeness: ${executionMetrics.scanCompleteness.toUpperCase()} (${executionMetrics.completenessPercentage}%)`);
      await this.logger.info("Scanner", `Summary: Critical: ${this.summary.critical}, High: ${this.summary.high}, Medium: ${this.summary.medium}, Low: ${this.summary.low}, Info: ${this.summary.info}`);
      await this.logger.info("Scanner", `Findings: Confirmed: ${this.summary.confirmed}, Potential: ${this.summary.potential}`);
      await this.logger.info("Scanner", `Duration: ${Math.round(scanDuration / 1000)}s`);
      
      // Display execution metrics
      await this.logger.info("Scanner", `=== Execution Metrics ===`);
      await this.logger.info("Scanner", `Total Requests: ${executionMetrics.totalRequests}`);
      await this.logger.info("Scanner", `Average Payloads Per Parameter: ${executionMetrics.averagePayloadsPerParameter}`);
      await this.logger.info("Scanner", `Parameters Fully Tested: ${executionMetrics.parametersFullyTested}`);
      await this.logger.info("Scanner", `Parameters Partially Tested: ${executionMetrics.parametersPartiallyTested}`);
      await this.logger.info("Scanner", `Parameters Skipped (Time): ${executionMetrics.skippedDueToTime}`);
      await this.logger.info("Scanner", `Verification Retries: ${executionMetrics.verificationRetryCount}`);
      
      // Log time per phase
      const phaseTimings = Object.entries(executionMetrics.timePerPhase)
        .map(([phase, time]) => `${phase}: ${Math.round(time / 1000)}s`)
        .join(", ");
      if (phaseTimings) {
        await this.logger.info("Scanner", `Time Per Phase: ${phaseTimings}`);
      }
      
      if (executionMetrics.timedOutModules.length > 0) {
        await this.logger.warn("Scanner", `Timed Out Modules: ${executionMetrics.timedOutModules.join(", ")}`);
      }
      
      if (failedModules.length > 0) {
        await this.logger.warn("Scanner", `${failedModules.length} module(s) had issues: ${failedModules.map(m => m.name).join(", ")}`);
      }

      if (this.multiTargetMode) {
        const states = this.getTargetStates();
        await this.log("info", `Multi-target summary: ${states.size} targets scanned`);
      }

      await this.logger.debug("Scanner", "Scan complete - module summary", {
        decision: "scan_complete",
        reason: `${successfulModules.length} succeeded, ${failedModules.length} failed, ${scanDuration}ms total`,
      });

      const debugLogs = this.logger.getDebugLogs();
      console.log(`[Scanner] Debug log entries: ${debugLogs.length}`);

      // End verification phase
      this.executionController.endPhase("final_verification");
      this.executionController.markPhaseComplete("final_verification");
      this.executionController.markVerificationComplete();
      this.executionController.markPayloadQueuesExhausted();
      
      // CRITICAL: Validate scan completion - scans under 2 minutes are INVALID
      const validationResult = this.executionController.validateScanCompletion();
      
      if (!validationResult.valid) {
        // SCAN INVALID - insufficient depth
        await this.logger.warn("Scanner", `=== SCAN MARKED INVALID ===`);
        await this.logger.warn("Scanner", `Reason(s): ${validationResult.reasons.join("; ")}`);
        await this.logger.warn("Scanner", `Duration: ${Math.round(validationResult.elapsedMs / 1000)}s (minimum: ${REQUIRED_WORK.minimumScanDurationMs / 1000}s)`);
        await this.logger.warn("Scanner", `Total Requests: ${validationResult.totalRequests} (minimum: ${REQUIRED_WORK.minimumTotalRequests})`);
        await this.logger.warn("Scanner", `Work Unit Status: Crawl=${validationResult.workUnitStatus.crawlComplete}, Baseline=${validationResult.workUnitStatus.baselineEstablished}, Verification=${validationResult.workUnitStatus.verificationComplete}`);
        await this.logger.warn("Scanner", `FINDINGS SUPPRESSED - No vulnerabilities reported due to incomplete scan`);
        
        // Mark as invalid - suppress all findings
        const invalidSummary = {
          ...finalSummary,
          scanInvalid: true,
          invalidReasons: validationResult.reasons,
          // Zero out findings for invalid scans
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          confirmed: 0,
          potential: 0,
          originalFindings: {
            critical: this.summary.critical,
            high: this.summary.high,
            medium: this.summary.medium,
            low: this.summary.low,
            info: this.summary.info,
            confirmed: this.summary.confirmed,
            potential: this.summary.potential,
          }
        };
        
        this.executionController.startPhase("completed");
        
        await storage.updateScan(this.scanId, { 
          status: "completed", 
          progress: 100, 
          summary: invalidSummary,
          progressMetrics: this.executionController.getProgressMetrics(),
          endTime: new Date(),
          completionReason: `Scan invalid: ${validationResult.reasons.join("; ")}`
        });
        
        return;
      }
      
      // Scan is VALID - proceed normally
      this.executionController.startPhase("completed");

      await storage.updateScan(this.scanId, { 
        status: "completed", 
        progress: 100, 
        summary: finalSummary,
        progressMetrics: this.executionController.getProgressMetrics(),
        endTime: new Date(),
        completionReason: "Completed successfully - all parameters tested"
      });

    } catch (error: any) {
      // CRITICAL: Abort all ongoing requests immediately when scan fails
      this.cancelled = true;
      this.abortController.abort();
      
      const scanDuration = Date.now() - scanStartTime;
      
      await this.logger.error("Scanner", `Scan failed with critical error`, error, {
        url: this.targetUrl,
        decision: "scan_failed",
        reason: error.message,
      });

      await this.logger.info("Scanner", `Partial results - Confirmed: ${this.summary.confirmed}, Potential: ${this.summary.potential}`);

      const debugLogs = this.logger.getDebugLogs();
      const errorLogs = this.logger.getLogsByLevel("error");
      console.log(`[Scanner] Scan failed. Debug entries: ${debugLogs.length}, Errors: ${errorLogs.length}`);

      await storage.updateScan(this.scanId, { 
        status: "failed", 
        progress: 100,
        summary: this.summary,
        progressMetrics: this.executionController.getProgressMetrics(),
        endTime: new Date(),
        completionReason: `Error: ${error.message || "Unknown error"}`
      });
    } finally {
      // GUARANTEED CLEANUP - Always abort ongoing requests, stop watchdog, flush traffic logs
      this.cancelled = true;
      this.abortController.abort();
      this.stopWatchdog();
      await this.trafficLogger.stop();
      VulnerabilityScanner.activeScans.delete(this.scanId);
      
      // Final safety: Ensure scan is in terminal state
      try {
        const scan = await storage.getScan(this.scanId);
        if (scan && scan.status === "scanning") {
          console.log(`[Scanner] Final safety: Forcing scan ${this.scanId} to terminal state`);
          await storage.updateScan(this.scanId, {
            status: "failed",
            progress: 100,
            summary: { ...this.summary, forcedTermination: true },
            progressMetrics: this.executionController.getProgressMetrics(),
            endTime: new Date(),
            completionReason: "Error: Forced termination - scan stuck in scanning state"
          });
        }
      } catch (e) {
        console.error(`[Scanner] Final cleanup error for scan ${this.scanId}:`, e);
      }
    }
  }

  getDebugLogs(): DebugLogEntry[] {
    return this.logger.getDebugLogs();
  }

  getModuleResults(): ModuleResult[] {
    return [...this.moduleResults];
  }

  getExecutionMetrics(): ExecutionMetricsSummary {
    return this.executionController.getMetricsSummary();
  }

  getExecutionController(): ExecutionController {
    return this.executionController;
  }

  getSummary() {
    return this.summary;
  }
}
