export interface ScanBudget {
  totalBudgetMs: number;
  perParameterBudgetMs: number;
  perModuleBudgetMs: number;
  minimumRequestsPerParam: number;
  zeroSpeedMode: boolean;
}

export const DEFAULT_BUDGET: ScanBudget = {
  totalBudgetMs: 60 * 60 * 1000, // FIXED: 1 hour max total scan time
  perParameterBudgetMs: 5 * 60 * 1000, // FIXED: 5 minutes per parameter
  perModuleBudgetMs: 15 * 60 * 1000, // FIXED: 15 minutes per module (phase)
  minimumRequestsPerParam: 50,
  zeroSpeedMode: false, // FIXED: Disable zero-speed mode
};

export interface RequiredWorkUnits {
  minimumScanDurationMs: number;
  minimumPayloadsPerParameter: number;
  minimumPayloadClassesPerParam: number;
  minimumTotalRequests: number;
  requireCrawlComplete: boolean;
  requireBaselineEstablished: boolean;
  requireVerificationComplete: boolean;
  requireWorkQueueEmpty: boolean;
}

export const REQUIRED_WORK: RequiredWorkUnits = {
  minimumScanDurationMs: 0,
  minimumPayloadsPerParameter: 0,
  minimumPayloadClassesPerParam: 0,
  minimumTotalRequests: 0,
  requireCrawlComplete: true,
  requireBaselineEstablished: true,
  requireVerificationComplete: true,
  requireWorkQueueEmpty: true,
};

export interface WorkUnitStatus {
  crawlComplete: boolean;
  baselineEstablished: boolean;
  verificationComplete: boolean;
  payloadQueuesExhausted: boolean;
  allPhasesComplete: boolean;
}

export interface ScanValidationResult {
  valid: boolean;
  reasons: string[];
  workUnitStatus: WorkUnitStatus;
  elapsedMs: number;
  totalRequests: number;
}

export interface ScanDepthMetrics {
  totalRequests: number;
  payloadsPerParameter: Map<string, number>;
  timePerPhase: Map<string, number>;
  verificationRetries: number;
  parametersFullyTested: number;
  parametersPartiallyTested: number;
  skippedDueToTime: number;
}

export interface PayloadClassTracking {
  parameter: string;
  classesTesteed: Set<string>;
  totalPayloads: number;
}

export type ScanCompleteness = "complete" | "partial";

export interface CompletenessResult {
  status: ScanCompleteness;
  reasons: string[];
  percentage: number;
  timedOutModules: string[];
}

export interface ExecutionMetricsSummary {
  totalRequests: number;
  averagePayloadsPerParameter: number;
  timePerPhase: Record<string, number>;
  verificationRetryCount: number;
  completenessPercentage: number;
  scanCompleteness: ScanCompleteness;
  timedOutModules: string[];
  parametersFullyTested: number;
  parametersPartiallyTested: number;
  skippedDueToTime: number;
}

export interface ProgressMetrics {
  currentPhase: string;
  phaseDescription: string;
  payloadsDiscovered: number;
  payloadsTested: number;
  payloadsRemaining: number;
  parametersDiscovered: number;
  parametersTested: number;
  urlsDiscovered: number;
  urlsTested: number;
  lastActivity: string;
  // War Room Metrics
  currentParameter?: string;
  currentUrl?: string;
  rps?: number;
  totalPayloadsInQueue?: number;
  payloadsSent?: number;
  blocksEncountered?: number;
  startTimestamp?: number;
  // Live Payload View (Elite Status)
  currentPayload?: string;
  currentPayloadType?: string;
  currentConfidence?: number;
  detectedDbType?: string;
  detectedContext?: string;
  // Adaptive Testing Metrics
  adaptiveConcurrency?: number;
  parametersSkipped?: number;
  coveragePerHour?: number;
  estimatedTimeRemaining?: number;
  workQueueSize?: number;
  successRate?: number;
}

const PHASE_DESCRIPTIONS: Record<string, string> = {
  initialization: "Initializing scan...",
  crawling: "Crawling website and discovering URLs",
  parameter_discovery: "Identifying parameters to test",
  baseline_profiling: "Establishing baseline responses",
  error_based_sql: "Testing for error-based SQL injection",
  boolean_based_sql: "Testing for boolean-based SQL injection",
  time_based_sql: "Testing for time-based SQL injection",
  union_based_sql: "Testing for union-based SQL injection",
  second_order_sql: "Testing for second-order SQL injection",
  final_verification: "Verifying findings",
  completed: "Scan complete",
};

export class ExecutionController {
  private budget: ScanBudget;
  private metrics: ScanDepthMetrics;
  private payloadTracking: Map<string, PayloadClassTracking>;
  private scanStartTime: number;
  private currentPhaseStart: number;
  private currentPhase: string;
  private timedOutModules: string[];
  private requestDelayMs: number;
  private baseDelayMs: number;
  private consecutiveErrors: number;
  private logCallback: (level: string, message: string) => Promise<void>;
  private payloadsDiscovered: number = 0;
  private payloadsTested: number = 0;
  private parametersDiscovered: number = 0;
  private parametersTested: number = 0;
  private urlsDiscovered: number = 0;
  private urlsTested: number = 0;
  private lastActivityTime: number = Date.now();
  // War Room Metrics
  private currentParameter: string = "";
  private currentUrl: string = "";
  private requestTimestamps: number[] = [];
  private totalPayloadsInQueue: number = 0;
  private blocksEncountered: number = 0;
  // Live Payload View (Elite Status)
  private currentPayload: string = "";
  private currentPayloadType: string = "";
  private currentConfidence: number = 0;
  private detectedDbType: string = "unknown";
  private detectedContext: string = "unknown";
  
  // Adaptive Testing Metrics
  private adaptiveConcurrency: number = 10;
  private maxConcurrency: number = 100; // FIXED: Hard limit to prevent explosion
  private parametersSkipped: number = 0;
  private coveragePerHour: number = 0;
  private estimatedTimeRemaining: number = 0;
  private workQueueSize: number = 0;
  private successRate: number = 100;
  
  // Work unit tracking - scan cannot complete without these
  private workUnitStatus: WorkUnitStatus = {
    crawlComplete: false,
    baselineEstablished: false,
    verificationComplete: false,
    payloadQueuesExhausted: false,
    allPhasesComplete: false,
  };
  private completedPhases: Set<string> = new Set();
  private requiredPhases: string[] = [];

  constructor(
    budget: Partial<ScanBudget> = {},
    logCallback: (level: string, message: string) => Promise<void>
  ) {
    this.budget = { ...DEFAULT_BUDGET, ...budget };
    this.metrics = {
      totalRequests: 0,
      payloadsPerParameter: new Map(),
      timePerPhase: new Map(),
      verificationRetries: 0,
      parametersFullyTested: 0,
      parametersPartiallyTested: 0,
      skippedDueToTime: 0,
    };
    this.payloadTracking = new Map();
    this.scanStartTime = Date.now();
    this.currentPhaseStart = Date.now();
    this.currentPhase = "initialization";
    this.timedOutModules = [];
    this.baseDelayMs = 100;
    this.requestDelayMs = this.baseDelayMs;
    this.consecutiveErrors = 0;
    this.logCallback = logCallback;
  }

  startScan(): void {
    this.scanStartTime = Date.now();
    this.currentPhaseStart = Date.now();
    this.logCallback("debug", `[ExecutionControl] Scan started with budget: ${this.budget.totalBudgetMs}ms total`);
  }

  startPhase(phaseName: string): void {
    if (this.currentPhase && this.currentPhase !== "initialization") {
      const elapsed = Date.now() - this.currentPhaseStart;
      this.metrics.timePerPhase.set(this.currentPhase, elapsed);
    }
    this.currentPhase = phaseName;
    this.currentPhaseStart = Date.now();
    this.updateActivity();
    this.logCallback("debug", `[ExecutionControl] Phase started: ${phaseName}`);
  }

  endPhase(phaseName: string): void {
    const elapsed = Date.now() - this.currentPhaseStart;
    this.metrics.timePerPhase.set(phaseName, elapsed);
    this.logCallback("debug", `[ExecutionControl] Phase ended: ${phaseName} (${elapsed}ms)`);
  }

  recordModuleTimeout(moduleName: string): void {
    if (!this.timedOutModules.includes(moduleName)) {
      this.timedOutModules.push(moduleName);
    }
    this.logCallback("warn", `[ExecutionControl] Module timed out: ${moduleName}`);
  }

  async recordRequest(parameter?: string): Promise<void> {
    this.metrics.totalRequests++;
    this.payloadsTested++;
    this.updateActivity();
    
    if (parameter) {
      const current = this.metrics.payloadsPerParameter.get(parameter) || 0;
      this.metrics.payloadsPerParameter.set(parameter, current + 1);
    }

    await this.applyPacing();
  }

  recordVerificationRetry(): void {
    this.metrics.verificationRetries++;
  }

  recordError(): void {
    this.consecutiveErrors++;
    this.requestDelayMs = Math.min(this.baseDelayMs * Math.pow(2, this.consecutiveErrors), 5000);
    this.logCallback("debug", `[ExecutionControl] Error detected, delay increased to ${this.requestDelayMs}ms`);
  }

  recordSuccess(): void {
    if (this.consecutiveErrors > 0) {
      this.consecutiveErrors = Math.max(0, this.consecutiveErrors - 1);
      this.requestDelayMs = Math.max(this.baseDelayMs, this.requestDelayMs / 2);
    }
  }

  private async applyPacing(): Promise<void> {
    if (this.requestDelayMs > 0) {
      await this.delay(this.requestDelayMs);
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  trackPayloadClass(parameter: string, payloadClass: string): void {
    let tracking = this.payloadTracking.get(parameter);
    if (!tracking) {
      tracking = {
        parameter,
        classesTesteed: new Set(),
        totalPayloads: 0,
      };
      this.payloadTracking.set(parameter, tracking);
    }
    tracking.classesTesteed.add(payloadClass);
    tracking.totalPayloads++;
  }

  hasMinimumPayloadClasses(parameter: string, requiredClasses: number = 3): boolean {
    const tracking = this.payloadTracking.get(parameter);
    if (!tracking) return false;
    return tracking.classesTesteed.size >= requiredClasses;
  }

  getTestedPayloadClasses(parameter: string): string[] {
    const tracking = this.payloadTracking.get(parameter);
    if (!tracking) return [];
    return Array.from(tracking.classesTesteed);
  }

  shouldContinueTesting(parameter: string): boolean {
    const payloadsForParam = this.metrics.payloadsPerParameter.get(parameter) || 0;
    
    if (payloadsForParam < this.budget.minimumRequestsPerParam) {
      return true;
    }

    const tracking = this.payloadTracking.get(parameter);
    if (!tracking || tracking.classesTesteed.size < 3) {
      return true;
    }

    const elapsedForParam = this.getElapsedForParameter(parameter);
    if (elapsedForParam < this.budget.perParameterBudgetMs) {
      return true;
    }

    return false;
  }

  private getElapsedForParameter(_parameter: string): number {
    return Date.now() - this.currentPhaseStart;
  }

  isWithinModuleBudget(): boolean {
    const elapsed = Date.now() - this.currentPhaseStart;
    return elapsed < this.budget.perModuleBudgetMs;
  }

  isWithinTotalBudget(): boolean {
    const elapsed = Date.now() - this.scanStartTime;
    return elapsed < this.budget.totalBudgetMs;
  }

  getRemainingModuleBudget(): number {
    const elapsed = Date.now() - this.currentPhaseStart;
    return Math.max(0, this.budget.perModuleBudgetMs - elapsed);
  }

  getRemainingTotalBudget(): number {
    const elapsed = Date.now() - this.scanStartTime;
    return Math.max(0, this.budget.totalBudgetMs - elapsed);
  }

  markParameterFullyTested(parameter: string): void {
    this.metrics.parametersFullyTested++;
    this.logCallback("debug", `[ExecutionControl] Parameter fully tested: ${parameter}`);
  }

  markParameterPartiallyTested(parameter: string): void {
    this.metrics.parametersPartiallyTested++;
    this.logCallback("debug", `[ExecutionControl] Parameter partially tested: ${parameter}`);
  }

  markParameterSkipped(parameter: string, reason: string): void {
    this.metrics.skippedDueToTime++;
    this.logCallback("debug", `[ExecutionControl] Parameter skipped: ${parameter} - ${reason}`);
  }

  evaluateCompleteness(): CompletenessResult {
    const totalScanTime = Date.now() - this.scanStartTime;
    const reasons: string[] = [];
    let isPartial = false;

    if (totalScanTime < 2 * 60 * 1000) {
      isPartial = true;
      reasons.push(`Scan completed in < 2 minutes (${Math.round(totalScanTime / 1000)}s)`);
    }

    const totalParams = this.metrics.parametersFullyTested + this.metrics.parametersPartiallyTested;
    if (totalParams > 0) {
      const fullyTestedRatio = this.metrics.parametersFullyTested / totalParams;
      if (fullyTestedRatio < 0.5) {
        isPartial = true;
        reasons.push(`< 50% of parameters fully tested (${Math.round(fullyTestedRatio * 100)}%)`);
      }
    }

    if (this.timedOutModules.length > 0) {
      isPartial = true;
      reasons.push(`Module(s) timed out: ${this.timedOutModules.join(", ")}`);
    }

    if (this.metrics.skippedDueToTime > 0) {
      reasons.push(`${this.metrics.skippedDueToTime} parameter(s) skipped due to time constraints`);
    }

    const percentage = this.calculateCompletenessPercentage();

    return {
      status: isPartial ? "partial" : "complete",
      reasons,
      percentage,
      timedOutModules: [...this.timedOutModules],
    };
  }

  private calculateCompletenessPercentage(): number {
    const totalParams = this.metrics.parametersFullyTested + this.metrics.parametersPartiallyTested + this.metrics.skippedDueToTime;
    
    if (totalParams === 0) {
      return this.timedOutModules.length === 0 ? 100 : 50;
    }

    const fullyTested = this.metrics.parametersFullyTested;
    const partiallyTested = this.metrics.parametersPartiallyTested * 0.5;
    
    const parameterScore = ((fullyTested + partiallyTested) / totalParams) * 100;

    const moduleDeduction = this.timedOutModules.length * 10;
    
    return Math.max(0, Math.min(100, Math.round(parameterScore - moduleDeduction)));
  }

  getMetricsSummary(): ExecutionMetricsSummary {
    const completeness = this.evaluateCompleteness();
    
    const totalParams = this.metrics.payloadsPerParameter.size;
    let totalPayloads = 0;
    this.metrics.payloadsPerParameter.forEach(count => {
      totalPayloads += count;
    });
    const avgPayloadsPerParam = totalParams > 0 ? totalPayloads / totalParams : 0;

    const timePerPhase: Record<string, number> = {};
    this.metrics.timePerPhase.forEach((time, phase) => {
      timePerPhase[phase] = time;
    });

    return {
      totalRequests: this.metrics.totalRequests,
      averagePayloadsPerParameter: Math.round(avgPayloadsPerParam * 10) / 10,
      timePerPhase,
      verificationRetryCount: this.metrics.verificationRetries,
      completenessPercentage: completeness.percentage,
      scanCompleteness: completeness.status,
      timedOutModules: completeness.timedOutModules,
      parametersFullyTested: this.metrics.parametersFullyTested,
      parametersPartiallyTested: this.metrics.parametersPartiallyTested,
      skippedDueToTime: this.metrics.skippedDueToTime,
    };
  }

  getDepthMetrics(): ScanDepthMetrics {
    return {
      ...this.metrics,
      payloadsPerParameter: new Map(this.metrics.payloadsPerParameter),
      timePerPhase: new Map(this.metrics.timePerPhase),
    };
  }

  setRequestDelay(delayMs: number): void {
    this.baseDelayMs = delayMs;
    this.requestDelayMs = delayMs;
    this.logCallback("debug", `[ExecutionControl] Request delay set to ${delayMs}ms`);
  }

  getCurrentDelay(): number {
    return this.requestDelayMs;
  }

  getBudget(): ScanBudget {
    return { ...this.budget };
  }

  getElapsedTime(): number {
    return Date.now() - this.scanStartTime;
  }

  setUrlsDiscovered(count: number): void {
    this.urlsDiscovered = count;
    this.updateActivity();
  }

  incrementUrlsTested(): void {
    this.urlsTested++;
    this.updateActivity();
  }

  setParametersDiscovered(count: number): void {
    this.parametersDiscovered = count;
    this.updateActivity();
  }

  incrementParametersTested(): void {
    this.parametersTested++;
    this.updateActivity();
  }

  setPayloadsDiscovered(count: number): void {
    this.payloadsDiscovered = count;
    this.updateActivity();
  }

  incrementPayloadsTested(): void {
    this.payloadsTested++;
    this.updateActivity();
  }

  // Heartbeat: Keep scan alive and prevent orphaning during long operations
  heartbeat(): void {
    this.updateActivity();
  }

  private updateActivity(): void {
    this.lastActivityTime = Date.now();
  }

  getCurrentPhase(): string {
    return this.currentPhase;
  }

  getProgressMetrics(): ProgressMetrics {
    // Calculate RPS from last 10 seconds of requests
    const now = Date.now();
    const tenSecondsAgo = now - 10000;
    const recentRequests = this.requestTimestamps.filter(t => t > tenSecondsAgo);
    const rps = recentRequests.length / 10;
    
    return {
      currentPhase: this.currentPhase,
      phaseDescription: PHASE_DESCRIPTIONS[this.currentPhase] || `Phase: ${this.currentPhase}`,
      payloadsDiscovered: this.payloadsDiscovered,
      payloadsTested: this.payloadsTested,
      payloadsRemaining: Math.max(0, this.payloadsDiscovered - this.payloadsTested),
      parametersDiscovered: this.parametersDiscovered,
      parametersTested: this.parametersTested,
      urlsDiscovered: this.urlsDiscovered,
      urlsTested: this.urlsTested,
      lastActivity: new Date(this.lastActivityTime).toISOString(),
      // War Room Metrics
      currentParameter: this.currentParameter,
      currentUrl: this.currentUrl,
      rps: Math.round(rps * 10) / 10,
      totalPayloadsInQueue: this.totalPayloadsInQueue,
      payloadsSent: this.payloadsTested,
      blocksEncountered: this.blocksEncountered,
      startTimestamp: this.scanStartTime,
      // Live Payload View (Elite Status)
      currentPayload: this.currentPayload,
      currentPayloadType: this.currentPayloadType,
      currentConfidence: this.currentConfidence,
      detectedDbType: this.detectedDbType,
      detectedContext: this.detectedContext,
      // Adaptive Testing Metrics
      adaptiveConcurrency: this.adaptiveConcurrency,
      parametersSkipped: this.parametersSkipped,
      coveragePerHour: this.coveragePerHour,
      estimatedTimeRemaining: this.estimatedTimeRemaining,
      workQueueSize: this.workQueueSize,
      successRate: this.successRate,
    };
  }
  
  // Adaptive Testing Setters
  setAdaptiveMetrics(metrics: {
    concurrency?: number;
    parametersSkipped?: number;
    coveragePerHour?: number;
    estimatedTimeRemaining?: number;
    workQueueSize?: number;
    successRate?: number;
  }): void {
    if (metrics.concurrency !== undefined) {
      // FIXED: Apply hard limit to prevent concurrency explosion
      this.adaptiveConcurrency = Math.min(metrics.concurrency, this.maxConcurrency);
    }
    if (metrics.parametersSkipped !== undefined) this.parametersSkipped = metrics.parametersSkipped;
    if (metrics.coveragePerHour !== undefined) this.coveragePerHour = metrics.coveragePerHour;
    if (metrics.estimatedTimeRemaining !== undefined) this.estimatedTimeRemaining = metrics.estimatedTimeRemaining;
    if (metrics.workQueueSize !== undefined) this.workQueueSize = metrics.workQueueSize;
    if (metrics.successRate !== undefined) this.successRate = metrics.successRate;
  }
  
  incrementParametersSkipped(): void {
    this.parametersSkipped++;
    this.updateActivity();
  }
  
  // War Room Methods
  setCurrentTarget(url: string, parameter: string): void {
    this.currentUrl = url;
    this.currentParameter = parameter;
    this.lastActivityTime = Date.now();
  }
  
  trackRequestForRPS(): void {
    const now = Date.now();
    this.requestTimestamps.push(now);
    // Keep only last 60 seconds of timestamps
    const oneMinuteAgo = now - 60000;
    this.requestTimestamps = this.requestTimestamps.filter(t => t > oneMinuteAgo);
    this.lastActivityTime = now;
  }
  
  setPayloadQueue(total: number): void {
    this.totalPayloadsInQueue = total;
    // Only set payloadsDiscovered if not already set (first call)
    if (this.payloadsDiscovered === 0) {
      this.payloadsDiscovered = total;
    }
  }
  
  setInitialPayloadCount(total: number): void {
    this.payloadsDiscovered = total;
    this.totalPayloadsInQueue = total;
  }
  
  recordBlock(): void {
    this.blocksEncountered++;
  }
  
  // Live Payload View Methods (Elite Status)
  setCurrentPayload(payload: string, payloadType: string, confidence: number): void {
    this.currentPayload = payload.length > 200 ? payload.substring(0, 200) + '...' : payload;
    this.currentPayloadType = payloadType;
    this.currentConfidence = confidence;
    this.lastActivityTime = Date.now();
  }
  
  setDetectedDbType(dbType: string): void {
    this.detectedDbType = dbType;
  }
  
  setDetectedContext(context: string): void {
    this.detectedContext = context;
  }
  
  getRPS(): number {
    const now = Date.now();
    const tenSecondsAgo = now - 10000;
    const recentRequests = this.requestTimestamps.filter(t => t > tenSecondsAgo);
    return recentRequests.length / 10;
  }

  getLastActivityTime(): number {
    return this.lastActivityTime;
  }

  isStalled(stallThresholdMs: number = 60000): boolean {
    return Date.now() - this.lastActivityTime > stallThresholdMs;
  }

  // Work unit tracking methods
  setRequiredPhases(phases: string[]): void {
    this.requiredPhases = phases;
    this.logCallback("debug", `[ExecutionControl] Required phases: ${phases.join(", ")}`);
  }

  markCrawlComplete(): void {
    this.workUnitStatus.crawlComplete = true;
    this.completedPhases.add("crawling");
    this.logCallback("info", `[WorkUnit] Crawl phase COMPLETE`);
  }

  markBaselineEstablished(): void {
    this.workUnitStatus.baselineEstablished = true;
    this.completedPhases.add("baseline_profiling");
    this.logCallback("info", `[WorkUnit] Baseline establishment COMPLETE`);
  }

  markVerificationComplete(): void {
    this.workUnitStatus.verificationComplete = true;
    this.completedPhases.add("final_verification");
    this.logCallback("info", `[WorkUnit] Verification phase COMPLETE`);
  }

  markPayloadQueuesExhausted(): void {
    this.workUnitStatus.payloadQueuesExhausted = true;
    this.logCallback("info", `[WorkUnit] Payload queues EXHAUSTED`);
  }

  markPhaseComplete(phase: string): void {
    this.completedPhases.add(phase);
    this.logCallback("debug", `[WorkUnit] Phase complete: ${phase}`);
    
    // Check if all required phases are done
    const allPhasesComplete = this.requiredPhases.every(p => this.completedPhases.has(p));
    if (allPhasesComplete) {
      this.workUnitStatus.allPhasesComplete = true;
      this.logCallback("info", `[WorkUnit] All required phases COMPLETE`);
    }
  }

  getWorkUnitStatus(): WorkUnitStatus {
    return { ...this.workUnitStatus };
  }

  // CRITICAL: Validates if scan can complete - returns false if work is incomplete
  validateScanCompletion(): ScanValidationResult {
    const elapsedMs = Date.now() - this.scanStartTime;
    const reasons: string[] = [];
    let valid = true;

    // Check 1: Minimum scan duration (2 minutes)
    if (elapsedMs < REQUIRED_WORK.minimumScanDurationMs) {
      valid = false;
      reasons.push(`Scan completed too fast (${Math.round(elapsedMs / 1000)}s < ${REQUIRED_WORK.minimumScanDurationMs / 1000}s minimum)`);
    }

    // Check 2: Minimum total requests
    if (this.metrics.totalRequests < REQUIRED_WORK.minimumTotalRequests) {
      valid = false;
      reasons.push(`Insufficient requests (${this.metrics.totalRequests} < ${REQUIRED_WORK.minimumTotalRequests} minimum)`);
    }

    // Check 3: Crawl must be complete
    if (REQUIRED_WORK.requireCrawlComplete && !this.workUnitStatus.crawlComplete) {
      valid = false;
      reasons.push("Crawl phase did not complete");
    }

    // Check 4: Baseline must be established (if parameters were discovered)
    if (REQUIRED_WORK.requireBaselineEstablished && this.parametersDiscovered > 0 && !this.workUnitStatus.baselineEstablished) {
      valid = false;
      reasons.push("Baseline responses not established");
    }

    // Check 5: Payload queues must be exhausted
    const payloadsRemaining = this.payloadsDiscovered - this.payloadsTested;
    if (payloadsRemaining > 0 && !this.workUnitStatus.payloadQueuesExhausted) {
      valid = false;
      reasons.push(`Payload queue not exhausted (${payloadsRemaining} remaining)`);
    }

    // Check 6: All required phases must complete
    if (this.requiredPhases.length > 0 && !this.workUnitStatus.allPhasesComplete) {
      const missingPhases = this.requiredPhases.filter(p => !this.completedPhases.has(p));
      if (missingPhases.length > 0) {
        valid = false;
        reasons.push(`Phases not completed: ${missingPhases.join(", ")}`);
      }
    }

    // Check 7: Parameters must be adequately tested
    if (this.parametersDiscovered > 0) {
      const testedRatio = this.parametersTested / this.parametersDiscovered;
      if (testedRatio < 0.8) {
        valid = false;
        reasons.push(`Only ${Math.round(testedRatio * 100)}% of parameters tested`);
      }
    }

    const result: ScanValidationResult = {
      valid,
      reasons,
      workUnitStatus: { ...this.workUnitStatus },
      elapsedMs,
      totalRequests: this.metrics.totalRequests,
    };

    if (!valid) {
      this.logCallback("warn", `[WorkUnit] SCAN INVALID: ${reasons.join("; ")}`);
    } else {
      this.logCallback("info", `[WorkUnit] Scan validation PASSED`);
    }

    return result;
  }

  // Force mark scan as having minimum requirements met (for testing/override)
  forceMinimumRequirementsMet(): void {
    this.workUnitStatus.crawlComplete = true;
    this.workUnitStatus.baselineEstablished = true;
    this.workUnitStatus.verificationComplete = true;
    this.workUnitStatus.payloadQueuesExhausted = true;
    this.workUnitStatus.allPhasesComplete = true;
  }
}
