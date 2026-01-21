/**
 * Event-Driven SQLi Context
 * 
 * CRITICAL: This immutable context object is created IMMEDIATELY upon SQLi confirmation
 * and is passed through all exploitation phases (fingerprint → enumerate → dump).
 * 
 * The SAME working payload must be reused across all phases.
 */

import { DatabaseType } from "./modules/sqli";

/**
 * SQL Injection Technique Types
 */
export type SQLiTechnique = 
  | "error-based"
  | "union-based"
  | "boolean-blind"
  | "time-blind"
  | "stacked-queries";

/**
 * Immutable SQLi Context created upon confirmation
 * This single object drives all exploitation phases
 */
export interface SQLiContext {
  // Target identification
  readonly url: string;
  readonly parameter: string;
  readonly method: "GET" | "POST";
  
  // Injection details
  readonly injectionType: SQLiTechnique;
  readonly workingPayload: string;  // ⚡ MUST be reused for ALL exploitation
  readonly confirmedTechnique: string;  // Detailed technique description
  
  // Database fingerprint
  readonly dbFingerprint: {
    type: DatabaseType;
    version?: string;
    detected: boolean;
  };
  
  // Confidence metrics
  readonly confidence: number;  // 0-100
  readonly confirmationCount: number;  // How many times confirmed
  
  // Context metadata
  readonly baseline: {
    responseTime: number;
    bodyHash: string;
    status: number;
  };
  
  // Session context (if applicable)
  readonly sessionCookies?: Record<string, string>;
  readonly headers?: Record<string, string>;
  
  // Timestamps
  readonly detectedAt: number;  // When first signal detected
  readonly confirmedAt: number;  // When confirmation completed
  
  // Exploitation state
  readonly exploitationStarted: boolean;
  readonly enumerationCompleted: boolean;
}

/**
 * Create immutable SQLi context after confirmation
 */
export function createSQLiContext(params: {
  url: string;
  parameter: string;
  method?: "GET" | "POST";
  injectionType: SQLiTechnique;
  workingPayload: string;
  confirmedTechnique: string;
  dbType: DatabaseType;
  dbVersion?: string;
  confidence: number;
  confirmationCount: number;
  baseline: {
    responseTime: number;
    bodyHash: string;
    status: number;
  };
  sessionCookies?: Record<string, string>;
  headers?: Record<string, string>;
  detectedAt?: number;
}): SQLiContext {
  return {
    url: params.url,
    parameter: params.parameter,
    method: params.method || "GET",
    injectionType: params.injectionType,
    workingPayload: params.workingPayload,
    confirmedTechnique: params.confirmedTechnique,
    dbFingerprint: {
      type: params.dbType,
      version: params.dbVersion,
      detected: params.dbType !== "unknown",
    },
    confidence: params.confidence,
    confirmationCount: params.confirmationCount,
    baseline: params.baseline,
    sessionCookies: params.sessionCookies,
    headers: params.headers,
    detectedAt: params.detectedAt || Date.now(),
    confirmedAt: Date.now(),
    exploitationStarted: false,
    enumerationCompleted: false,
  };
}

/**
 * Signal Detection Event
 * Emitted when first SQL signal is detected (before confirmation)
 */
export interface SQLSignalEvent {
  readonly url: string;
  readonly parameter: string;
  readonly payload: string;
  readonly technique: SQLiTechnique;
  readonly evidence: string;
  readonly detectedAt: number;
  readonly shouldConfirm: boolean;  // If true, trigger confirmation gate
}

/**
 * Confirmation Complete Event
 * Emitted when confirmation gate passes
 */
export interface ConfirmationCompleteEvent {
  readonly context: SQLiContext;
  readonly shouldExploit: boolean;  // If true, trigger immediate exploitation
}

/**
 * Event-Driven SQLi Detection State
 * Tracks per-parameter execution context
 */
export interface ParameterExecutionContext {
  readonly url: string;
  readonly parameter: string;
  
  // State flags
  signalDetected: boolean;
  confirmationRunning: boolean;
  confirmed: boolean;
  exploitationRunning: boolean;
  completed: boolean;
  
  // Detection data
  firstSignal?: SQLSignalEvent;
  confirmedContext?: SQLiContext;
  
  // Control flags
  shouldStopFuzzing: boolean;  // Set to true when signal detected
  payloadsSent: number;
  confirmationAttempts: number;
  
  // Timestamps
  startedAt: number;
  signalDetectedAt?: number;
  confirmedAt?: number;
  completedAt?: number;
}

/**
 * Create parameter execution context
 */
export function createParameterContext(
  url: string,
  parameter: string
): ParameterExecutionContext {
  return {
    url,
    parameter,
    signalDetected: false,
    confirmationRunning: false,
    confirmed: false,
    exploitationRunning: false,
    completed: false,
    shouldStopFuzzing: false,
    payloadsSent: 0,
    confirmationAttempts: 0,
    startedAt: Date.now(),
  };
}
