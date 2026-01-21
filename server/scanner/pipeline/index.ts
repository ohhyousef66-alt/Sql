/**
 * SQL Injection Scanning Pipeline - Main Exports
 * 
 * Professional staged pipeline for SQL injection testing with:
 * - Strict stage gates
 * - Confirmation requirements
 * - Database fingerprinting
 * - Opt-in enumeration
 * - Safety controls
 * - Resumable operations
 * - Adaptive pacing
 * - Audit trails
 */

// Core types
export * from "./types";

// Pipeline components
export { ConfirmationGate } from "./confirmation-gate";
export type { ConfirmationGateConfig, ConfirmationDecision } from "./confirmation-gate";

export { DatabaseFingerprinter } from "./database-fingerprinter";

export { CheckpointManager, InMemoryCheckpointStorage } from "./checkpoint-manager";
export type { CheckpointStorage } from "./checkpoint-manager";

export { EnumerationEngine } from "./enumeration-engine";
export type { EnumerationResult } from "./enumeration-engine";

export { AdaptivePacer } from "./adaptive-pacer";
export type { PacingConfig } from "./adaptive-pacer";

export { ResponseAnalyzer } from "./response-analyzer";
export type {
  NormalizedResponse,
  ComparisonResult,
} from "./response-analyzer";

export { SafetyControlsManager } from "./safety-controls";
export type {
  UserConsent,
  AuditAction,
  SafetyDecision,
} from "./safety-controls";

export { PipelineController } from "./pipeline-controller";
export type {
  PipelineConfig,
  PipelineEventType,
  PipelineEvent,
} from "./pipeline-controller";
