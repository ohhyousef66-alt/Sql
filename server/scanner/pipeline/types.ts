/**
 * SQL Injection Scanning Pipeline - Type Definitions
 * 
 * This file defines the core types for the staged pipeline architecture.
 * Each stage must complete successfully before the next stage can execute.
 */

/**
 * Pipeline stages executed in strict order
 */
export enum ScanStage {
  TARGET_NORMALIZATION = "target_normalization",
  PARAMETER_DISCOVERY = "parameter_discovery",
  VULNERABILITY_CONFIRMATION = "vulnerability_confirmation",
  DATABASE_FINGERPRINTING = "database_fingerprinting",
  POST_CONFIRMATION_ENUMERATION = "post_confirmation_enumeration",
  REPORTING = "reporting",
}

/**
 * Stage execution status
 */
export enum StageStatus {
  PENDING = "pending",
  IN_PROGRESS = "in_progress",
  COMPLETED = "completed",
  FAILED = "failed",
  BLOCKED = "blocked",
}

/**
 * Confidence level for vulnerability confirmation
 */
export enum ConfidenceLevel {
  NONE = 0,
  LOW = 25,
  MEDIUM = 50,
  HIGH = 75,
  CONFIRMED = 100,
}

/**
 * Supported database types
 */
export enum DatabaseType {
  UNKNOWN = "unknown",
  MYSQL = "mysql",
  POSTGRESQL = "postgresql",
  MSSQL = "mssql",
  ORACLE = "oracle",
  SQLITE = "sqlite",
}

/**
 * Injection technique types
 */
export enum InjectionTechnique {
  UNION_BASED = "union_based",
  ERROR_BASED = "error_based",
  BOOLEAN_BASED = "boolean_based",
  TIME_BASED = "time_based",
  STACKED_QUERIES = "stacked_queries",
}

/**
 * Enumeration phase within post-confirmation stage
 */
export enum EnumerationPhase {
  DATABASES = "databases",
  TABLES = "tables",
  COLUMNS = "columns",
  DATA_PREVIEW = "data_preview",
}

/**
 * Normalized target information
 */
export interface NormalizedTarget {
  originalUrl: string;
  normalizedUrl: string;
  protocol: string;
  host: string;
  port: number;
  path: string;
  queryParams: Map<string, string>;
  fragmentParams: Map<string, string>;
  method: string;
  headers: Record<string, string>;
  body?: string;
  cookies?: Record<string, string>;
}

/**
 * Discovered parameter metadata
 */
export interface ParameterMetadata {
  name: string;
  location: "query" | "path" | "header" | "cookie" | "body";
  originalValue: string;
  type: "string" | "numeric" | "boolean" | "array";
  injectable: boolean;
  requiredForFunctionality: boolean;
}

/**
 * Confirmation signal from vulnerability testing
 */
export interface ConfirmationSignal {
  technique: InjectionTechnique;
  payload: string;
  responseTimeMs: number;
  evidenceType: "error_message" | "union_data" | "boolean_behavior" | "time_delay" | "structural_change";
  evidence: string;
  confidence: ConfidenceLevel;
  timestamp: Date;
}

/**
 * Database fingerprint result
 */
export interface DatabaseFingerprint {
  type: DatabaseType;
  version?: string;
  confidence: ConfidenceLevel;
  detectionMethod: string;
  capabilities: {
    supportsUnion: boolean;
    supportsErrorBased: boolean;
    supportsTimeBased: boolean;
    supportsStackedQueries: boolean;
    supportsInformationSchema: boolean;
  };
  metadata: Record<string, any>;
}

/**
 * Checkpoint for resumable operations
 */
export interface EnumerationCheckpoint {
  phase: EnumerationPhase;
  currentDatabase?: string;
  currentTable?: string;
  completedDatabases: string[];
  completedTables: string[];
  completedColumns: string[];
  lastSuccessfulQuery?: string;
  retryCount: number;
  timestamp: Date;
}

/**
 * Stage output with state
 */
export interface StageOutput<T = any> {
  stage: ScanStage;
  status: StageStatus;
  data: T;
  confidence: ConfidenceLevel;
  errors: string[];
  warnings: string[];
  startTime: Date;
  endTime?: Date;
  metadata: Record<string, any>;
}

/**
 * Complete pipeline state (immutable snapshots)
 */
export interface PipelineState {
  scanId: string;
  targetUrl: string;
  currentStage: ScanStage;
  stages: Map<ScanStage, StageOutput>;
  checkpoint?: EnumerationCheckpoint;
  createdAt: Date;
  updatedAt: Date;
  version: number; // For state versioning
}

/**
 * Enumeration configuration (opt-in)
 */
export interface EnumerationConfig {
  enabled: boolean; // MUST BE FALSE BY DEFAULT
  schemaOnly: boolean; // Default TRUE
  databasesEnabled: boolean;
  tablesEnabled: boolean;
  columnsEnabled: boolean;
  dataPreviewEnabled: boolean; // MUST BE FALSE BY DEFAULT
  maxDatabases: number;
  maxTablesPerDatabase: number;
  maxColumnsPerTable: number;
  maxRowsPreview: number;
  maxFieldsPreview: number;
  requestDelayMs: number;
  maxRetries: number;
  timeoutMs: number;
}

/**
 * Adaptive pacing metrics
 */
export interface PacingMetrics {
  averageLatencyMs: number;
  errorRate: number;
  responseVariance: number;
  consecutiveErrors: number;
  consecutiveTimeouts: number;
  suggestedDelayMs: number;
  shouldThrottle: boolean;
  shouldPause: boolean;
}

/**
 * Progress tracking (real units, not percentages)
 */
export interface RealProgress {
  currentStage: ScanStage;
  currentPhase?: EnumerationPhase;
  completedWorkUnits: number;
  totalWorkUnits: number;
  remainingWorkUnits: number;
  estimatedOperationsRemaining: number;
  lastActivity: string;
  activeOperations: string[];
}

/**
 * Safety controls and audit
 */
export interface SafetyAudit {
  scanId: string;
  targetUrl: string;
  userConsent: {
    enumerationEnabled: boolean;
    dataPreviewEnabled: boolean;
    acknowledgedLegalWarnings: boolean;
    timestamp: Date;
  };
  actions: Array<{
    action: string;
    stage: ScanStage;
    phase?: EnumerationPhase;
    timestamp: Date;
    metadata: Record<string, any>;
  }>;
}
