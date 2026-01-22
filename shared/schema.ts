import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const scanModes = ["sqli"] as const;
export type ScanMode = typeof scanModes[number];

export const verificationStatuses = ["confirmed", "potential", "not_applicable"] as const;
export type VerificationStatus = typeof verificationStatuses[number];

export const scanPhases = [
  "initialization",
  "crawling",
  "parameter_discovery",
  "baseline_profiling",
  "error_based_sql",
  "boolean_based_sql", 
  "time_based_sql",
  "union_based_sql",
  "second_order_sql",
  "final_verification",
  "completed"
] as const;
export type ScanPhase = typeof scanPhases[number];

export const scans = pgTable("scans", {
  id: serial("id").primaryKey(),
  targetUrl: text("target_url").notNull(),
  scanMode: text("scan_mode").notNull().default("sqli"), // sqli only
  threads: integer("threads").notNull().default(10), // concurrent threads 1-50
  status: text("status").notNull().default("pending"), // pending, scanning, completed, failed, batch_parent
  progress: integer("progress").default(0),
  startTime: timestamp("start_time").defaultNow(),
  endTime: timestamp("end_time"),
  parentScanId: integer("parent_scan_id"),
  isParent: boolean("is_parent").default(false),
  completionReason: text("completion_reason"), // Why the scan ended: completed, cancelled, timeout, blocked, error
  progressMetrics: jsonb("progress_metrics").$type<{
    currentPhase: ScanPhase;
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
    successRate?: number;
    parametersSkipped?: number;
    coveragePerHour?: number;
    workQueueSize?: number;
  }>(),
  crawlStats: jsonb("crawl_stats").$type<{
    urlsDiscovered: number;
    formsFound: number;
    parametersFound: number;
    apiEndpoints: number;
  }>(),
  techStack: jsonb("tech_stack").$type<{
    server?: string;
    language?: string;
    framework?: string;
    cms?: string;
  }>(),
  summary: jsonb("summary").$type<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    confirmed: number;
    potential: number;
    attackChains?: number;
  }>(),
  attackChains: jsonb("attack_chains").$type<Array<{
    id: string;
    name: string;
    description: string;
    overallSeverity: "Critical" | "High" | "Medium";
    exploitability: "Easy" | "Moderate" | "Complex";
    impact: string;
    attackFlow: string;
    links: Array<{
      vulnId: number;
      vulnType: string;
      severity: string;
      description: string;
      order: number;
    }>;
  }>>(),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").references(() => scans.id).notNull(),
  type: text("type").notNull(), // SQLi, XSS, etc.
  severity: text("severity").notNull(), // Critical, High, Medium, Low, Info
  verificationStatus: text("verification_status").notNull().default("potential"), // confirmed, potential, not_applicable
  confidence: integer("confidence").default(50), // 0-100 confidence score
  url: text("url").notNull(),
  path: text("path"),
  parameter: text("parameter"),
  payload: text("payload"),
  evidence: text("evidence"), // Response snippet or proof
  verificationDetails: text("verification_details"), // Explains WHY the finding is confirmed/potential
  description: text("description"),
  remediation: text("remediation"),
  timestamp: timestamp("timestamp").defaultNow(),
});

export const scanLogs = pgTable("scan_logs", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").references(() => scans.id).notNull(),
  level: text("level").notNull(), // info, warn, error, success
  message: text("message").notNull(),
  timestamp: timestamp("timestamp").defaultNow(),
});

export const trafficLogs = pgTable("traffic_logs", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").references(() => scans.id).notNull(),
  requestUrl: text("request_url").notNull(),
  requestMethod: text("request_method").notNull().default("GET"),
  requestHeaders: jsonb("request_headers").$type<Record<string, string>>(),
  requestPayload: text("request_payload"),
  parameterName: text("parameter_name"),
  payloadType: text("payload_type"),
  encodingUsed: text("encoding_used"),
  responseStatus: integer("response_status"),
  responseTime: integer("response_time"),
  responseSize: integer("response_size"),
  responseSnippet: text("response_snippet"),
  detectionResult: text("detection_result"),
  confidenceScore: integer("confidence_score"),
  timestamp: timestamp("timestamp").defaultNow(),
});

export const insertScanSchema = createInsertSchema(scans).pick({
  targetUrl: true,
  scanMode: true,
  threads: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).omit({
  id: true,
  timestamp: true,
});

export const insertScanLogSchema = createInsertSchema(scanLogs).omit({
  id: true,
  timestamp: true,
});

export const insertTrafficLogSchema = createInsertSchema(trafficLogs).omit({
  id: true,
  timestamp: true,
});

// ============================================================
// DATA DUMPING ENGINE - SQLi Dumper Feature
// ============================================================

// Extracted Databases from vulnerable targets
export const extractedDatabases = pgTable("extracted_databases", {
  id: serial("id").primaryKey(),
  vulnerabilityId: integer("vulnerability_id").references(() => vulnerabilities.id).notNull(),
  scanId: integer("scan_id").references(() => scans.id).notNull(),
  targetUrl: text("target_url").notNull(),
  databaseName: text("database_name").notNull(),
  dbType: text("db_type").notNull(), // mysql, postgresql, mssql, oracle, sqlite
  extractionMethod: text("extraction_method").notNull(), // error-based, union-based, boolean-based, time-based
  tableCount: integer("table_count").default(0),
  status: text("status").notNull().default("discovered"), // discovered, dumping, completed, failed
  extractedAt: timestamp("extracted_at").defaultNow(),
  metadata: jsonb("metadata").$type<{
    version?: string;
    user?: string;
    currentDb?: string;
    serverInfo?: string;
    privileges?: string[];
  }>(),
});

// Extracted Tables from databases
export const extractedTables = pgTable("extracted_tables", {
  id: serial("id").primaryKey(),
  databaseId: integer("database_id").references(() => extractedDatabases.id).notNull(),
  tableName: text("table_name").notNull(),
  rowCount: integer("row_count").default(0),
  columnCount: integer("column_count").default(0),
  status: text("status").notNull().default("discovered"), // discovered, dumping, completed, failed
  extractedAt: timestamp("extracted_at").defaultNow(),
});

// Extracted Columns from tables
export const extractedColumns = pgTable("extracted_columns", {
  id: serial("id").primaryKey(),
  tableId: integer("table_id").references(() => extractedTables.id).notNull(),
  columnName: text("column_name").notNull(),
  dataType: text("data_type"),
  isNullable: boolean("is_nullable"),
  columnKey: text("column_key"), // PRI, UNI, MUL, etc.
  columnDefault: text("column_default"),
  extra: text("extra"), // auto_increment, etc.
  extractedAt: timestamp("extracted_at").defaultNow(),
});

// Extracted Data (actual rows)
export const extractedData = pgTable("extracted_data", {
  id: serial("id").primaryKey(),
  tableId: integer("table_id").references(() => extractedTables.id).notNull(),
  rowIndex: integer("row_index").notNull(),
  rowData: jsonb("row_data").$type<Record<string, any>>().notNull(), // { column1: value1, column2: value2 }
  extractedAt: timestamp("extracted_at").defaultNow(),
});

// Dumping Jobs - Track progress of data extraction
export const dumpingJobs = pgTable("dumping_jobs", {
  id: serial("id").primaryKey(),
  vulnerabilityId: integer("vulnerability_id").references(() => vulnerabilities.id).notNull(),
  scanId: integer("scan_id").references(() => scans.id).notNull(),
  targetUrl: text("target_url").notNull(),
  targetType: text("target_type").notNull(), // database, table, column
  targetId: integer("target_id").notNull(), // ID of database/table/column
  status: text("status").notNull().default("pending"), // pending, running, completed, failed, paused
  progress: integer("progress").default(0), // 0-100
  itemsTotal: integer("items_total").default(0),
  itemsExtracted: integer("items_extracted").default(0),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  errorMessage: text("error_message"),
  extractionMetrics: jsonb("extraction_metrics").$type<{
    requestsSent: number;
    avgResponseTime: number;
    blocksEncountered: number;
    retriesPerformed: number;
    technique: string;
    concurrency: number;
  }>(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertExtractedDatabaseSchema = createInsertSchema(extractedDatabases).omit({
  id: true,
  extractedAt: true,
});

export const insertExtractedTableSchema = createInsertSchema(extractedTables).omit({
  id: true,
  extractedAt: true,
});

export const insertExtractedColumnSchema = createInsertSchema(extractedColumns).omit({
  id: true,
  extractedAt: true,
});

export const insertExtractedDataSchema = createInsertSchema(extractedData).omit({
  id: true,
  extractedAt: true,
});

export const insertDumpingJobSchema = createInsertSchema(dumpingJobs).omit({
  id: true,
  createdAt: true,
});

export type Scan = typeof scans.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;
export type ScanLog = typeof scanLogs.$inferSelect;
export type InsertScanLog = z.infer<typeof insertScanLogSchema>;
export type TrafficLog = typeof trafficLogs.$inferSelect;
export type InsertTrafficLog = z.infer<typeof insertTrafficLogSchema>;

// Data Dumping Types
export type ExtractedDatabase = typeof extractedDatabases.$inferSelect;
export type InsertExtractedDatabase = z.infer<typeof insertExtractedDatabaseSchema>;
export type ExtractedTable = typeof extractedTables.$inferSelect;
export type InsertExtractedTable = z.infer<typeof insertExtractedTableSchema>;
export type ExtractedColumn = typeof extractedColumns.$inferSelect;
export type InsertExtractedColumn = z.infer<typeof insertExtractedColumnSchema>;
export type ExtractedData = typeof extractedData.$inferSelect;
export type InsertExtractedData = z.infer<typeof insertExtractedDataSchema>;
export type DumpingJob = typeof dumpingJobs.$inferSelect;
export type InsertDumpingJob = z.infer<typeof insertDumpingJobSchema>;
