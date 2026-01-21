/**
 * Post-Confirmation Enumeration Engine
 * 
 * OPT-IN ONLY enumeration with schema-first approach.
 * Implements rate limiting, retry logic, and resumable operations.
 * 
 * IMPORTANT: This is methodology-based, NOT copied from any closed-source tool.
 */

import {
  DatabaseType,
  EnumerationPhase,
  EnumerationConfig,
  DatabaseFingerprint,
} from "./types";
import { CheckpointManager } from "./checkpoint-manager";

/**
 * Enumeration result for a single query
 */
export interface EnumerationResult {
  phase: EnumerationPhase;
  data: string[];
  query: string;
  success: boolean;
  error?: string;
  retryCount: number;
}

/**
 * Rate limiter for controlling request pace
 */
class RateLimiter {
  private lastRequestTime = 0;
  private delayMs: number;

  constructor(delayMs: number) {
    this.delayMs = delayMs;
  }

  async wait(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;

    if (timeSinceLastRequest < this.delayMs) {
      const waitTime = this.delayMs - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    this.lastRequestTime = Date.now();
  }

  setDelay(delayMs: number): void {
    this.delayMs = delayMs;
  }

  getDelay(): number {
    return this.delayMs;
  }
}

/**
 * Post-Confirmation Enumeration Engine
 */
export class EnumerationEngine {
  private config: EnumerationConfig;
  private dbType: DatabaseType;
  private checkpointManager: CheckpointManager;
  private rateLimiter: RateLimiter;
  private executor: (query: string) => Promise<string[] | null>;

  constructor(
    config: EnumerationConfig,
    fingerprint: DatabaseFingerprint,
    checkpointManager: CheckpointManager,
    executor: (query: string) => Promise<string[] | null>
  ) {
    // CRITICAL: Verify enumeration is explicitly enabled
    if (!config.enabled) {
      throw new Error(
        "Enumeration is disabled. User must explicitly opt-in."
      );
    }

    this.config = config;
    this.dbType = fingerprint.type;
    this.checkpointManager = checkpointManager;
    this.executor = executor;
    this.rateLimiter = new RateLimiter(config.requestDelayMs);
  }

  /**
   * Enumerate databases
   */
  async enumerateDatabases(): Promise<EnumerationResult> {
    if (!this.config.databasesEnabled) {
      return {
        phase: EnumerationPhase.DATABASES,
        data: [],
        query: "",
        success: false,
        error: "Database enumeration not enabled",
        retryCount: 0,
      };
    }

    await this.checkpointManager.initialize(
      "scan_id",
      EnumerationPhase.DATABASES
    );

    const query = this.buildDatabaseQuery();
    const result = await this.executeWithRetry(
      query,
      EnumerationPhase.DATABASES
    );

    // Apply limit
    if (result.success && result.data.length > this.config.maxDatabases) {
      result.data = result.data.slice(0, this.config.maxDatabases);
    }

    return result;
  }

  /**
   * Enumerate tables in a database
   */
  async enumerateTables(database: string): Promise<EnumerationResult> {
    if (!this.config.tablesEnabled) {
      return {
        phase: EnumerationPhase.TABLES,
        data: [],
        query: "",
        success: false,
        error: "Table enumeration not enabled",
        retryCount: 0,
      };
    }

    // Skip if already completed (resume support)
    if (this.checkpointManager.isDatabaseCompleted(database)) {
      console.log(`⏭️  Skipping completed database: ${database}`);
      return {
        phase: EnumerationPhase.TABLES,
        data: [],
        query: "",
        success: true,
        retryCount: 0,
      };
    }

    const query = this.buildTablesQuery(database);
    const result = await this.executeWithRetry(query, EnumerationPhase.TABLES);

    // Apply limit
    if (result.success && result.data.length > this.config.maxTablesPerDatabase) {
      result.data = result.data.slice(0, this.config.maxTablesPerDatabase);
    }

    // Mark database as completed
    if (result.success) {
      this.checkpointManager.markDatabaseCompleted(database);
      await this.checkpointManager.save();
    }

    return result;
  }

  /**
   * Enumerate columns in a table
   */
  async enumerateColumns(
    database: string,
    table: string
  ): Promise<EnumerationResult> {
    if (!this.config.columnsEnabled) {
      return {
        phase: EnumerationPhase.COLUMNS,
        data: [],
        query: "",
        success: false,
        error: "Column enumeration not enabled",
        retryCount: 0,
      };
    }

    // Skip if already completed
    const tableKey = `${database}.${table}`;
    if (this.checkpointManager.isTableCompleted(tableKey)) {
      console.log(`⏭️  Skipping completed table: ${tableKey}`);
      return {
        phase: EnumerationPhase.COLUMNS,
        data: [],
        query: "",
        success: true,
        retryCount: 0,
      };
    }

    const query = this.buildColumnsQuery(database, table);
    const result = await this.executeWithRetry(query, EnumerationPhase.COLUMNS);

    // Apply limit
    if (result.success && result.data.length > this.config.maxColumnsPerTable) {
      result.data = result.data.slice(0, this.config.maxColumnsPerTable);
    }

    // Mark table as completed
    if (result.success) {
      this.checkpointManager.markTableCompleted(tableKey);
      await this.checkpointManager.save();
    }

    return result;
  }

  /**
   * Data preview (RESTRICTED - requires explicit opt-in)
   */
  async previewData(
    database: string,
    table: string,
    columns: string[]
  ): Promise<EnumerationResult> {
    // CRITICAL: Double-check data preview is enabled
    if (!this.config.dataPreviewEnabled) {
      throw new Error(
        "Data preview is disabled. User must explicitly opt-in with legal acknowledgment."
      );
    }

    // Apply column limit
    const limitedColumns = columns.slice(0, this.config.maxFieldsPreview);

    const query = this.buildDataPreviewQuery(
      database,
      table,
      limitedColumns,
      this.config.maxRowsPreview
    );

    const result = await this.executeWithRetry(
      query,
      EnumerationPhase.DATA_PREVIEW
    );

    return result;
  }

  /**
   * Execute query with retry logic and exponential backoff
   */
  private async executeWithRetry(
    query: string,
    phase: EnumerationPhase
  ): Promise<EnumerationResult> {
    let retryCount = 0;
    let lastError: string | undefined;

    while (retryCount <= this.config.maxRetries) {
      try {
        // Rate limiting
        await this.rateLimiter.wait();

        // Execute with timeout
        const data = await this.executeWithTimeout(query);

        if (data && data.length > 0) {
          // Success - reset retry count in checkpoint
          this.checkpointManager.resetRetry();

          return {
            phase,
            data,
            query,
            success: true,
            retryCount,
          };
        } else {
          lastError = "Empty result";
        }
      } catch (error: any) {
        lastError = error.message || String(error);
        console.warn(
          `⚠️  Retry ${retryCount + 1}/${this.config.maxRetries}: ${lastError}`
        );
      }

      // Increment retry
      retryCount++;
      this.checkpointManager.incrementRetry();

      // Exponential backoff
      if (retryCount <= this.config.maxRetries) {
        const backoffMs = Math.min(1000 * Math.pow(2, retryCount), 30000);
        await new Promise(resolve => setTimeout(resolve, backoffMs));
      }
    }

    // All retries failed
    return {
      phase,
      data: [],
      query,
      success: false,
      error: lastError || "Unknown error",
      retryCount,
    };
  }

  /**
   * Execute query with timeout
   */
  private async executeWithTimeout(
    query: string
  ): Promise<string[] | null> {
    return Promise.race([
      this.executor(query),
      new Promise<null>((_, reject) =>
        setTimeout(
          () => reject(new Error("Query timeout")),
          this.config.timeoutMs
        )
      ),
    ]);
  }

  /**
   * Build database enumeration query based on DB type
   */
  private buildDatabaseQuery(): string {
    switch (this.dbType) {
      case DatabaseType.MYSQL:
        return "SELECT schema_name FROM information_schema.schemata";

      case DatabaseType.POSTGRESQL:
        return "SELECT datname FROM pg_database WHERE datistemplate = false";

      case DatabaseType.MSSQL:
        return "SELECT name FROM sys.databases";

      case DatabaseType.ORACLE:
        return "SELECT DISTINCT owner FROM all_tables";

      case DatabaseType.SQLITE:
        return "SELECT name FROM sqlite_master WHERE type='table'";

      default:
        throw new Error(`Unsupported database type: ${this.dbType}`);
    }
  }

  /**
   * Build tables enumeration query
   */
  private buildTablesQuery(database: string): string {
    // Escape single quotes to prevent SQL injection
    const escapedDb = database.replace(/'/g, "''");
    
    switch (this.dbType) {
      case DatabaseType.MYSQL:
        return `SELECT table_name FROM information_schema.tables WHERE table_schema='${escapedDb}'`;

      case DatabaseType.POSTGRESQL:
        return `SELECT tablename FROM pg_tables WHERE schemaname='${escapedDb}'`;

      case DatabaseType.MSSQL:
        // For MSSQL, use QUOTENAME for proper escaping
        return `SELECT name FROM [${database.replace(/]/g, "]]")}].sys.tables`;

      case DatabaseType.ORACLE:
        return `SELECT table_name FROM all_tables WHERE owner='${escapedDb}'`;

      case DatabaseType.SQLITE:
        return `SELECT name FROM sqlite_master WHERE type='table'`;

      default:
        throw new Error(`Unsupported database type: ${this.dbType}`);
    }
  }

  /**
   * Build columns enumeration query
   */
  private buildColumnsQuery(database: string, table: string): string {
    // Escape single quotes to prevent SQL injection
    const escapedDb = database.replace(/'/g, "''");
    const escapedTable = table.replace(/'/g, "''");
    
    switch (this.dbType) {
      case DatabaseType.MYSQL:
        return `SELECT column_name FROM information_schema.columns WHERE table_schema='${escapedDb}' AND table_name='${escapedTable}'`;

      case DatabaseType.POSTGRESQL:
        return `SELECT column_name FROM information_schema.columns WHERE table_schema='${escapedDb}' AND table_name='${escapedTable}'`;

      case DatabaseType.MSSQL:
        // For MSSQL, use proper escaping
        return `SELECT column_name FROM [${database.replace(/]/g, "]]")}].information_schema.columns WHERE table_name='${escapedTable}'`;

      case DatabaseType.ORACLE:
        return `SELECT column_name FROM all_tab_columns WHERE owner='${escapedDb}' AND table_name='${escapedTable}'`;

      case DatabaseType.SQLITE:
        // For SQLite, table names in PRAGMA should be quoted
        return `PRAGMA table_info('${escapedTable}')`;

      default:
        throw new Error(`Unsupported database type: ${this.dbType}`);
    }
  }

  /**
   * Build data preview query with strict limits
   */
  private buildDataPreviewQuery(
    database: string,
    table: string,
    columns: string[],
    rowLimit: number
  ): string {
    const columnList = columns.join(", ");

    switch (this.dbType) {
      case DatabaseType.MYSQL:
        return `SELECT ${columnList} FROM ${database}.${table} LIMIT ${rowLimit}`;

      case DatabaseType.POSTGRESQL:
        return `SELECT ${columnList} FROM ${database}.${table} LIMIT ${rowLimit}`;

      case DatabaseType.MSSQL:
        return `SELECT TOP ${rowLimit} ${columnList} FROM ${database}.dbo.${table}`;

      case DatabaseType.ORACLE:
        return `SELECT ${columnList} FROM ${database}.${table} WHERE ROWNUM <= ${rowLimit}`;

      case DatabaseType.SQLITE:
        return `SELECT ${columnList} FROM ${table} LIMIT ${rowLimit}`;

      default:
        throw new Error(`Unsupported database type: ${this.dbType}`);
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): EnumerationConfig {
    return { ...this.config };
  }

  /**
   * Update rate limiting delay
   */
  updateDelay(delayMs: number): void {
    this.rateLimiter.setDelay(delayMs);
  }
}
