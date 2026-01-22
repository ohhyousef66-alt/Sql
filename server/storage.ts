import { db } from "./db";
import {
  scans,
  vulnerabilities,
  scanLogs,
  trafficLogs,
  // uploadedFiles,  // Not in schema
  // stagedTargets,  // Not in schema
  // stageRuns,      // Not in schema
  extractedDatabases,
  extractedTables,
  extractedColumns,
  extractedData,
  dumpingJobs,
  type Scan,
  type InsertScan,
  type Vulnerability,
  type InsertVulnerability,
  type ScanLog,
  type InsertScanLog,
  type TrafficLog,
  type InsertTrafficLog,
  type UploadedFile,
  type InsertUploadedFile,
  type StagedTarget,
  type InsertStagedTarget,
  type StageRun,
  type InsertStageRun,
  type ExtractedDatabase,
  type InsertExtractedDatabase,
  type ExtractedTable,
  type InsertExtractedTable,
  type ExtractedColumn,
  type InsertExtractedColumn,
  type ExtractedData,
  type InsertExtractedData,
  type DumpingJob,
  type InsertDumpingJob,
} from "@shared/schema";
import { eq, desc, and, lt, or, isNull } from "drizzle-orm";

export interface IStorage {
  // Scans
  getScans(): Promise<Scan[]>;
  getScan(id: number): Promise<Scan | undefined>;
  createScan(scan: InsertScan): Promise<Scan>;
  createBatchParentScan(targetUrls: string[], scanMode: string): Promise<Scan>;
  createChildScan(parentScanId: number, targetUrl: string, scanMode: string): Promise<Scan>;
  getChildScans(parentScanId: number): Promise<Scan[]>;
  updateParentScanFromChildren(parentScanId: number): Promise<Scan>;
  updateScanStatus(id: number, status: string, progress?: number, summary?: any): Promise<Scan>;
  updateScan(id: number, updates: {
    status?: string;
    progress?: number;
    summary?: any;
    crawlStats?: any;
    techStack?: any;
    progressMetrics?: any;
    endTime?: Date;
    completionReason?: string;
  }): Promise<Scan>;
  
  // Vulnerabilities
  getVulnerabilities(scanId: number): Promise<Vulnerability[]>;
  createVulnerability(vuln: InsertVulnerability): Promise<Vulnerability>;
  
  // Logs
  getScanLogs(scanId: number): Promise<ScanLog[]>;
  createScanLog(log: InsertScanLog): Promise<ScanLog>;
  
  // Traffic Logs
  getTrafficLogs(scanId: number, limit?: number): Promise<TrafficLog[]>;
  createTrafficLog(log: InsertTrafficLog): Promise<TrafficLog>;
  
  cancelScan(id: number): Promise<Scan>;
  
  // Uploaded Files (Mass-Scan Management)
  createUploadedFile(data: InsertUploadedFile): Promise<UploadedFile>;
  getUploadedFile(id: number): Promise<UploadedFile | undefined>;
  getUploadedFiles(): Promise<UploadedFile[]>;
  updateUploadedFile(id: number, data: Partial<UploadedFile>): Promise<UploadedFile>;
  deleteUploadedFile(id: number): Promise<void>;
  
  // Staged Targets (Mass-Scan Management)
  createStagedTarget(data: InsertStagedTarget): Promise<StagedTarget>;
  createStagedTargets(data: InsertStagedTarget[]): Promise<StagedTarget[]>;
  getStagedTargetsByFile(fileId: number): Promise<StagedTarget[]>;
  getStagedTargetsByFileAndStage(fileId: number, stage: number): Promise<StagedTarget[]>;
  getFlaggedTargets(fileId?: number): Promise<StagedTarget[]>;
  updateStagedTarget(id: number, data: Partial<StagedTarget>): Promise<StagedTarget>;
  
  // Stage Runs (Mass-Scan Management)
  createStageRun(data: InsertStageRun): Promise<StageRun>;
  getStageRun(id: number): Promise<StageRun | undefined>;
  getStageRunsByFile(fileId: number): Promise<StageRun[]>;
  updateStageRun(id: number, data: Partial<StageRun>): Promise<StageRun>;
  
  // Data Dumping (SQLi Dumper Feature)
  getVulnerability(id: number): Promise<Vulnerability | undefined>;
  createExtractedDatabase(data: InsertExtractedDatabase): Promise<ExtractedDatabase>;
  getExtractedDatabase(id: number): Promise<ExtractedDatabase | undefined>;
  getExtractedDatabases(vulnerabilityId: number): Promise<ExtractedDatabase[]>;
  updateExtractedDatabase(id: number, data: Partial<ExtractedDatabase>): Promise<ExtractedDatabase>;
  
  createExtractedTable(data: InsertExtractedTable): Promise<ExtractedTable>;
  getExtractedTable(id: number): Promise<ExtractedTable | undefined>;
  getExtractedTables(databaseId: number): Promise<ExtractedTable[]>;
  updateExtractedTable(id: number, data: Partial<ExtractedTable>): Promise<ExtractedTable>;
  
  createExtractedColumn(data: InsertExtractedColumn): Promise<ExtractedColumn>;
  getExtractedColumns(tableId: number): Promise<ExtractedColumn[]>;
  
  createExtractedData(data: InsertExtractedData): Promise<ExtractedData>;
  getExtractedData(tableId: number, limit?: number, offset?: number): Promise<ExtractedData[]>;
  getExtractedDataCount(tableId: number): Promise<number>;
  
  createDumpingJob(data: InsertDumpingJob): Promise<DumpingJob>;
  getDumpingJob(id: number): Promise<DumpingJob | undefined>;
  getDumpingJobs(vulnerabilityId: number): Promise<DumpingJob[]>;
  updateDumpingJob(id: number, data: Partial<DumpingJob>): Promise<DumpingJob>;
}

export class DatabaseStorage implements IStorage {
  async getScans(): Promise<Scan[]> {
    return await db.select().from(scans).orderBy(desc(scans.startTime));
  }

  async getScan(id: number): Promise<Scan | undefined> {
    const [scan] = await db.select().from(scans).where(eq(scans.id, id));
    return scan;
  }

  async createScan(insertScan: InsertScan): Promise<Scan> {
    const [scan] = await db.insert(scans).values(insertScan).returning();
    return scan;
  }

  async createBatchParentScan(targetUrls: string[], scanMode: string): Promise<Scan> {
    const [parentScan] = await db.insert(scans).values({
      targetUrl: `Batch scan: ${targetUrls.length} targets`,
      scanMode,
      status: "batch_parent",
      isParent: true,
      progress: 0,
    }).returning();
    return parentScan;
  }

  async createChildScan(parentScanId: number, targetUrl: string, scanMode: string): Promise<Scan> {
    const [childScan] = await db.insert(scans).values({
      targetUrl,
      scanMode,
      status: "pending",
      parentScanId,
      isParent: false,
      progress: 0,
    }).returning();
    return childScan;
  }

  async getChildScans(parentScanId: number): Promise<Scan[]> {
    return await db
      .select()
      .from(scans)
      .where(eq(scans.parentScanId, parentScanId))
      .orderBy(scans.id);
  }

  async updateParentScanFromChildren(parentScanId: number): Promise<Scan> {
    const children = await this.getChildScans(parentScanId);
    
    if (children.length === 0) {
      const [updated] = await db
        .update(scans)
        .set({ status: "completed", progress: 100, endTime: new Date() })
        .where(eq(scans.id, parentScanId))
        .returning();
      return updated;
    }

    const completedCount = children.filter(c => 
      c.status === "completed" || c.status === "failed" || c.status === "cancelled"
    ).length;
    
    const allDone = completedCount === children.length;
    const progress = Math.round((completedCount / children.length) * 100);
    
    const aggregatedSummary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      confirmed: 0,
      potential: 0,
      childScans: children.length,
      completedScans: completedCount,
    };

    for (const child of children) {
      const summary = child.summary as Record<string, number> | null;
      if (summary) {
        aggregatedSummary.critical += summary.critical || 0;
        aggregatedSummary.high += summary.high || 0;
        aggregatedSummary.medium += summary.medium || 0;
        aggregatedSummary.low += summary.low || 0;
        aggregatedSummary.info += summary.info || 0;
        aggregatedSummary.confirmed += summary.confirmed || 0;
        aggregatedSummary.potential += summary.potential || 0;
      }
    }

    const updates: any = {
      progress,
      summary: aggregatedSummary,
    };
    
    if (allDone) {
      updates.status = "completed";
      updates.endTime = new Date();
    } else if (children.some(c => c.status === "scanning")) {
      updates.status = "scanning";
    }

    const [updated] = await db
      .update(scans)
      .set(updates)
      .where(eq(scans.id, parentScanId))
      .returning();
    return updated;
  }

  async updateScanStatus(id: number, status: string, progress?: number, summary?: any): Promise<Scan> {
    const updates: any = { status };
    if (progress !== undefined) updates.progress = progress;
    if (summary !== undefined) updates.summary = summary;
    if (status === "completed" || status === "failed") updates.endTime = new Date();

    const [updated] = await db
      .update(scans)
      .set(updates)
      .where(eq(scans.id, id))
      .returning();
    return updated;
  }

  async updateScan(
    id: number,
    updates: {
      status?: string;
      progress?: number;
      summary?: any;
      crawlStats?: any;
      techStack?: any;
      progressMetrics?: any;
      endTime?: Date;
      completionReason?: string;
    }
  ): Promise<Scan> {
    const updateData: any = {};
    
    if (updates.status !== undefined) updateData.status = updates.status;
    if (updates.progress !== undefined) updateData.progress = updates.progress;
    if (updates.summary !== undefined) updateData.summary = updates.summary;
    if (updates.crawlStats !== undefined) updateData.crawlStats = updates.crawlStats;
    if (updates.techStack !== undefined) updateData.techStack = updates.techStack;
    if (updates.progressMetrics !== undefined) updateData.progressMetrics = updates.progressMetrics;
    if (updates.endTime !== undefined) updateData.endTime = updates.endTime;
    if (updates.completionReason !== undefined) updateData.completionReason = updates.completionReason;

    const [updated] = await db
      .update(scans)
      .set(updateData)
      .where(eq(scans.id, id))
      .returning();
    return updated;
  }

  async getVulnerabilities(scanId: number): Promise<Vulnerability[]> {
    return await db
      .select()
      .from(vulnerabilities)
      .where(eq(vulnerabilities.scanId, scanId));
  }

  async createVulnerability(vuln: InsertVulnerability): Promise<Vulnerability> {
    const [newVuln] = await db.insert(vulnerabilities).values(vuln).returning();
    return newVuln;
  }

  async getScanLogs(scanId: number): Promise<ScanLog[]> {
    return await db
      .select()
      .from(scanLogs)
      .where(eq(scanLogs.scanId, scanId))
      .orderBy(desc(scanLogs.timestamp));
  }

  async createScanLog(log: InsertScanLog): Promise<ScanLog> {
    const [newLog] = await db.insert(scanLogs).values(log).returning();
    return newLog;
  }

  async getTrafficLogs(scanId: number, limit: number = 1000): Promise<TrafficLog[]> {
    return await db
      .select()
      .from(trafficLogs)
      .where(eq(trafficLogs.scanId, scanId))
      .orderBy(desc(trafficLogs.timestamp))
      .limit(limit);
  }

  async createTrafficLog(log: InsertTrafficLog): Promise<TrafficLog> {
    const [newLog] = await db.insert(trafficLogs).values(log).returning();
    return newLog;
  }

  async cancelScan(id: number): Promise<Scan> {
    const [updated] = await db
      .update(scans)
      .set({ status: "cancelled", endTime: new Date(), completionReason: "Cancelled by user" })
      .where(eq(scans.id, id))
      .returning();
    return updated;
  }

  async deleteScan(id: number): Promise<void> {
    await db.delete(vulnerabilities).where(eq(vulnerabilities.scanId, id));
    await db.delete(scanLogs).where(eq(scanLogs.scanId, id));
    await db.delete(trafficLogs).where(eq(trafficLogs.scanId, id));
    await db.delete(scans).where(eq(scans.id, id));
  }

  // Uploaded Files (Mass-Scan Management) - DISABLED (not in schema)
  async createUploadedFile(data: any): Promise<any> {
    throw new Error("Uploaded files feature not available");
  }

  async getUploadedFile(id: number): Promise<any> {
    return undefined;
  }

  async getUploadedFiles(): Promise<any[]> {
    return [];
  }

  async updateUploadedFile(id: number, data: any): Promise<any> {
    throw new Error("Uploaded files feature not available");
  }

  async deleteUploadedFile(id: number): Promise<void> {
    // Feature disabled
  }

  // Staged Targets (Mass-Scan Management) - DISABLED (not in schema)
  async createStagedTarget(data: any): Promise<any> {
    throw new Error("Staged targets feature not available");
  }

  async createStagedTargets(data: any[]): Promise<any[]> {
    throw new Error("Staged targets feature not available");
  }

  async getStagedTargetsByFile(fileId: number): Promise<any[]> {
    return [];
  }

  async getStagedTargetsByFileAndStage(fileId: number, stage: number): Promise<any[]> {
    return [];
  }

  async getFlaggedTargets(fileId?: number): Promise<any[]> {
    return [];
  }

  async updateStagedTarget(id: number, data: any): Promise<any> {
    throw new Error("Staged targets feature not available");
  }

  // Stage Runs (Mass-Scan Management) - DISABLED (not in schema)
  async createStageRun(data: any): Promise<any> {
    throw new Error("Stage runs feature not available");
  }

  async getStageRun(id: number): Promise<any> {
    return undefined;
  }

  async getStageRunsByFile(fileId: number): Promise<any[]> {
    return [];
  }

  async updateStageRun(id: number, data: any): Promise<any> {
    throw new Error("Stage runs feature not available");
  }

  async cleanupOrphanedScans(): Promise<number> {
    // Increased from 10 minutes to 2 hours to accommodate slow/complex scans
    const staleThreshold = new Date(Date.now() - 2 * 60 * 60 * 1000);
    
    const result = await db
      .update(scans)
      .set({ 
        status: "failed", 
        endTime: new Date(),
        completionReason: "Error: Orphaned scan - stale for over 10 minutes",
        summary: { 
          confirmed: 0, 
          potential: 0, 
          info: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        }
      })
      .where(
        and(
          or(
            eq(scans.status, "scanning"),
            eq(scans.status, "in_progress"),
            eq(scans.status, "pending")
          ),
          lt(scans.startTime, staleThreshold)
        )
      )
      .returning();
    
    return result.length;
  }

  // ============================================================
  // DATA DUMPING METHODS - SQLi Dumper Feature
  // ============================================================

  async getVulnerability(id: number): Promise<Vulnerability | undefined> {
    const [vuln] = await db.select().from(vulnerabilities).where(eq(vulnerabilities.id, id));
    return vuln;
  }

  async createExtractedDatabase(data: InsertExtractedDatabase): Promise<ExtractedDatabase> {
    const [database] = await db.insert(extractedDatabases).values({
      ...data,
      metadata: data.metadata as any,
    }).returning();
    return database;
  }

  async getExtractedDatabase(id: number): Promise<ExtractedDatabase | undefined> {
    const [database] = await db.select().from(extractedDatabases).where(eq(extractedDatabases.id, id));
    return database;
  }

  async getExtractedDatabases(vulnerabilityId?: number): Promise<ExtractedDatabase[]> {
    if (vulnerabilityId) {
      return await db
        .select()
        .from(extractedDatabases)
        .where(eq(extractedDatabases.vulnerabilityId, vulnerabilityId))
        .orderBy(desc(extractedDatabases.extractedAt));
    }
    return await db
      .select()
      .from(extractedDatabases)
      .orderBy(desc(extractedDatabases.extractedAt));
  }

  async updateExtractedDatabase(id: number, data: Partial<ExtractedDatabase>): Promise<ExtractedDatabase> {
    const [updated] = await db
      .update(extractedDatabases)
      .set(data)
      .where(eq(extractedDatabases.id, id))
      .returning();
    return updated;
  }

  async createExtractedTable(data: InsertExtractedTable): Promise<ExtractedTable> {
    const [table] = await db.insert(extractedTables).values(data).returning();
    return table;
  }

  async getExtractedTable(id: number): Promise<ExtractedTable | undefined> {
    const [table] = await db.select().from(extractedTables).where(eq(extractedTables.id, id));
    return table;
  }

  async getExtractedTables(databaseId: number): Promise<ExtractedTable[]> {
    return await db
      .select()
      .from(extractedTables)
      .where(eq(extractedTables.databaseId, databaseId))
      .orderBy(extractedTables.tableName);
  }

  async updateExtractedTable(id: number, data: Partial<ExtractedTable>): Promise<ExtractedTable> {
    const [updated] = await db
      .update(extractedTables)
      .set(data)
      .where(eq(extractedTables.id, id))
      .returning();
    return updated;
  }

  async createExtractedColumn(data: InsertExtractedColumn): Promise<ExtractedColumn> {
    const [column] = await db.insert(extractedColumns).values(data).returning();
    return column;
  }

  async getExtractedColumns(tableId: number): Promise<ExtractedColumn[]> {
    return await db
      .select()
      .from(extractedColumns)
      .where(eq(extractedColumns.tableId, tableId))
      .orderBy(extractedColumns.columnName);
  }

  async createExtractedData(data: InsertExtractedData): Promise<ExtractedData> {
    const [dataRow] = await db.insert(extractedData).values(data).returning();
    return dataRow;
  }

  async getExtractedData(tableId: number, limit: number = 100, offset: number = 0): Promise<ExtractedData[]> {
    return await db
      .select()
      .from(extractedData)
      .where(eq(extractedData.tableId, tableId))
      .orderBy(extractedData.rowIndex)
      .limit(limit)
      .offset(offset);
  }

  async getExtractedDataCount(tableId: number): Promise<number> {
    const result = await db
      .select()
      .from(extractedData)
      .where(eq(extractedData.tableId, tableId));
    return result.length;
  }

  async createDumpingJob(data: InsertDumpingJob): Promise<DumpingJob> {
    const [job] = await db.insert(dumpingJobs).values(data).returning();
    return job;
  }

  async getDumpingJob(id: number): Promise<DumpingJob | undefined> {
    const [job] = await db.select().from(dumpingJobs).where(eq(dumpingJobs.id, id));
    return job;
  }

  async getDumpingJobs(vulnerabilityId: number): Promise<DumpingJob[]> {
    return await db
      .select()
      .from(dumpingJobs)
      .where(eq(dumpingJobs.vulnerabilityId, vulnerabilityId))
      .orderBy(desc(dumpingJobs.createdAt));
  }

  async updateDumpingJob(id: number, data: Partial<DumpingJob>): Promise<DumpingJob> {
    const [updated] = await db
      .update(dumpingJobs)
      .set(data)
      .where(eq(dumpingJobs.id, id))
      .returning();
    return updated;
  }

  // Get enumeration results for a scan
  async getEnumerationResults(scanId: number) {
    // Get all databases for this scan
    const databases = await db
      .select()
      .from(extractedDatabases)
      .where(eq(extractedDatabases.scanId, scanId))
      .orderBy(extractedDatabases.extractedAt);

    // For each database, get tables and columns
    const results = [];
    for (const database of databases) {
      const tables = await db
        .select()
        .from(extractedTables)
        .where(eq(extractedTables.databaseId, database.id))
        .orderBy(extractedTables.extractedAt);

      const tablesWithColumns = [];
      for (const table of tables) {
        const columns = await db
          .select()
          .from(extractedColumns)
          .where(eq(extractedColumns.tableId, table.id))
          .orderBy(extractedColumns.extractedAt);

        tablesWithColumns.push({
          ...table,
          columns,
        });
      }

      results.push({
        ...database,
        tables: tablesWithColumns,
      });
    }

    return results;
  }
}

export const storage = new DatabaseStorage();
