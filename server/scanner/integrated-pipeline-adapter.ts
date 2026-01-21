/**
 * Integrated SQL Injection Pipeline Adapter
 * 
 * Bridges the new professional pipeline system with existing scanner infrastructure.
 * Provides end-to-end SQLi detection + confirmation + fingerprinting + enumeration.
 * 
 * Works for BOTH single-target and mass-target scans.
 */

import { storage } from "../storage";
import { VulnerabilityScanner } from "./index";
import { DataDumpingEngine } from "./data-dumping-engine";
import {
  PipelineController,
  ConfirmationGate,
  DatabaseFingerprinter,
  CheckpointManager,
  InMemoryCheckpointStorage,
  EnumerationEngine,
  SafetyControlsManager,
  ScanStage,
  StageStatus,
  ConfirmationSignal,
  ConfidenceLevel,
  InjectionTechnique,
  DatabaseType,
  EnumerationPhase,
  EnumerationConfig,
  DatabaseFingerprint,
  PipelineState,
  RealProgress,
} from "./pipeline";

/**
 * Scan context with pipeline integration
 */
export interface IntegratedScanContext {
  scanId: number;
  targetUrl: string;
  vulnerabilities: any[];
  confirmedVulnerability?: any;
  databaseFingerprint?: DatabaseFingerprint;
  enumerationEnabled: boolean;
  userConsent?: {
    acknowledgedWarnings: string[];
    metadata?: {
      ipAddress?: string;
      userAgent?: string;
    };
  };
}

/**
 * Enumeration results for storage
 */
export interface EnumerationResults {
  scanId: number;
  targetUrl: string;
  databaseType: string;
  databaseVersion?: string;
  databases: string[];
  tables: Record<string, string[]>; // database -> tables
  columns: Record<string, string[]>; // table_key -> columns
  dataPreview?: Record<string, any[]>; // table_key -> rows
  enumeratedAt: Date;
  confidence: number;
}

/**
 * Integrated Pipeline Adapter
 * 
 * Coordinates between:
 * - VulnerabilityScanner (SQLi detection)
 * - ConfirmationGate (multi-signal verification)
 * - DatabaseFingerprinter (DB type identification)
 * - EnumerationEngine (schema extraction)
 */
export class IntegratedPipelineAdapter {
  private context: IntegratedScanContext;
  private confirmationGate: ConfirmationGate;
  private fingerprinter: DatabaseFingerprinter;
  private safetyControls: SafetyControlsManager;
  private checkpointManager: CheckpointManager;
  private currentStage: ScanStage = ScanStage.TARGET_NORMALIZATION;

  constructor(context: IntegratedScanContext) {
    this.context = context;
    
    // Initialize pipeline components
    this.confirmationGate = new ConfirmationGate({
      minimumSignals: 2,
      minimumConfidence: ConfidenceLevel.HIGH,
      requireDifferentTechniques: true,
      requireDifferentEvidenceTypes: false, // Relaxed for integration
      timeWindowMs: 300000, // 5 minutes
    });

    this.fingerprinter = new DatabaseFingerprinter();
    
    this.safetyControls = new SafetyControlsManager(
      context.scanId.toString(),
      context.targetUrl
    );

    this.checkpointManager = new CheckpointManager(
      new InMemoryCheckpointStorage(),
      5000
    );

    // Handle user consent if provided
    if (context.enumerationEnabled && context.userConsent) {
      this.safetyControls.requestEnumerationConsent(
        context.userConsent.acknowledgedWarnings,
        context.userConsent.metadata
      );
    }
  }

  /**
   * Process detected vulnerabilities and add to confirmation gate
   */
  async processVulnerabilities(vulnerabilities: any[]): Promise<void> {
    console.log(`\n📊 Processing ${vulnerabilities.length} vulnerabilities for confirmation\n`);

    for (const vuln of vulnerabilities) {
      // Map vulnerability to confirmation signal
      const signal = this.mapVulnerabilityToSignal(vuln);
      if (signal) {
        this.confirmationGate.addSignal(signal);
        console.log(`✅ Added signal: ${signal.technique} (${signal.evidenceType})`);
      }
    }

    this.context.vulnerabilities = vulnerabilities;
  }

  /**
   * Map vulnerability detection to confirmation signal
   */
  private mapVulnerabilityToSignal(vuln: any): ConfirmationSignal | null {
    // Determine technique
    let technique: InjectionTechnique;
    let evidenceType: "error_message" | "union_data" | "boolean_behavior" | "time_delay" | "structural_change";
    
    const vulnType = vuln.type?.toLowerCase() || "";

    if (vulnType.includes("union")) {
      technique = InjectionTechnique.UNION_BASED;
      evidenceType = "union_data";
    } else if (vulnType.includes("error")) {
      technique = InjectionTechnique.ERROR_BASED;
      evidenceType = "error_message";
    } else if (vulnType.includes("boolean") || vulnType.includes("blind")) {
      technique = InjectionTechnique.BOOLEAN_BASED;
      evidenceType = "boolean_behavior";
    } else if (vulnType.includes("time")) {
      technique = InjectionTechnique.TIME_BASED;
      evidenceType = "time_delay";
    } else {
      // Default to error-based
      technique = InjectionTechnique.ERROR_BASED;
      evidenceType = "error_message";
    }

    // Map confidence
    let confidence: ConfidenceLevel;
    if (vuln.confidence >= 90) {
      confidence = ConfidenceLevel.CONFIRMED;
    } else if (vuln.confidence >= 75) {
      confidence = ConfidenceLevel.HIGH;
    } else if (vuln.confidence >= 50) {
      confidence = ConfidenceLevel.MEDIUM;
    } else {
      confidence = ConfidenceLevel.LOW;
    }

    return {
      technique,
      payload: vuln.payload || "",
      responseTimeMs: 150,
      evidenceType,
      evidence: vuln.evidence || vuln.verificationDetails || "",
      confidence,
      timestamp: new Date(vuln.timestamp || Date.now()),
    };
  }

  /**
   * Evaluate confirmation gate
   */
  async evaluateConfirmation(): Promise<boolean> {
    console.log(`\n🚦 Evaluating Confirmation Gate...\n`);

    const decision = this.confirmationGate.evaluate();

    console.log(`Decision: ${decision.passed ? "✅ PASSED" : "❌ BLOCKED"}`);
    console.log(`Confidence: ${decision.confidence}`);
    console.log(`Signals: ${decision.signals.length}`);
    console.log(`\nReasons:`);
    decision.reasons.forEach(r => console.log(`  - ${r}`));

    if (decision.passed) {
      // Mark stage as completed
      this.currentStage = ScanStage.DATABASE_FINGERPRINTING;
      
      // Store confirmed vulnerability
      if (this.context.vulnerabilities.length > 0) {
        this.context.confirmedVulnerability = this.context.vulnerabilities[0];
      }

      return true;
    }

    return false;
  }

  /**
   * Perform database fingerprinting
   */
  async fingerprintDatabase(): Promise<DatabaseFingerprint | null> {
    console.log(`\n🔍 Fingerprinting Database...\n`);

    if (!this.context.confirmedVulnerability) {
      console.warn("⚠️  No confirmed vulnerability for fingerprinting");
      return null;
    }

    try {
      // Create executor using DataDumpingEngine
      const engine = new DataDumpingEngine({
        targetUrl: this.context.targetUrl,
        vulnerableParameter: this.context.confirmedVulnerability.parameter,
        dbType: "mysql",
        technique: "error-based",
        injectionPoint: this.context.confirmedVulnerability.payload,
        signal: new AbortController().signal,
      });

      const executor = async (query: string): Promise<string | null> => {
        try {
          // Use engine's extractValue method to execute SQL query
          const result = await (engine as any).extractValue(query);
          return result;
        } catch (error) {
          return null;
        }
      };

      const fingerprint = await this.fingerprinter.fingerprint(executor);

      console.log(`\n📋 Fingerprint Results:`);
      console.log(`  Type: ${fingerprint.type}`);
      console.log(`  Version: ${fingerprint.version || "Unknown"}`);
      console.log(`  Confidence: ${fingerprint.confidence}`);
      console.log(`  Method: ${fingerprint.detectionMethod}`);

      this.context.databaseFingerprint = fingerprint;
      this.currentStage = ScanStage.POST_CONFIRMATION_ENUMERATION;

      // Save fingerprint to scan
      await storage.updateScan(this.context.scanId, {
        techStack: {
          database: fingerprint.type,
          version: fingerprint.version,
        },
      });

      return fingerprint;
    } catch (error: any) {
      console.error("❌ Fingerprinting failed:", error.message);
      return null;
    }
  }

  /**
   * Perform post-confirmation enumeration
   */
  async enumerateDatabase(): Promise<EnumerationResults | null> {
    console.log(`\n📚 Starting Database Enumeration...\n`);

    // Check if enumeration is allowed
    if (!this.safetyControls.isEnumerationAllowed()) {
      console.log("⏭️  Enumeration not enabled or no user consent");
      return null;
    }

    if (!this.context.databaseFingerprint) {
      console.warn("⚠️  No database fingerprint available");
      return null;
    }

    if (!this.context.confirmedVulnerability) {
      console.warn("⚠️  No confirmed vulnerability");
      return null;
    }

    try {
      // Get safe enumeration config
      const config = this.safetyControls.getSafeEnumerationConfig();

      // Create executor
      const engine = new DataDumpingEngine({
        targetUrl: this.context.targetUrl,
        vulnerableParameter: this.context.confirmedVulnerability.parameter,
        dbType: "mysql",
        technique: "error-based",
        injectionPoint: this.context.confirmedVulnerability.payload,
        signal: new AbortController().signal,
      });

      const executor = async (query: string): Promise<string[] | null> => {
        try {
          const result = await (engine as any).extractValue(query);
          if (result) {
            // Parse result into array
            return result.split(",").map((s: string) => s.trim()).filter(Boolean);
          }
          return null;
        } catch (error) {
          return null;
        }
      };

      // Initialize checkpoint
      await this.checkpointManager.initialize(
        this.context.scanId.toString(),
        EnumerationPhase.DATABASES
      );

      // Create enumeration engine
      const enumerationEngine = new EnumerationEngine(
        config,
        this.context.databaseFingerprint,
        this.checkpointManager,
        executor
      );

      const results: EnumerationResults = {
        scanId: this.context.scanId,
        targetUrl: this.context.targetUrl,
        databaseType: this.context.databaseFingerprint.type,
        databaseVersion: this.context.databaseFingerprint.version,
        databases: [],
        tables: {},
        columns: {},
        enumeratedAt: new Date(),
        confidence: this.context.databaseFingerprint.confidence,
      };

      // Enumerate databases
      if (config.databasesEnabled) {
        console.log("\n📊 Enumerating Databases...");
        const dbResult = await enumerationEngine.enumerateDatabases();
        if (dbResult.success) {
          results.databases = dbResult.data;
          console.log(`✅ Found ${results.databases.length} databases`);
          results.databases.forEach(db => console.log(`  - ${db}`));
        }
      }

      // Enumerate tables (for each database, limited)
      if (config.tablesEnabled && results.databases.length > 0) {
        const databasesToEnum = results.databases.slice(0, 3); // Limit to first 3 databases
        
        for (const database of databasesToEnum) {
          console.log(`\n📊 Enumerating Tables in: ${database}`);
          const tablesResult = await enumerationEngine.enumerateTables(database);
          
          if (tablesResult.success) {
            results.tables[database] = tablesResult.data;
            console.log(`✅ Found ${tablesResult.data.length} tables`);
            tablesResult.data.forEach(table => console.log(`  - ${table}`));
          }
        }
      }

      // Enumerate columns (for first table of first database, as example)
      if (config.columnsEnabled && Object.keys(results.tables).length > 0) {
        const firstDb = Object.keys(results.tables)[0];
        const firstTable = results.tables[firstDb]?.[0];
        
        if (firstTable) {
          console.log(`\n📊 Enumerating Columns in: ${firstDb}.${firstTable}`);
          const columnsResult = await enumerationEngine.enumerateColumns(firstDb, firstTable);
          
          if (columnsResult.success) {
            results.columns[`${firstDb}.${firstTable}`] = columnsResult.data;
            console.log(`✅ Found ${columnsResult.data.length} columns`);
            columnsResult.data.forEach(col => console.log(`  - ${col}`));
          }
        }
      }

      console.log(`\n✨ Enumeration Complete!\n`);

      // Save results
      await this.saveEnumerationResults(results);

      return results;
    } catch (error: any) {
      console.error("❌ Enumeration failed:", error.message);
      this.safetyControls.logAction({
        action: "enumeration_failed",
        stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
        timestamp: new Date(),
        metadata: { error: error.message },
        result: "failure",
        reason: error.message,
      });
      return null;
    }
  }

  /**
   * Save enumeration results to storage
   */
  private async saveEnumerationResults(results: EnumerationResults): Promise<void> {
    try {
      // Get first vulnerability for this scan (confirmed vuln)
      const vulns = await storage.getVulnerabilities(this.context.scanId);
      if (vulns.length === 0) {
        console.warn("⚠️  No vulnerabilities found for scan, cannot save enumeration results");
        return;
      }

      const firstVuln = vulns[0];

      // Save database information
      for (const dbName of results.databases) {
        const dbRecord = await storage.createExtractedDatabase({
          vulnerabilityId: firstVuln.id,
          scanId: this.context.scanId,
          targetUrl: this.context.targetUrl,
          databaseName: dbName,
          dbType: results.databaseType,
          extractionMethod: "pipeline",
          tableCount: results.tables[dbName]?.length || 0,
          status: "completed",
          metadata: {
            version: results.databaseVersion,
          },
        });

        const dbId = dbRecord.id;

        // Save tables for this database
        const tables = results.tables[dbName] || [];
        for (const tableName of tables) {
          const tableRecord = await storage.createExtractedTable({
            databaseId: dbId,
            tableName,
            columnCount: results.columns[`${dbName}.${tableName}`]?.length || 0,
            status: "completed",
          });

          const tableId = tableRecord.id;

          // Save columns for this table
          const columns = results.columns[`${dbName}.${tableName}`] || [];
          for (const columnName of columns) {
            await storage.createExtractedColumn({
              tableId,
              columnName,
            });
          }
        }
      }

      console.log("\n💾 Enumeration results saved to database");
      console.log(`   - ${results.databases.length} databases`);
      console.log(`   - ${Object.values(results.tables).flat().length} tables`);
      console.log(`   - ${Object.values(results.columns).flat().length} columns`);

      // Also log to audit trail
      this.safetyControls.logAction({
        action: "enumeration_completed",
        stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
        timestamp: new Date(),
        metadata: {
          databasesFound: results.databases.length,
          tablesFound: Object.values(results.tables).flat().length,
          columnsFound: Object.values(results.columns).flat().length,
        },
        result: "success",
      });
    } catch (error: any) {
      console.error("❌ Failed to save enumeration results:", error.message);
      this.safetyControls.logAction({
        action: "enumeration_save_failed",
        stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
        timestamp: new Date(),
        metadata: { error: error.message },
        result: "failure",
        reason: error.message,
      });
    }
  }

  /**
   * Get current pipeline stage
   */
  getCurrentStage(): ScanStage {
    return this.currentStage;
  }

  /**
   * Get audit trail
   */
  getAuditTrail() {
    return this.safetyControls.getAuditTrail();
  }

  /**
   * Check if enumeration is allowed
   */
  isEnumerationAllowed(): boolean {
    return this.safetyControls.isEnumerationAllowed();
  }
}
