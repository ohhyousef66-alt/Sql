/**
 * Database Fingerprinting Module
 * 
 * Deterministic identification of backend database type and version.
 * Uses decision tree approach, NOT random if/else logic.
 */

import {
  DatabaseType,
  DatabaseFingerprint,
  ConfidenceLevel,
} from "./types";

/**
 * Fingerprint test result
 */
interface FingerprintTest {
  dbType: DatabaseType;
  payload: string;
  expectedPattern: RegExp;
  confidence: ConfidenceLevel;
  description: string;
}

/**
 * Database Fingerprinting Engine
 */
export class DatabaseFingerprinter {
  private tests: FingerprintTest[] = [];

  constructor() {
    this.initializeTests();
  }

  /**
   * Initialize fingerprint tests in decision tree order
   */
  private initializeTests(): void {
    // MySQL tests (most common first)
    this.tests.push({
      dbType: DatabaseType.MYSQL,
      payload: "SELECT VERSION()",
      expectedPattern: /\d+\.\d+\.\d+(-MariaDB)?/i,
      confidence: ConfidenceLevel.CONFIRMED,
      description: "MySQL VERSION() function",
    });

    this.tests.push({
      dbType: DatabaseType.MYSQL,
      payload: "SELECT @@version_comment",
      expectedPattern: /mysql/i,
      confidence: ConfidenceLevel.HIGH,
      description: "MySQL version_comment variable",
    });

    this.tests.push({
      dbType: DatabaseType.MYSQL,
      payload: "SELECT DATABASE()",
      expectedPattern: /.+/,
      confidence: ConfidenceLevel.MEDIUM,
      description: "MySQL DATABASE() function",
    });

    // PostgreSQL tests
    this.tests.push({
      dbType: DatabaseType.POSTGRESQL,
      payload: "SELECT version()",
      expectedPattern: /postgresql/i,
      confidence: ConfidenceLevel.CONFIRMED,
      description: "PostgreSQL version() function",
    });

    this.tests.push({
      dbType: DatabaseType.POSTGRESQL,
      payload: "SELECT current_database()",
      expectedPattern: /.+/,
      confidence: ConfidenceLevel.MEDIUM,
      description: "PostgreSQL current_database() function",
    });

    // MSSQL tests
    this.tests.push({
      dbType: DatabaseType.MSSQL,
      payload: "SELECT @@VERSION",
      expectedPattern: /microsoft|sql server/i,
      confidence: ConfidenceLevel.CONFIRMED,
      description: "MSSQL @@VERSION variable",
    });

    this.tests.push({
      dbType: DatabaseType.MSSQL,
      payload: "SELECT DB_NAME()",
      expectedPattern: /.+/,
      confidence: ConfidenceLevel.MEDIUM,
      description: "MSSQL DB_NAME() function",
    });

    // Oracle tests
    this.tests.push({
      dbType: DatabaseType.ORACLE,
      payload: "SELECT banner FROM v$version WHERE ROWNUM=1",
      expectedPattern: /oracle/i,
      confidence: ConfidenceLevel.CONFIRMED,
      description: "Oracle v$version banner",
    });

    this.tests.push({
      dbType: DatabaseType.ORACLE,
      payload: "SELECT * FROM DUAL",
      expectedPattern: /./,
      confidence: ConfidenceLevel.LOW,
      description: "Oracle DUAL table",
    });

    // SQLite tests
    this.tests.push({
      dbType: DatabaseType.SQLITE,
      payload: "SELECT sqlite_version()",
      expectedPattern: /\d+\.\d+\.\d+/,
      confidence: ConfidenceLevel.CONFIRMED,
      description: "SQLite sqlite_version() function",
    });
  }

  /**
   * Perform fingerprinting
   * @param executor Function to execute SQL and return response
   */
  async fingerprint(
    executor: (payload: string) => Promise<string | null>
  ): Promise<DatabaseFingerprint> {
    const results: Map<DatabaseType, ConfidenceLevel> = new Map();
    let detectedVersion: string | undefined;
    let detectionMethod = "";

    // Execute tests in order
    for (const test of this.tests) {
      try {
        const response = await executor(test.payload);
        
        if (response && test.expectedPattern.test(response)) {
          // Test passed - increase confidence for this DB type
          const currentConfidence = results.get(test.dbType) || ConfidenceLevel.NONE;
          results.set(test.dbType, Math.max(currentConfidence, test.confidence) as ConfidenceLevel);
          
          // Extract version if available
          if (!detectedVersion && test.confidence === ConfidenceLevel.CONFIRMED) {
            const versionMatch = response.match(/\d+\.\d+(\.\d+)?/);
            if (versionMatch) {
              detectedVersion = versionMatch[0];
            }
          }

          detectionMethod = test.description;

          // If CONFIRMED match found, can stop early
          if (test.confidence === ConfidenceLevel.CONFIRMED) {
            break;
          }
        }
      } catch (error) {
        // Test failed - continue to next
        continue;
      }
    }

    // Determine most likely database type
    let maxConfidence = ConfidenceLevel.NONE;
    let detectedType = DatabaseType.UNKNOWN;

    for (const [dbType, confidence] of results.entries()) {
      if (confidence > maxConfidence) {
        maxConfidence = confidence;
        detectedType = dbType;
      }
    }

    // Determine capabilities based on database type
    const capabilities = this.getCapabilities(detectedType);

    return {
      type: detectedType,
      version: detectedVersion,
      confidence: maxConfidence,
      detectionMethod,
      capabilities,
      metadata: {
        testedPayloads: this.tests.length,
        matchedTests: results.size,
      },
    };
  }

  /**
   * Get database capabilities based on type
   */
  private getCapabilities(dbType: DatabaseType) {
    switch (dbType) {
      case DatabaseType.MYSQL:
        return {
          supportsUnion: true,
          supportsErrorBased: true,
          supportsTimeBased: true,
          supportsStackedQueries: false, // Depends on configuration
          supportsInformationSchema: true,
        };

      case DatabaseType.POSTGRESQL:
        return {
          supportsUnion: true,
          supportsErrorBased: true,
          supportsTimeBased: true,
          supportsStackedQueries: true,
          supportsInformationSchema: true,
        };

      case DatabaseType.MSSQL:
        return {
          supportsUnion: true,
          supportsErrorBased: true,
          supportsTimeBased: true,
          supportsStackedQueries: true,
          supportsInformationSchema: true,
        };

      case DatabaseType.ORACLE:
        return {
          supportsUnion: true,
          supportsErrorBased: true,
          supportsTimeBased: true,
          supportsStackedQueries: false,
          supportsInformationSchema: false, // Uses different schema tables
        };

      case DatabaseType.SQLITE:
        return {
          supportsUnion: true,
          supportsErrorBased: false,
          supportsTimeBased: false,
          supportsStackedQueries: false,
          supportsInformationSchema: false, // Uses sqlite_master
        };

      default:
        return {
          supportsUnion: false,
          supportsErrorBased: false,
          supportsTimeBased: false,
          supportsStackedQueries: false,
          supportsInformationSchema: false,
        };
    }
  }

  /**
   * Get fingerprint tests for a specific database type
   */
  getTestsForDatabase(dbType: DatabaseType): FingerprintTest[] {
    return this.tests.filter(t => t.dbType === dbType);
  }
}
