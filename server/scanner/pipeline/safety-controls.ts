/**
 * Safety Controls and Audit Trail System
 * 
 * MANDATORY legal and safety controls:
 * - Enumeration DISABLED by default
 * - Data preview DISABLED by default
 * - Explicit user consent required
 * - Full audit trail logging
 * 
 * Public deployments MUST ship with enumeration features OFF.
 */

import {
  SafetyAudit,
  ScanStage,
  EnumerationPhase,
  EnumerationConfig,
} from "./types";

/**
 * User consent record
 */
export interface UserConsent {
  enumerationEnabled: boolean;
  dataPreviewEnabled: boolean;
  acknowledgedLegalWarnings: boolean;
  acknowledgedRisks: string[];
  consentTimestamp: Date;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Audit action
 */
export interface AuditAction {
  action: string;
  stage: ScanStage;
  phase?: EnumerationPhase;
  timestamp: Date;
  metadata: Record<string, any>;
  result?: "success" | "failure" | "blocked";
  reason?: string;
}

/**
 * Safety gate decision
 */
export interface SafetyDecision {
  allowed: boolean;
  reason: string;
  missingConsents: string[];
}

/**
 * Safety Controls Manager
 */
export class SafetyControlsManager {
  private consent?: UserConsent;
  private auditLog: AuditAction[] = [];
  private scanId: string;
  private targetUrl: string;

  // Legal warnings (MUST be acknowledged)
  private static readonly LEGAL_WARNINGS = [
    "I have explicit written authorization to test this target",
    "I understand that unauthorized access is illegal",
    "I take full responsibility for all actions performed",
    "I will not use extracted data for malicious purposes",
  ];

  constructor(scanId: string, targetUrl: string) {
    this.scanId = scanId;
    this.targetUrl = targetUrl;
  }

  /**
   * Request user consent for enumeration
   * 
   * CRITICAL: This MUST be called before any enumeration can proceed
   */
  requestEnumerationConsent(
    acknowledgedWarnings: string[],
    metadata?: {
      ipAddress?: string;
      userAgent?: string;
    }
  ): SafetyDecision {
    // Verify all legal warnings acknowledged
    const missingWarnings = SafetyControlsManager.LEGAL_WARNINGS.filter(
      warning => !acknowledgedWarnings.includes(warning)
    );

    if (missingWarnings.length > 0) {
      this.logAction({
        action: "enumeration_consent_denied",
        stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
        timestamp: new Date(),
        metadata: {
          reason: "Missing legal acknowledgments",
          missingWarnings,
        },
        result: "blocked",
        reason: "User did not acknowledge all legal warnings",
      });

      return {
        allowed: false,
        reason: "All legal warnings must be acknowledged",
        missingConsents: missingWarnings,
      };
    }

    // Grant consent
    this.consent = {
      enumerationEnabled: true,
      dataPreviewEnabled: false, // Still disabled by default
      acknowledgedLegalWarnings: true,
      acknowledgedRisks: acknowledgedWarnings,
      consentTimestamp: new Date(),
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    };

    this.logAction({
      action: "enumeration_consent_granted",
      stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
      timestamp: new Date(),
      metadata: {
        ipAddress: metadata?.ipAddress,
        acknowledgedWarnings: acknowledgedWarnings.length,
      },
      result: "success",
    });

    return {
      allowed: true,
      reason: "Enumeration consent granted",
      missingConsents: [],
    };
  }

  /**
   * Request user consent for data preview
   * 
   * CRITICAL: Requires ADDITIONAL consent beyond enumeration
   */
  requestDataPreviewConsent(
    additionalAcknowledgments: string[]
  ): SafetyDecision {
    // Must have enumeration consent first
    if (!this.consent || !this.consent.enumerationEnabled) {
      return {
        allowed: false,
        reason: "Enumeration consent required first",
        missingConsents: ["Enumeration consent"],
      };
    }

    // Additional warnings for data preview
    const dataPreviewWarnings = [
      "I understand that data preview may expose sensitive information",
      "I will handle any extracted data responsibly",
      "I will not store or redistribute extracted data without authorization",
    ];

    const missingWarnings = dataPreviewWarnings.filter(
      warning => !additionalAcknowledgments.includes(warning)
    );

    if (missingWarnings.length > 0) {
      this.logAction({
        action: "data_preview_consent_denied",
        stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
        phase: EnumerationPhase.DATA_PREVIEW,
        timestamp: new Date(),
        metadata: {
          reason: "Missing data preview acknowledgments",
          missingWarnings,
        },
        result: "blocked",
      });

      return {
        allowed: false,
        reason: "All data preview warnings must be acknowledged",
        missingConsents: missingWarnings,
      };
    }

    // Grant data preview consent
    this.consent.dataPreviewEnabled = true;
    this.consent.acknowledgedRisks.push(...additionalAcknowledgments);

    this.logAction({
      action: "data_preview_consent_granted",
      stage: ScanStage.POST_CONFIRMATION_ENUMERATION,
      phase: EnumerationPhase.DATA_PREVIEW,
      timestamp: new Date(),
      metadata: {},
      result: "success",
    });

    return {
      allowed: true,
      reason: "Data preview consent granted",
      missingConsents: [],
    };
  }

  /**
   * Check if enumeration is allowed
   */
  isEnumerationAllowed(): boolean {
    return this.consent?.enumerationEnabled === true;
  }

  /**
   * Check if data preview is allowed
   */
  isDataPreviewAllowed(): boolean {
    return (
      this.consent?.enumerationEnabled === true &&
      this.consent?.dataPreviewEnabled === true
    );
  }

  /**
   * Get safe enumeration configuration
   */
  getSafeEnumerationConfig(): EnumerationConfig {
    return {
      enabled: this.isEnumerationAllowed(),
      schemaOnly: true, // Always prefer schema-only
      databasesEnabled: this.isEnumerationAllowed(),
      tablesEnabled: this.isEnumerationAllowed(),
      columnsEnabled: this.isEnumerationAllowed(),
      dataPreviewEnabled: this.isDataPreviewAllowed(),
      maxDatabases: 50,
      maxTablesPerDatabase: 100,
      maxColumnsPerTable: 50,
      maxRowsPreview: 10,
      maxFieldsPreview: 5,
      requestDelayMs: 1000,
      maxRetries: 3,
      timeoutMs: 10000,
    };
  }

  /**
   * Log an action to audit trail
   */
  logAction(action: AuditAction): void {
    this.auditLog.push(action);

    // Log to console for visibility
    const status = action.result ? `[${action.result.toUpperCase()}]` : "";
    console.log(
      `🔒 AUDIT ${status}: ${action.action} at ${action.stage}${
        action.phase ? ` / ${action.phase}` : ""
      }`
    );

    if (action.reason) {
      console.log(`   Reason: ${action.reason}`);
    }
  }

  /**
   * Get full audit trail
   */
  getAuditTrail(): SafetyAudit {
    return {
      scanId: this.scanId,
      targetUrl: this.targetUrl,
      userConsent: this.consent
        ? {
            enumerationEnabled: this.consent.enumerationEnabled,
            dataPreviewEnabled: this.consent.dataPreviewEnabled,
            acknowledgedLegalWarnings: this.consent.acknowledgedLegalWarnings,
            timestamp: this.consent.consentTimestamp,
          }
        : {
            enumerationEnabled: false,
            dataPreviewEnabled: false,
            acknowledgedLegalWarnings: false,
            timestamp: new Date(),
          },
      actions: [...this.auditLog],
    };
  }

  /**
   * Export audit trail to JSON
   */
  exportAuditTrail(): string {
    return JSON.stringify(this.getAuditTrail(), null, 2);
  }

  /**
   * Get legal warnings that must be acknowledged
   */
  static getLegalWarnings(): string[] {
    return [...SafetyControlsManager.LEGAL_WARNINGS];
  }

  /**
   * Validate that a configuration is safe for production
   */
  static validateProductionConfig(config: EnumerationConfig): {
    safe: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    // CRITICAL: These MUST be false in production by default
    if (config.enabled) {
      violations.push("Enumeration must be DISABLED by default in production");
    }

    if (config.dataPreviewEnabled) {
      violations.push(
        "Data preview must be DISABLED by default in production"
      );
    }

    // Check limits are reasonable
    if (config.maxDatabases > 100) {
      violations.push("maxDatabases too high for production (max: 100)");
    }

    if (config.maxTablesPerDatabase > 200) {
      violations.push("maxTablesPerDatabase too high for production (max: 200)");
    }

    if (config.maxRowsPreview > 20) {
      violations.push("maxRowsPreview too high for production (max: 20)");
    }

    if (config.requestDelayMs < 500) {
      violations.push("requestDelayMs too low for production (min: 500ms)");
    }

    return {
      safe: violations.length === 0,
      violations,
    };
  }
}
