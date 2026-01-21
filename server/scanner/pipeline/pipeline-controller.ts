/**
 * Scanning Pipeline Controller
 * 
 * Orchestrates the complete staged pipeline with hard gates between stages.
 * Each stage must complete successfully before the next can execute.
 * 
 * Stage order (STRICT):
 * 1. Target Normalization
 * 2. Parameter Discovery
 * 3. Vulnerability Confirmation
 * 4. Database Fingerprinting
 * 5. Post-Confirmation Enumeration (OPT-IN)
 * 6. Reporting
 */

import {
  ScanStage,
  StageStatus,
  StageOutput,
  PipelineState,
  ConfidenceLevel,
  RealProgress,
} from "./types";
import { ConfirmationGate } from "./confirmation-gate";
import { DatabaseFingerprinter } from "./database-fingerprinter";
import {
  CheckpointManager,
  InMemoryCheckpointStorage,
} from "./checkpoint-manager";
import { EnumerationEngine } from "./enumeration-engine";
import { AdaptivePacer } from "./adaptive-pacer";
import { ResponseAnalyzer } from "./response-analyzer";
import { SafetyControlsManager } from "./safety-controls";

/**
 * Pipeline configuration
 */
export interface PipelineConfig {
  scanId: string;
  targetUrl: string;
  enableEnumeration?: boolean; // Default: FALSE
  userConsent?: {
    acknowledgedWarnings: string[];
    metadata?: {
      ipAddress?: string;
      userAgent?: string;
    };
  };
}

/**
 * Pipeline event emitter
 */
export type PipelineEventType =
  | "stage_started"
  | "stage_completed"
  | "stage_failed"
  | "progress_updated"
  | "gate_blocked"
  | "enumeration_requested";

export interface PipelineEvent {
  type: PipelineEventType;
  stage: ScanStage;
  data: any;
  timestamp: Date;
}

/**
 * Pipeline Controller
 */
export class PipelineController {
  private config: PipelineConfig;
  private state: PipelineState;
  private confirmationGate: ConfirmationGate;
  private fingerprinter: DatabaseFingerprinter;
  private checkpointManager: CheckpointManager;
  private pacer: AdaptivePacer;
  private responseAnalyzer: ResponseAnalyzer;
  private safetyControls: SafetyControlsManager;
  private eventListeners: Map<PipelineEventType, Array<(event: PipelineEvent) => void>> = new Map();

  constructor(config: PipelineConfig) {
    this.config = config;

    // Initialize state
    this.state = {
      scanId: config.scanId,
      targetUrl: config.targetUrl,
      currentStage: ScanStage.TARGET_NORMALIZATION,
      stages: new Map(),
      createdAt: new Date(),
      updatedAt: new Date(),
      version: 1,
    };

    // Initialize components
    this.confirmationGate = new ConfirmationGate();
    this.fingerprinter = new DatabaseFingerprinter();
    this.checkpointManager = new CheckpointManager(
      new InMemoryCheckpointStorage()
    );
    this.pacer = new AdaptivePacer();
    this.responseAnalyzer = new ResponseAnalyzer();
    this.safetyControls = new SafetyControlsManager(
      config.scanId,
      config.targetUrl
    );

    // Handle user consent if provided
    if (config.enableEnumeration && config.userConsent) {
      this.safetyControls.requestEnumerationConsent(
        config.userConsent.acknowledgedWarnings,
        config.userConsent.metadata
      );
    }
  }

  /**
   * Execute complete pipeline
   */
  async execute(): Promise<PipelineState> {
    console.log(`\n🚀 Starting Pipeline for ${this.config.targetUrl}\n`);

    try {
      // Stage 1: Target Normalization
      await this.executeStage(
        ScanStage.TARGET_NORMALIZATION,
        () => this.normalizeTarget()
      );

      // Stage 2: Parameter Discovery
      await this.executeStage(
        ScanStage.PARAMETER_DISCOVERY,
        () => this.discoverParameters()
      );

      // Stage 3: Vulnerability Confirmation
      await this.executeStage(
        ScanStage.VULNERABILITY_CONFIRMATION,
        () => this.confirmVulnerability()
      );

      // Check confirmation gate
      const gateDecision = this.confirmationGate.evaluate();
      if (!gateDecision.passed) {
        this.emit("gate_blocked", ScanStage.VULNERABILITY_CONFIRMATION, {
          decision: gateDecision,
        });

        console.warn(`\n❌ Confirmation Gate BLOCKED:`);
        gateDecision.reasons.forEach(r => console.warn(`   - ${r}`));
        console.warn(`\nRecommendation: ${gateDecision.recommendation}\n`);

        return this.state;
      }

      console.log(`\n✅ Confirmation Gate PASSED\n`);

      // Stage 4: Database Fingerprinting
      await this.executeStage(
        ScanStage.DATABASE_FINGERPRINTING,
        () => this.fingerprintDatabase()
      );

      // Stage 5: Post-Confirmation Enumeration (OPT-IN)
      if (this.safetyControls.isEnumerationAllowed()) {
        await this.executeStage(
          ScanStage.POST_CONFIRMATION_ENUMERATION,
          () => this.enumerateDatabase()
        );
      } else {
        console.log(
          `\n⏭️  Skipping enumeration (not enabled or no user consent)\n`
        );
      }

      // Stage 6: Reporting
      await this.executeStage(
        ScanStage.REPORTING,
        () => this.generateReport()
      );

      console.log(`\n✨ Pipeline completed successfully\n`);
    } catch (error: any) {
      console.error(`\n💥 Pipeline failed:`, error.message);
      throw error;
    }

    return this.state;
  }

  /**
   * Execute a single pipeline stage
   */
  private async executeStage<T>(
    stage: ScanStage,
    executor: () => Promise<T>
  ): Promise<void> {
    // Check if previous stage completed
    if (!this.canProceedToStage(stage)) {
      throw new Error(
        `Cannot proceed to ${stage}: Previous stage not completed`
      );
    }

    this.state.currentStage = stage;
    this.emit("stage_started", stage, {});

    console.log(`\n📍 Stage: ${stage}`);
    console.log(`${"=".repeat(50)}`);

    const stageOutput: StageOutput<T> = {
      stage,
      status: StageStatus.IN_PROGRESS,
      data: null as any,
      confidence: ConfidenceLevel.NONE,
      errors: [],
      warnings: [],
      startTime: new Date(),
      metadata: {},
    };

    try {
      const result = await executor();

      stageOutput.data = result;
      stageOutput.status = StageStatus.COMPLETED;
      stageOutput.endTime = new Date();

      this.state.stages.set(stage, stageOutput);
      this.state.updatedAt = new Date();
      this.state.version++;

      this.emit("stage_completed", stage, { output: stageOutput });

      const duration = stageOutput.endTime.getTime() - stageOutput.startTime.getTime();
      console.log(`✅ Completed in ${duration}ms\n`);
    } catch (error: any) {
      stageOutput.status = StageStatus.FAILED;
      stageOutput.errors.push(error.message);
      stageOutput.endTime = new Date();

      this.state.stages.set(stage, stageOutput);
      this.emit("stage_failed", stage, { error: error.message });

      console.error(`❌ Failed: ${error.message}\n`);
      throw error;
    }
  }

  /**
   * Check if can proceed to stage
   */
  private canProceedToStage(stage: ScanStage): boolean {
    const stageOrder = [
      ScanStage.TARGET_NORMALIZATION,
      ScanStage.PARAMETER_DISCOVERY,
      ScanStage.VULNERABILITY_CONFIRMATION,
      ScanStage.DATABASE_FINGERPRINTING,
      ScanStage.POST_CONFIRMATION_ENUMERATION,
      ScanStage.REPORTING,
    ];

    const currentIndex = stageOrder.indexOf(stage);
    if (currentIndex === 0) return true;

    const previousStage = stageOrder[currentIndex - 1];
    const previousOutput = this.state.stages.get(previousStage);

    return previousOutput?.status === StageStatus.COMPLETED;
  }

  /**
   * Stage 1: Normalize target URL
   */
  private async normalizeTarget(): Promise<any> {
    // Placeholder implementation
    return {
      normalizedUrl: this.config.targetUrl,
      method: "GET",
      parameters: [],
    };
  }

  /**
   * Stage 2: Discover injectable parameters
   */
  private async discoverParameters(): Promise<any> {
    // Placeholder implementation
    return {
      discovered: 5,
      injectable: 2,
    };
  }

  /**
   * Stage 3: Confirm vulnerability
   */
  private async confirmVulnerability(): Promise<any> {
    // Placeholder implementation
    // In real implementation, this would run tests and add signals to confirmation gate
    return {
      confirmed: true,
      signals: 2,
    };
  }

  /**
   * Stage 4: Fingerprint database
   */
  private async fingerprintDatabase(): Promise<any> {
    // Placeholder implementation
    return {
      type: "mysql",
      version: "8.0.0",
      confidence: ConfidenceLevel.HIGH,
    };
  }

  /**
   * Stage 5: Enumerate database (OPT-IN)
   */
  private async enumerateDatabase(): Promise<any> {
    // Placeholder implementation
    return {
      databases: 5,
      tables: 20,
      columns: 100,
    };
  }

  /**
   * Stage 6: Generate report
   */
  private async generateReport(): Promise<any> {
    // Placeholder implementation
    return {
      generated: true,
      timestamp: new Date(),
    };
  }

  /**
   * Get real progress (not percentages!)
   */
  getRealProgress(): RealProgress {
    const completedStages = Array.from(this.state.stages.values()).filter(
      s => s.status === StageStatus.COMPLETED
    ).length;

    const totalStages = 6; // Fixed number of stages

    const activeStage = this.state.currentStage;
    const stageOutput = this.state.stages.get(activeStage);

    return {
      currentStage: activeStage,
      completedWorkUnits: completedStages,
      totalWorkUnits: totalStages,
      remainingWorkUnits: totalStages - completedStages,
      estimatedOperationsRemaining: (totalStages - completedStages) * 10, // Rough estimate
      lastActivity: stageOutput ? `Executing ${activeStage}` : "Idle",
      activeOperations: stageOutput?.status === StageStatus.IN_PROGRESS
        ? [activeStage]
        : [],
    };
  }

  /**
   * Get current pipeline state
   */
  getState(): PipelineState {
    return { ...this.state };
  }

  /**
   * Get safety audit trail
   */
  getAuditTrail() {
    return this.safetyControls.getAuditTrail();
  }

  /**
   * Subscribe to pipeline events
   */
  on(event: PipelineEventType, listener: (event: PipelineEvent) => void): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)!.push(listener);
  }

  /**
   * Emit pipeline event
   */
  private emit(type: PipelineEventType, stage: ScanStage, data: any): void {
    const event: PipelineEvent = {
      type,
      stage,
      data,
      timestamp: new Date(),
    };

    const listeners = this.eventListeners.get(type) || [];
    listeners.forEach(listener => listener(event));
  }
}
