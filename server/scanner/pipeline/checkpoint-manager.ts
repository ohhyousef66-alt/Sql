/**
 * Checkpointing System for Resumable Operations
 * 
 * Persists enumeration progress at granular level to allow safe resume
 * after interruption without starting from scratch.
 */

import {
  EnumerationPhase,
  EnumerationCheckpoint,
} from "./types";

/**
 * Checkpoint storage interface
 */
export interface CheckpointStorage {
  save(scanId: string, checkpoint: EnumerationCheckpoint): Promise<void>;
  load(scanId: string): Promise<EnumerationCheckpoint | null>;
  delete(scanId: string): Promise<void>;
  exists(scanId: string): Promise<boolean>;
}

/**
 * In-memory checkpoint storage (for testing/development)
 */
export class InMemoryCheckpointStorage implements CheckpointStorage {
  private checkpoints = new Map<string, EnumerationCheckpoint>();

  async save(scanId: string, checkpoint: EnumerationCheckpoint): Promise<void> {
    this.checkpoints.set(scanId, { ...checkpoint });
  }

  async load(scanId: string): Promise<EnumerationCheckpoint | null> {
    const checkpoint = this.checkpoints.get(scanId);
    return checkpoint ? { ...checkpoint } : null;
  }

  async delete(scanId: string): Promise<void> {
    this.checkpoints.delete(scanId);
  }

  async exists(scanId: string): Promise<boolean> {
    return this.checkpoints.has(scanId);
  }
}

/**
 * Checkpoint manager for resumable operations
 */
export class CheckpointManager {
  private storage: CheckpointStorage;
  private autoSaveIntervalMs: number;
  private autoSaveTimer?: NodeJS.Timeout;
  private currentCheckpoint?: EnumerationCheckpoint;
  private currentScanId?: string;

  constructor(
    storage: CheckpointStorage,
    autoSaveIntervalMs: number = 5000 // Auto-save every 5 seconds
  ) {
    this.storage = storage;
    this.autoSaveIntervalMs = autoSaveIntervalMs;
  }

  /**
   * Initialize checkpoint for a scan
   */
  async initialize(scanId: string, phase: EnumerationPhase): Promise<void> {
    this.currentScanId = scanId;

    // Try to load existing checkpoint
    const existing = await this.storage.load(scanId);

    if (existing) {
      this.currentCheckpoint = existing;
      console.log(`📂 Resumed from checkpoint: ${phase} phase`);
    } else {
      this.currentCheckpoint = {
        phase,
        completedDatabases: [],
        completedTables: [],
        completedColumns: [],
        retryCount: 0,
        timestamp: new Date(),
      };
      await this.save();
      console.log(`📝 Created new checkpoint: ${phase} phase`);
    }

    // Start auto-save
    this.startAutoSave();
  }

  /**
   * Update checkpoint with progress
   */
  update(updates: Partial<EnumerationCheckpoint>): void {
    if (!this.currentCheckpoint) {
      throw new Error("Checkpoint not initialized");
    }

    this.currentCheckpoint = {
      ...this.currentCheckpoint,
      ...updates,
      timestamp: new Date(),
    };
  }

  /**
   * Mark database as completed
   */
  markDatabaseCompleted(database: string): void {
    if (!this.currentCheckpoint) return;

    if (!this.currentCheckpoint.completedDatabases.includes(database)) {
      this.currentCheckpoint.completedDatabases.push(database);
      this.currentCheckpoint.timestamp = new Date();
    }
  }

  /**
   * Mark table as completed
   */
  markTableCompleted(table: string): void {
    if (!this.currentCheckpoint) return;

    if (!this.currentCheckpoint.completedTables.includes(table)) {
      this.currentCheckpoint.completedTables.push(table);
      this.currentCheckpoint.timestamp = new Date();
    }
  }

  /**
   * Mark column as completed
   */
  markColumnCompleted(column: string): void {
    if (!this.currentCheckpoint) return;

    if (!this.currentCheckpoint.completedColumns.includes(column)) {
      this.currentCheckpoint.completedColumns.push(column);
      this.currentCheckpoint.timestamp = new Date();
    }
  }

  /**
   * Check if database already completed
   */
  isDatabaseCompleted(database: string): boolean {
    return this.currentCheckpoint?.completedDatabases.includes(database) ?? false;
  }

  /**
   * Check if table already completed
   */
  isTableCompleted(table: string): boolean {
    return this.currentCheckpoint?.completedTables.includes(table) ?? false;
  }

  /**
   * Check if column already completed
   */
  isColumnCompleted(column: string): boolean {
    return this.currentCheckpoint?.completedColumns.includes(column) ?? false;
  }

  /**
   * Increment retry count
   */
  incrementRetry(): number {
    if (!this.currentCheckpoint) return 0;

    this.currentCheckpoint.retryCount++;
    this.currentCheckpoint.timestamp = new Date();
    return this.currentCheckpoint.retryCount;
  }

  /**
   * Reset retry count
   */
  resetRetry(): void {
    if (this.currentCheckpoint) {
      this.currentCheckpoint.retryCount = 0;
    }
  }

  /**
   * Manually save checkpoint
   */
  async save(): Promise<void> {
    if (!this.currentScanId || !this.currentCheckpoint) return;
    await this.storage.save(this.currentScanId, this.currentCheckpoint);
  }

  /**
   * Get current checkpoint
   */
  getCurrent(): EnumerationCheckpoint | undefined {
    return this.currentCheckpoint ? { ...this.currentCheckpoint } : undefined;
  }

  /**
   * Clear checkpoint
   */
  async clear(): Promise<void> {
    this.stopAutoSave();

    if (this.currentScanId) {
      await this.storage.delete(this.currentScanId);
    }

    this.currentCheckpoint = undefined;
    this.currentScanId = undefined;
  }

  /**
   * Start auto-save timer
   */
  private startAutoSave(): void {
    this.stopAutoSave();

    this.autoSaveTimer = setInterval(async () => {
      try {
        await this.save();
      } catch (error) {
        console.error("Auto-save failed:", error);
      }
    }, this.autoSaveIntervalMs);
  }

  /**
   * Stop auto-save timer
   */
  private stopAutoSave(): void {
    if (this.autoSaveTimer) {
      clearInterval(this.autoSaveTimer);
      this.autoSaveTimer = undefined;
    }
  }

  /**
   * Calculate progress statistics
   */
  getProgress(): {
    completedDatabases: number;
    completedTables: number;
    completedColumns: number;
    retryCount: number;
    lastUpdate: Date;
  } {
    if (!this.currentCheckpoint) {
      return {
        completedDatabases: 0,
        completedTables: 0,
        completedColumns: 0,
        retryCount: 0,
        lastUpdate: new Date(),
      };
    }

    return {
      completedDatabases: this.currentCheckpoint.completedDatabases.length,
      completedTables: this.currentCheckpoint.completedTables.length,
      completedColumns: this.currentCheckpoint.completedColumns.length,
      retryCount: this.currentCheckpoint.retryCount,
      lastUpdate: this.currentCheckpoint.timestamp,
    };
  }
}
