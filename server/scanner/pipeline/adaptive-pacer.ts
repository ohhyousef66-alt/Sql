/**
 * Adaptive Pacing and Throttling System
 * 
 * Automatically adjusts scanning speed based on:
 * - Latency trends
 * - Error rates  
 * - Response variance
 * 
 * Prioritizes stability over raw speed.
 */

import { PacingMetrics } from "./types";

/**
 * Pacing configuration
 */
export interface PacingConfig {
  baseDelayMs: number;
  minDelayMs: number;
  maxDelayMs: number;
  errorRateThreshold: number; // 0.0 to 1.0
  latencyThresholdMs: number;
  varianceThreshold: number;
  consecutiveErrorLimit: number;
  consecutiveTimeoutLimit: number;
  adaptationFactor: number; // Multiplier for delay adjustment
}

/**
 * Response timing record
 */
interface ResponseRecord {
  timestamp: Date;
  latencyMs: number;
  success: boolean;
  error?: string;
  isTimeout: boolean;
}

/**
 * Adaptive Pacer
 */
export class AdaptivePacer {
  private config: PacingConfig;
  private currentDelayMs: number;
  private responseHistory: ResponseRecord[] = [];
  private maxHistorySize = 100;
  private consecutiveErrors = 0;
  private consecutiveTimeouts = 0;
  private pausedUntil?: Date;

  constructor(config?: Partial<PacingConfig>) {
    this.config = {
      baseDelayMs: config?.baseDelayMs ?? 1000,
      minDelayMs: config?.minDelayMs ?? 100,
      maxDelayMs: config?.maxDelayMs ?? 30000,
      errorRateThreshold: config?.errorRateThreshold ?? 0.3,
      latencyThresholdMs: config?.latencyThresholdMs ?? 5000,
      varianceThreshold: config?.varianceThreshold ?? 2000,
      consecutiveErrorLimit: config?.consecutiveErrorLimit ?? 5,
      consecutiveTimeoutLimit: config?.consecutiveTimeoutLimit ?? 3,
      adaptationFactor: config?.adaptationFactor ?? 1.5,
    };

    this.currentDelayMs = this.config.baseDelayMs;
  }

  /**
   * Record a response
   */
  recordResponse(
    latencyMs: number,
    success: boolean,
    error?: string,
    isTimeout: boolean = false
  ): void {
    const record: ResponseRecord = {
      timestamp: new Date(),
      latencyMs,
      success,
      error,
      isTimeout,
    };

    this.responseHistory.push(record);

    // Keep history size limited
    if (this.responseHistory.length > this.maxHistorySize) {
      this.responseHistory.shift();
    }

    // Track consecutive failures
    if (!success) {
      this.consecutiveErrors++;
      if (isTimeout) {
        this.consecutiveTimeouts++;
      }
    } else {
      this.consecutiveErrors = 0;
      this.consecutiveTimeouts = 0;
    }

    // Adapt pacing based on metrics
    this.adapt();
  }

  /**
   * Adapt pacing based on current metrics
   */
  private adapt(): void {
    const metrics = this.calculateMetrics();

    // Check for pause conditions
    if (metrics.shouldPause) {
      this.pause();
      return;
    }

    // Check for throttling
    if (metrics.shouldThrottle) {
      this.increaseDelay();
    } else if (this.isStable()) {
      this.decreaseDelay();
    }
  }

  /**
   * Calculate current pacing metrics
   */
  calculateMetrics(): PacingMetrics {
    if (this.responseHistory.length === 0) {
      return {
        averageLatencyMs: 0,
        errorRate: 0,
        responseVariance: 0,
        consecutiveErrors: 0,
        consecutiveTimeouts: 0,
        suggestedDelayMs: this.currentDelayMs,
        shouldThrottle: false,
        shouldPause: false,
      };
    }

    // Calculate average latency
    const latencies = this.responseHistory.map(r => r.latencyMs);
    const avgLatency =
      latencies.reduce((a, b) => a + b, 0) / latencies.length;

    // Calculate variance
    const variance =
      latencies.reduce((sum, val) => sum + Math.pow(val - avgLatency, 2), 0) /
      latencies.length;

    // Calculate error rate
    const errors = this.responseHistory.filter(r => !r.success).length;
    const errorRate = errors / this.responseHistory.length;

    // Determine if we should throttle
    const shouldThrottle =
      errorRate > this.config.errorRateThreshold ||
      avgLatency > this.config.latencyThresholdMs ||
      variance > this.config.varianceThreshold;

    // Determine if we should pause
    const shouldPause =
      this.consecutiveErrors >= this.config.consecutiveErrorLimit ||
      this.consecutiveTimeouts >= this.config.consecutiveTimeoutLimit;

    return {
      averageLatencyMs: Math.round(avgLatency),
      errorRate: Math.round(errorRate * 100) / 100,
      responseVariance: Math.round(variance),
      consecutiveErrors: this.consecutiveErrors,
      consecutiveTimeouts: this.consecutiveTimeouts,
      suggestedDelayMs: this.currentDelayMs,
      shouldThrottle,
      shouldPause,
    };
  }

  /**
   * Increase delay (throttle)
   */
  private increaseDelay(): void {
    const newDelay = Math.min(
      this.currentDelayMs * this.config.adaptationFactor,
      this.config.maxDelayMs
    );

    if (newDelay !== this.currentDelayMs) {
      console.log(
        `🐢 Throttling: Increasing delay from ${this.currentDelayMs}ms to ${newDelay}ms`
      );
      this.currentDelayMs = newDelay;
    }
  }

  /**
   * Decrease delay (speed up)
   */
  private decreaseDelay(): void {
    const newDelay = Math.max(
      this.currentDelayMs / this.config.adaptationFactor,
      this.config.minDelayMs
    );

    if (newDelay !== this.currentDelayMs) {
      console.log(
        `🐇 Speeding up: Decreasing delay from ${this.currentDelayMs}ms to ${newDelay}ms`
      );
      this.currentDelayMs = newDelay;
    }
  }

  /**
   * Pause scanning temporarily
   */
  private pause(): void {
    const pauseDurationMs = Math.min(
      this.currentDelayMs * 10,
      60000 // Max 1 minute pause
    );

    this.pausedUntil = new Date(Date.now() + pauseDurationMs);

    console.warn(
      `⏸️  Pausing for ${pauseDurationMs}ms due to consecutive errors/timeouts`
    );
  }

  /**
   * Check if system is stable
   */
  private isStable(): boolean {
    const recentHistory = this.responseHistory.slice(-10);
    if (recentHistory.length < 10) return false;

    const recentErrors = recentHistory.filter(r => !r.success).length;
    return recentErrors === 0;
  }

  /**
   * Wait based on current pacing
   */
  async wait(): Promise<void> {
    // Check if paused
    if (this.pausedUntil && new Date() < this.pausedUntil) {
      const remainingPauseMs = this.pausedUntil.getTime() - Date.now();
      await new Promise(resolve => setTimeout(resolve, remainingPauseMs));
      this.pausedUntil = undefined;
      
      // Reset consecutive counters after pause
      this.consecutiveErrors = 0;
      this.consecutiveTimeouts = 0;
      
      console.log("▶️  Resuming after pause");
    }

    // Normal delay
    await new Promise(resolve => setTimeout(resolve, this.currentDelayMs));
  }

  /**
   * Get current delay
   */
  getCurrentDelay(): number {
    return this.currentDelayMs;
  }

  /**
   * Check if currently paused
   */
  isPaused(): boolean {
    return this.pausedUntil !== undefined && new Date() < this.pausedUntil;
  }

  /**
   * Reset pacer state
   */
  reset(): void {
    this.currentDelayMs = this.config.baseDelayMs;
    this.responseHistory = [];
    this.consecutiveErrors = 0;
    this.consecutiveTimeouts = 0;
    this.pausedUntil = undefined;
  }

  /**
   * Get configuration
   */
  getConfig(): PacingConfig {
    return { ...this.config };
  }
}
