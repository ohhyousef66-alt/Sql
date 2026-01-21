/**
 * Confirmation Gate - Anti-False-Positive System
 * 
 * Enforces strict confirmation requirements before allowing enumeration.
 * Requires multiple independent confirmation signals with high confidence.
 */

import {
  ConfirmationSignal,
  ConfidenceLevel,
  InjectionTechnique,
} from "./types";

/**
 * Configuration for confirmation gate
 */
export interface ConfirmationGateConfig {
  minimumSignals: number; // Default: 2
  minimumConfidence: ConfidenceLevel; // Default: HIGH (75)
  requireDifferentTechniques: boolean; // Default: true
  requireDifferentEvidenceTypes: boolean; // Default: true
  timeWindowMs: number; // Signals must be within this window
}

/**
 * Confirmation gate decision
 */
export interface ConfirmationDecision {
  passed: boolean;
  confidence: ConfidenceLevel;
  signals: ConfirmationSignal[];
  reasons: string[];
  recommendation: "proceed" | "collect_more_signals" | "reject";
}

/**
 * Confirmation Gate implementation
 */
export class ConfirmationGate {
  private config: ConfirmationGateConfig;
  private signals: ConfirmationSignal[] = [];

  constructor(config?: Partial<ConfirmationGateConfig>) {
    this.config = {
      minimumSignals: config?.minimumSignals ?? 2,
      minimumConfidence: config?.minimumConfidence ?? ConfidenceLevel.HIGH,
      requireDifferentTechniques: config?.requireDifferentTechniques ?? true,
      requireDifferentEvidenceTypes: config?.requireDifferentEvidenceTypes ?? true,
      timeWindowMs: config?.timeWindowMs ?? 60000, // 1 minute
    };
  }

  /**
   * Add a confirmation signal
   */
  addSignal(signal: ConfirmationSignal): void {
    // Remove old signals outside time window
    const cutoffTime = new Date(Date.now() - this.config.timeWindowMs);
    this.signals = this.signals.filter(s => s.timestamp >= cutoffTime);

    // Add new signal
    this.signals.push(signal);
  }

  /**
   * Evaluate if gate passes
   */
  evaluate(): ConfirmationDecision {
    const reasons: string[] = [];
    
    // Check minimum signals
    if (this.signals.length < this.config.minimumSignals) {
      reasons.push(
        `Insufficient signals: ${this.signals.length}/${this.config.minimumSignals}`
      );
      return {
        passed: false,
        confidence: this.calculateOverallConfidence(),
        signals: this.signals,
        reasons,
        recommendation: "collect_more_signals",
      };
    }

    // Check technique diversity
    if (this.config.requireDifferentTechniques) {
      const techniques = new Set(this.signals.map(s => s.technique));
      if (techniques.size < 2) {
        reasons.push(
          `Insufficient technique diversity: ${techniques.size} unique techniques`
        );
        return {
          passed: false,
          confidence: this.calculateOverallConfidence(),
          signals: this.signals,
          reasons,
          recommendation: "collect_more_signals",
        };
      }
    }

    // Check evidence type diversity
    if (this.config.requireDifferentEvidenceTypes) {
      const evidenceTypes = new Set(this.signals.map(s => s.evidenceType));
      if (evidenceTypes.size < 2) {
        reasons.push(
          `Insufficient evidence diversity: ${evidenceTypes.size} unique evidence types`
        );
        return {
          passed: false,
          confidence: this.calculateOverallConfidence(),
          signals: this.signals,
          reasons,
          recommendation: "collect_more_signals",
        };
      }
    }

    // Check overall confidence
    const overallConfidence = this.calculateOverallConfidence();
    if (overallConfidence < this.config.minimumConfidence) {
      reasons.push(
        `Insufficient confidence: ${overallConfidence}/${this.config.minimumConfidence}`
      );
      return {
        passed: false,
        confidence: overallConfidence,
        signals: this.signals,
        reasons,
        recommendation: "reject",
      };
    }

    // All checks passed
    reasons.push("All confirmation requirements met");
    reasons.push(`${this.signals.length} independent signals collected`);
    reasons.push(`Overall confidence: ${overallConfidence}`);

    return {
      passed: true,
      confidence: overallConfidence,
      signals: this.signals,
      reasons,
      recommendation: "proceed",
    };
  }

  /**
   * Calculate weighted confidence score
   */
  private calculateOverallConfidence(): ConfidenceLevel {
    if (this.signals.length === 0) {
      return ConfidenceLevel.NONE;
    }

    // Weight by evidence quality
    const weights: Record<string, number> = {
      error_message: 1.2,
      union_data: 1.5,
      boolean_behavior: 1.0,
      time_delay: 0.8,
      structural_change: 0.9,
    };

    let weightedSum = 0;
    let totalWeight = 0;

    for (const signal of this.signals) {
      const weight = weights[signal.evidenceType] || 1.0;
      weightedSum += signal.confidence * weight;
      totalWeight += weight;
    }

    const avgConfidence = Math.round(weightedSum / totalWeight);
    
    // Cap at CONFIRMED
    return Math.min(avgConfidence, ConfidenceLevel.CONFIRMED) as ConfidenceLevel;
  }

  /**
   * Reset gate state
   */
  reset(): void {
    this.signals = [];
  }

  /**
   * Get current signals
   */
  getSignals(): ConfirmationSignal[] {
    return [...this.signals];
  }

  /**
   * Get gate configuration
   */
  getConfig(): ConfirmationGateConfig {
    return { ...this.config };
  }
}
