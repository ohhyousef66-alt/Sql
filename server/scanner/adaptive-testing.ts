import { makeRequest, RequestResult, sleep, hashString } from "./utils";
import { globalPayloadRepository, Payload, PayloadCategory } from "./payload-repository";

export interface HeuristicProbeResult {
  parameterName: string;
  hasDifferentialBehavior: boolean;
  responseTimeDeviation: number;
  statusCodeChanged: boolean;
  sizeDeviation: number;
  domStructureChanged: boolean;
  errorPatternsFound: string[];
  shouldEscalate: boolean;
  confidence: number;
  evidence: string;
}

export interface AdaptiveDecision {
  action: "skip" | "probe_further" | "deep_dive";
  reason: string;
  confidence: number;
  estimatedPayloads: number;
}

export interface PayloadSuccessRecord {
  payloadHash: string;
  category: string;
  successCount: number;
  totalAttempts: number;
  lastUsed: Date;
  avgConfidence: number;
}

export interface ConcurrencyMetrics {
  currentConcurrency: number;
  successRate: number;
  errorRate: number;
  rateLimitHits: number;
  serverOverloads: number;
  adjustmentHistory: { time: Date; from: number; to: number; reason: string }[];
}

const POLYGLOT_PROBES = [
  `'||(SELECT 1)--`,
  `1' OR '1'='1`,
  `" OR ""="`,
  `1; SELECT 1--`,
  `1) OR (1=1`,
  `' AND SLEEP(0)--`,
  `1 UNION SELECT NULL--`,
  `'; WAITFOR DELAY '0:0:0'--`,
];

const PROBE_CATEGORIES = {
  string: [`'`, `"`, `''`, `""`],
  numeric: [`1`, `0`, `-1`, `999999999`],
  bracket: [`(`, `)`, `((`, `))`],
  comment: [`--`, `#`, `/**/`, `-- -`],
  time: [`SLEEP(0)`, `pg_sleep(0)`, `WAITFOR DELAY '0:0:0'`],
};

export class AdaptiveTestingEngine {
  private onLog: (level: string, message: string) => Promise<void>;
  private isCancelled: () => boolean;
  private abortSignal?: AbortSignal;
  private onSkipParameter?: () => void;
  
  private concurrencyMetrics: ConcurrencyMetrics = {
    currentConcurrency: 10,
    successRate: 100,
    errorRate: 0,
    rateLimitHits: 0,
    serverOverloads: 0,
    adjustmentHistory: [],
  };
  
  private payloadSuccessHistory: Map<string, PayloadSuccessRecord> = new Map();
  private parameterHeuristicCache: Map<string, HeuristicProbeResult> = new Map();
  
  private maxConcurrency = 100;  // FIXED: Hard limit to prevent explosion
  private minConcurrency = 1;
  private recentErrors: { time: number; code: number }[] = [];
  private recentSuccesses = 0;
  private totalRequests = 0;
  
  constructor(
    onLog: (level: string, message: string) => Promise<void>,
    isCancelled: () => boolean,
    abortSignal?: AbortSignal,
    initialConcurrency: number = 10,
    onSkipParameter?: () => void
  ) {
    this.onLog = onLog;
    this.isCancelled = isCancelled;
    this.abortSignal = abortSignal;
    this.concurrencyMetrics.currentConcurrency = Math.max(1, Math.min(100, initialConcurrency));
    this.onSkipParameter = onSkipParameter;
  }
  
  setOnSkipParameter(callback: () => void): void {
    this.onSkipParameter = callback;
  }

  async runHeuristicProbe(
    url: string,
    paramName: string,
    originalValue: string,
    baselineResponse: RequestResult
  ): Promise<HeuristicProbeResult> {
    const cacheKey = `${url}:${paramName}`;
    
    if (this.parameterHeuristicCache.has(cacheKey)) {
      return this.parameterHeuristicCache.get(cacheKey)!;
    }
    
    const result: HeuristicProbeResult = {
      parameterName: paramName,
      hasDifferentialBehavior: false,
      responseTimeDeviation: 0,
      statusCodeChanged: false,
      sizeDeviation: 0,
      domStructureChanged: false,
      errorPatternsFound: [],
      shouldEscalate: false,
      confidence: 0,
      evidence: "",
    };
    
    const evidenceParts: string[] = [];
    const probePayloads = this.selectRepresentativeProbes();
    
    let deviationCount = 0;
    const responseTimes: number[] = [baselineResponse.responseTime || 0];
    
    for (const probe of probePayloads) {
      if (this.isCancelled() || this.abortSignal?.aborted) break;
      
      const injectedUrl = this.injectPayload(url, paramName, originalValue, probe);
      const probeResponse = await makeRequest(injectedUrl, { 
        signal: this.abortSignal,
        timeout: 10000 
      });
      
      this.trackRequestOutcome(probeResponse);
      
      if (probeResponse.error) continue;
      
      responseTimes.push(probeResponse.responseTime || 0);
      
      if (probeResponse.status !== baselineResponse.status) {
        result.statusCodeChanged = true;
        deviationCount++;
        evidenceParts.push(`Status changed: ${baselineResponse.status} -> ${probeResponse.status}`);
      }
      
      const sizeDiff = Math.abs((probeResponse.body?.length || 0) - (baselineResponse.body?.length || 0));
      const sizeRatio = sizeDiff / Math.max(baselineResponse.body?.length || 1, 1);
      if (sizeRatio > 0.1) {
        result.sizeDeviation = sizeRatio;
        deviationCount++;
        evidenceParts.push(`Size deviation: ${(sizeRatio * 100).toFixed(1)}%`);
      }
      
      const errorPatterns = this.detectErrorPatterns(probeResponse.body || "");
      if (errorPatterns.length > 0) {
        result.errorPatternsFound.push(...errorPatterns);
        deviationCount++;
        evidenceParts.push(`Errors: ${errorPatterns.slice(0, 2).join(", ")}`);
      }
      
      const bodyHashBase = hashString(this.normalizeHtml(baselineResponse.body || ""));
      const bodyHashProbe = hashString(this.normalizeHtml(probeResponse.body || ""));
      if (bodyHashBase !== bodyHashProbe) {
        result.domStructureChanged = true;
        deviationCount++;
      }
    }
    
    const avgTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    const baseTime = baselineResponse.responseTime || avgTime;
    result.responseTimeDeviation = Math.abs(avgTime - baseTime) / Math.max(baseTime, 1);
    
    result.hasDifferentialBehavior = deviationCount >= 2;
    result.confidence = Math.min(100, deviationCount * 25);
    result.shouldEscalate = result.hasDifferentialBehavior || result.errorPatternsFound.length > 0;
    result.evidence = evidenceParts.join("; ");
    
    this.parameterHeuristicCache.set(cacheKey, result);
    
    await this.onLog("debug", 
      `[Adaptive] Heuristic probe for ${paramName}: escalate=${result.shouldEscalate}, ` +
      `deviations=${deviationCount}, confidence=${result.confidence}%`
    );
    
    return result;
  }

  makeAdaptiveDecision(probeResult: HeuristicProbeResult): AdaptiveDecision {
    if (!probeResult.hasDifferentialBehavior && 
        probeResult.errorPatternsFound.length === 0 &&
        probeResult.responseTimeDeviation < 0.2 &&
        !probeResult.statusCodeChanged) {
      return {
        action: "skip",
        reason: "Zero deviation detected - parameter appears secure",
        confidence: 95 - probeResult.confidence,
        estimatedPayloads: 0,
      };
    }
    
    if (probeResult.errorPatternsFound.length > 0 || probeResult.confidence >= 50) {
      return {
        action: "deep_dive",
        reason: `High-confidence indicators: ${probeResult.evidence || "differential behavior detected"}`,
        confidence: probeResult.confidence,
        estimatedPayloads: 200,
      };
    }
    
    return {
      action: "probe_further",
      reason: "Moderate indicators - additional probing recommended",
      confidence: probeResult.confidence,
      estimatedPayloads: 50,
    };
  }

  getPrioritizedPayloads(category: PayloadCategory, limit: number = 100): Payload[] {
    const allPayloads = globalPayloadRepository.getPayloadsByCategory(category);
    
    const scoredPayloads = allPayloads.map(payload => {
      const hash = hashString(payload.template);
      const record = this.payloadSuccessHistory.get(hash);
      
      let score = 50;
      
      if (record) {
        const successRate = record.totalAttempts > 0 
          ? (record.successCount / record.totalAttempts) * 100 
          : 50;
        score = successRate * 0.6 + record.avgConfidence * 0.4;
        
        const daysSinceUse = (Date.now() - record.lastUsed.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceUse < 1) score *= 1.2;
      }
      
      const highRiskCategories: PayloadCategory[] = ["error_based", "time_based", "union_discovery"];
      if (highRiskCategories.includes(payload.category)) score *= 1.3;
      
      return { payload, score };
    });
    
    scoredPayloads.sort((a, b) => b.score - a.score);
    
    return scoredPayloads.slice(0, limit).map(s => s.payload);
  }

  recordPayloadResult(payloadTemplate: string, category: string, success: boolean, confidence: number): void {
    const hash = hashString(payloadTemplate);
    
    const existing = this.payloadSuccessHistory.get(hash) || {
      payloadHash: hash,
      category,
      successCount: 0,
      totalAttempts: 0,
      lastUsed: new Date(),
      avgConfidence: 0,
    };
    
    existing.totalAttempts++;
    if (success) existing.successCount++;
    existing.lastUsed = new Date();
    existing.avgConfidence = (existing.avgConfidence * (existing.totalAttempts - 1) + confidence) / existing.totalAttempts;
    
    this.payloadSuccessHistory.set(hash, existing);
  }

  getCurrentConcurrency(): number {
    return this.concurrencyMetrics.currentConcurrency;
  }

  getConcurrencyMetrics(): ConcurrencyMetrics {
    return { ...this.concurrencyMetrics };
  }
  
  getMetricsForUI(): {
    concurrency: number;
    successRate: number;
  } {
    return {
      concurrency: this.concurrencyMetrics.currentConcurrency,
      successRate: this.concurrencyMetrics.successRate,
    };
  }
  
  trackResponse(response: RequestResult): void {
    this.trackRequestOutcome(response);
  }

  private trackRequestOutcome(response: RequestResult): void {
    this.totalRequests++;
    const now = Date.now();
    
    this.recentErrors = this.recentErrors.filter(e => now - e.time < 10000);
    
    if (response.error || response.status === 0) {
      this.recentErrors.push({ time: now, code: 0 });
    } else if (response.status === 429) {
      this.recentErrors.push({ time: now, code: 429 });
      this.concurrencyMetrics.rateLimitHits++;
    } else if (response.status >= 500 && response.status < 600) {
      this.recentErrors.push({ time: now, code: response.status });
      if (response.status === 503) {
        this.concurrencyMetrics.serverOverloads++;
      }
    } else if (response.status >= 200 && response.status < 400) {
      this.recentSuccesses++;
    }
    
    this.adjustConcurrency();
  }

  private adjustConcurrency(): void {
    const windowMs = 10000;
    const recentErrorCount = this.recentErrors.length;
    const recentRateLimits = this.recentErrors.filter(e => e.code === 429).length;
    const recent503s = this.recentErrors.filter(e => e.code === 503).length;
    
    const oldConcurrency = this.concurrencyMetrics.currentConcurrency;
    let newConcurrency = oldConcurrency;
    let reason = "";
    
    if (recentRateLimits >= 3 || recent503s >= 2) {
      newConcurrency = Math.max(this.minConcurrency, Math.floor(oldConcurrency * 0.5));
      reason = `Heavy throttling: ${recentRateLimits} rate limits, ${recent503s} overloads`;
    } else if (recentRateLimits >= 1 || recent503s >= 1) {
      newConcurrency = Math.max(this.minConcurrency, Math.floor(oldConcurrency * 0.75));
      reason = `Moderate throttling: ${recentRateLimits} rate limits, ${recent503s} overloads`;
    } else if (recentErrorCount === 0 && this.totalRequests > 50) {
      if (this.recentSuccesses >= 20) {
        newConcurrency = Math.min(this.maxConcurrency, Math.ceil(oldConcurrency * 1.25));
        reason = "Scaling up: 100% success rate";
        this.recentSuccesses = 0;
      }
    }
    
    if (newConcurrency !== oldConcurrency) {
      this.concurrencyMetrics.currentConcurrency = newConcurrency;
      this.concurrencyMetrics.adjustmentHistory.push({
        time: new Date(),
        from: oldConcurrency,
        to: newConcurrency,
        reason,
      });
      
      this.onLog("info", `[Adaptive] Concurrency adjusted: ${oldConcurrency} -> ${newConcurrency} (${reason})`);
    }
    
    this.concurrencyMetrics.successRate = this.totalRequests > 0 
      ? ((this.totalRequests - this.recentErrors.filter(e => Date.now() - e.time < windowMs).length) / this.totalRequests) * 100
      : 100;
    this.concurrencyMetrics.errorRate = 100 - this.concurrencyMetrics.successRate;
  }

  private selectRepresentativeProbes(): string[] {
    const probes: string[] = [];
    
    probes.push(PROBE_CATEGORIES.string[0], PROBE_CATEGORIES.string[1]);
    probes.push(PROBE_CATEGORIES.numeric[0], PROBE_CATEGORIES.numeric[2]);
    probes.push(PROBE_CATEGORIES.bracket[0], PROBE_CATEGORIES.bracket[1]);
    probes.push(POLYGLOT_PROBES[0], POLYGLOT_PROBES[1], POLYGLOT_PROBES[4]);
    
    return probes;
  }

  private injectPayload(url: string, paramName: string, originalValue: string, payload: string): string {
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.set(paramName, originalValue + payload);
      return urlObj.toString();
    } catch {
      return url.replace(
        new RegExp(`([?&])${paramName}=[^&]*`),
        `$1${paramName}=${encodeURIComponent(originalValue + payload)}`
      );
    }
  }

  private detectErrorPatterns(body: string): string[] {
    const patterns: string[] = [];
    const lowerBody = body.toLowerCase();
    
    const errorIndicators = [
      { pattern: /sql\s*syntax/i, name: "SQL syntax error" },
      { pattern: /mysql.*error/i, name: "MySQL error" },
      { pattern: /postgresql.*error/i, name: "PostgreSQL error" },
      { pattern: /ora-\d{5}/i, name: "Oracle error" },
      { pattern: /microsoft.*odbc/i, name: "MSSQL ODBC error" },
      { pattern: /sqlite.*error/i, name: "SQLite error" },
      { pattern: /warning.*mysql/i, name: "MySQL warning" },
      { pattern: /unclosed\s*quotation/i, name: "Unclosed quotation" },
      { pattern: /quoted\s*string\s*not\s*properly\s*terminated/i, name: "String not terminated" },
      { pattern: /you\s*have\s*an\s*error\s*in\s*your\s*sql/i, name: "SQL error message" },
    ];
    
    for (const indicator of errorIndicators) {
      if (indicator.pattern.test(body)) {
        patterns.push(indicator.name);
      }
    }
    
    return patterns;
  }

  private normalizeHtml(html: string): string {
    return html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
      .replace(/<!--[\s\S]*?-->/g, "")
      .replace(/\s+/g, " ")
      .replace(/>\s+</g, "><")
      .trim();
  }

  shouldEarlyExit(paramName: string, confirmations: number, confidence: number): boolean {
    return confidence >= 100 && confirmations >= 2;
  }

  async processParametersAdaptively(
    parameters: { url: string; name: string; value: string; baseline: RequestResult }[],
    onTestParameter: (url: string, paramName: string, escalationLevel: "skip" | "probe_further" | "deep_dive") => Promise<boolean>
  ): Promise<{ tested: number; skipped: number; vulnerable: number }> {
    const stats = { tested: 0, skipped: 0, vulnerable: 0 };
    
    for (const param of parameters) {
      if (this.isCancelled() || this.abortSignal?.aborted) break;
      
      const probeResult = await this.runHeuristicProbe(
        param.url,
        param.name,
        param.value,
        param.baseline
      );
      
      const decision = this.makeAdaptiveDecision(probeResult);
      
      await this.onLog("debug", 
        `[Adaptive] ${param.name}: decision=${decision.action}, ` +
        `confidence=${decision.confidence}%, reason=${decision.reason}`
      );
      
      if (decision.action === "skip") {
        stats.skipped++;
        await this.onLog("info", `[Adaptive] Skipping ${param.name} - zero deviation (saving ${decision.estimatedPayloads || 100} payloads)`);
        if (this.onSkipParameter) {
          this.onSkipParameter();
        }
        continue;
      }
      
      stats.tested++;
      const isVulnerable = await onTestParameter(param.url, param.name, decision.action);
      
      if (isVulnerable) {
        stats.vulnerable++;
      }
    }
    
    return stats;
  }

  getAdaptiveStats(): {
    cacheHitRate: number;
    avgConcurrency: number;
    totalAdjustments: number;
    parametersSkipped: number;
  } {
    const adjustments = this.concurrencyMetrics.adjustmentHistory;
    const avgConcurrency = adjustments.length > 0
      ? adjustments.reduce((sum, a) => sum + a.to, this.concurrencyMetrics.currentConcurrency) / (adjustments.length + 1)
      : this.concurrencyMetrics.currentConcurrency;
    
    return {
      cacheHitRate: 0,
      avgConcurrency,
      totalAdjustments: adjustments.length,
      parametersSkipped: 0,
    };
  }
}

export class ResourceOptimizer {
  private blockedResourceTypes = ["image", "font", "stylesheet", "media"];
  private blockedDomains = [
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.com",
    "twitter.com",
    "doubleclick.net",
    "googlesyndication.com",
    "hotjar.com",
    "clarity.ms",
    "segment.io",
    "mixpanel.com",
  ];

  getPlaywrightResourceBlocker(): (route: { request: () => { resourceType: () => string; url: () => string }; abort: () => void; continue: () => void }) => void {
    return (route) => {
      const request = route.request();
      const resourceType = request.resourceType();
      const url = request.url();
      
      if (this.blockedResourceTypes.includes(resourceType)) {
        route.abort();
        return;
      }
      
      for (const domain of this.blockedDomains) {
        if (url.includes(domain)) {
          route.abort();
          return;
        }
      }
      
      route.continue();
    };
  }

  shouldUseHeadlessMode(url: string, hasJavaScript: boolean): boolean {
    if (!hasJavaScript) return false;
    
    const simplePatterns = [
      /\.json$/i,
      /\.xml$/i,
      /\.txt$/i,
      /api\//i,
      /rest\//i,
    ];
    
    return !simplePatterns.some(p => p.test(url));
  }
}

export interface DynamicProgressMetrics {
  workQueueSize: number;
  completedTasks: number;
  totalEstimatedTasks: number;
  coveragePerHour: number;
  estimatedTimeRemaining: number;
  currentPhase: string;
  parametersRemaining: number;
  urlsRemaining: number;
}

export class DynamicProgressTracker {
  private startTime: number = Date.now();
  private completedTasks = 0;
  private totalTasks = 0;
  private workQueue: Set<string> = new Set();
  private completedUrls: Set<string> = new Set();
  private completedParams: Set<string> = new Set();
  private currentPhase = "initializing";
  
  addToQueue(itemId: string): void {
    this.workQueue.add(itemId);
    this.totalTasks++;
  }
  
  removeFromQueue(itemId: string): void {
    this.workQueue.delete(itemId);
  }
  
  markCompleted(itemId: string): void {
    this.workQueue.delete(itemId);
    this.completedTasks++;
    
    if (itemId.startsWith("url:")) {
      this.completedUrls.add(itemId);
    } else if (itemId.startsWith("param:")) {
      this.completedParams.add(itemId);
    }
  }
  
  setPhase(phase: string): void {
    this.currentPhase = phase;
  }
  
  getProgress(): DynamicProgressMetrics {
    const elapsedMs = Date.now() - this.startTime;
    const elapsedHours = elapsedMs / (1000 * 60 * 60);
    
    const coveragePerHour = elapsedHours > 0 
      ? this.completedTasks / elapsedHours 
      : 0;
    
    const remainingTasks = this.workQueue.size;
    const estimatedTimeRemaining = coveragePerHour > 0 
      ? (remainingTasks / coveragePerHour) * 60 * 60 * 1000 
      : 0;
    
    return {
      workQueueSize: this.workQueue.size,
      completedTasks: this.completedTasks,
      totalEstimatedTasks: Math.max(this.totalTasks, this.completedTasks + this.workQueue.size),
      coveragePerHour,
      estimatedTimeRemaining,
      currentPhase: this.currentPhase,
      parametersRemaining: Array.from(this.workQueue).filter(id => id.startsWith("param:")).length,
      urlsRemaining: Array.from(this.workQueue).filter(id => id.startsWith("url:")).length,
    };
  }
  
  getProgressPercentage(): number {
    const total = Math.max(this.totalTasks, this.completedTasks + this.workQueue.size);
    if (total === 0) return 0;
    return Math.round((this.completedTasks / total) * 100);
  }
}
