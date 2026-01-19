import { TieredConcurrencyManager, makeRequest, RequestResult } from "./utils";
import { Crawler, CrawlResult, CrawlerOptions } from "./crawler";
import { globalPayloadRepository } from "./payload-repository";
import { storage } from "../storage";
import type { PipelineStage } from "@shared/schema";

export interface StageProfile {
  stageNumber: PipelineStage;
  name: string;
  description: string;
  highConcurrency: number;
  lowConcurrency: number;
  crawlOnly: boolean;
  enablePolyglotProbes: boolean;
  enableContextAwareTesting: boolean;
  enableFullPayloadSuite: boolean;
  enableMultiVectorVerification: boolean;
  zeroSpeedMode: boolean;
  quickRejection: boolean;
}

export interface StageProgressCallback {
  (progress: {
    processedTargets: number;
    totalTargets: number;
    flaggedTargets: number;
    confirmedVulns: number;
    currentTarget?: string;
    stageNumber: number;
  }): void;
}

export interface StageExecutionResult {
  stageNumber: number;
  processedCount: number;
  flaggedCount: number;
  confirmedVulns: number;
  errors: string[];
  durationMs: number;
}

export const STAGE_PROFILES: Record<PipelineStage, StageProfile> = {
  1: {
    stageNumber: 1,
    name: "Discovery",
    description: "Crawl only, no payload testing, high concurrency",
    highConcurrency: 1000,
    lowConcurrency: 100,
    crawlOnly: true,
    enablePolyglotProbes: false,
    enableContextAwareTesting: false,
    enableFullPayloadSuite: false,
    enableMultiVectorVerification: false,
    zeroSpeedMode: false,
    quickRejection: false,
  },
  2: {
    stageNumber: 2,
    name: "Heuristic Probing",
    description: "Polyglot probes, quick rejection, high concurrency",
    highConcurrency: 500,
    lowConcurrency: 50,
    crawlOnly: false,
    enablePolyglotProbes: true,
    enableContextAwareTesting: false,
    enableFullPayloadSuite: false,
    enableMultiVectorVerification: false,
    zeroSpeedMode: false,
    quickRejection: true,
  },
  3: {
    stageNumber: 3,
    name: "Boolean/Error Context",
    description: "Context-aware testing, medium concurrency",
    highConcurrency: 200,
    lowConcurrency: 20,
    crawlOnly: false,
    enablePolyglotProbes: false,
    enableContextAwareTesting: true,
    enableFullPayloadSuite: false,
    enableMultiVectorVerification: false,
    zeroSpeedMode: false,
    quickRejection: false,
  },
  4: {
    stageNumber: 4,
    name: "Deep Fuzzing",
    description: "Full payload suite, zeroSpeedMode enabled, low concurrency",
    highConcurrency: 50,
    lowConcurrency: 10,
    crawlOnly: false,
    enablePolyglotProbes: false,
    enableContextAwareTesting: false,
    enableFullPayloadSuite: true,
    enableMultiVectorVerification: false,
    zeroSpeedMode: true,
    quickRejection: false,
  },
  5: {
    stageNumber: 5,
    name: "Confirmation",
    description: "Multi-vector verification, zeroSpeedMode enabled, low concurrency",
    highConcurrency: 20,
    lowConcurrency: 5,
    crawlOnly: false,
    enablePolyglotProbes: false,
    enableContextAwareTesting: false,
    enableFullPayloadSuite: false,
    enableMultiVectorVerification: true,
    zeroSpeedMode: true,
    quickRejection: false,
  },
};

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

const ERROR_PATTERNS = [
  /sql.*syntax/i,
  /mysql.*error/i,
  /postgresql.*error/i,
  /ora-\d{5}/i,
  /sqlite.*error/i,
  /mssql.*error/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /syntax error.*near/i,
  /invalid.*query/i,
  /unexpected.*token/i,
];

export class StageExecutor {
  private concurrencyManager: TieredConcurrencyManager;
  private abortController: AbortController;
  private cancelled = false;
  private logs: string[] = [];

  constructor() {
    this.concurrencyManager = new TieredConcurrencyManager();
    this.abortController = new AbortController();
  }

  getStageProfile(stageNumber: number): StageProfile | null {
    if (stageNumber < 1 || stageNumber > 5) {
      return null;
    }
    return STAGE_PROFILES[stageNumber as PipelineStage];
  }

  cancel(): void {
    this.cancelled = true;
    this.abortController.abort();
  }

  private async log(level: string, message: string): Promise<void> {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    this.logs.push(logEntry);
    console.log(logEntry);
  }

  async executeStage(
    fileId: number,
    stageNumber: number,
    targets: string[],
    onProgress: StageProgressCallback
  ): Promise<StageExecutionResult> {
    const profile = this.getStageProfile(stageNumber);
    if (!profile) {
      throw new Error(`Invalid stage number: ${stageNumber}`);
    }

    const startTime = Date.now();
    this.cancelled = false;
    this.abortController = new AbortController();
    this.logs = [];

    await this.log("info", `Starting Stage ${stageNumber} (${profile.name}) for file ${fileId} with ${targets.length} targets`);
    console.log(`[StageExecutor] Starting Stage ${stageNumber} for file ${fileId}:`, {
      totalTargets: targets.length,
      profile: profile.name,
      crawlOnly: profile.crawlOnly,
      enablePolyglotProbes: profile.enablePolyglotProbes,
      enableContextAwareTesting: profile.enableContextAwareTesting,
      enableFullPayloadSuite: profile.enableFullPayloadSuite,
      zeroSpeedMode: profile.zeroSpeedMode,
    });

    this.concurrencyManager.setLimits(profile.highConcurrency, profile.lowConcurrency);
    this.concurrencyManager.resetMetrics();

    const result: StageExecutionResult = {
      stageNumber,
      processedCount: 0,
      flaggedCount: 0,
      confirmedVulns: 0,
      errors: [],
      durationMs: 0,
    };

    const progressState = {
      processedTargets: 0,
      totalTargets: targets.length,
      flaggedTargets: 0,
      confirmedVulns: 0,
      stageNumber,
      currentTarget: undefined as string | undefined,
    };

    // Build URL-to-target-ID map for efficient lookups (Issue 2 fix)
    const allTargets = await storage.getStagedTargetsByFile(fileId);
    const urlToTargetMap = new Map<string, number>();
    for (const t of allTargets) {
      urlToTargetMap.set(t.url, t.id);
    }

    const batchSize = Math.min(profile.highConcurrency, targets.length);
    const batches: string[][] = [];
    for (let i = 0; i < targets.length; i += batchSize) {
      batches.push(targets.slice(i, i + batchSize));
    }

    for (const batch of batches) {
      if (this.cancelled) {
        await this.log("warn", "Stage execution cancelled");
        break;
      }

      const batchPromises = batch.map(async (targetUrl) => {
        const acquired = await this.concurrencyManager.acquireHigh(this.abortController.signal);
        if (!acquired || this.cancelled) {
          return;
        }

        try {
          progressState.currentTarget = targetUrl;
          const targetResult = await this.executeTargetForStage(fileId, targetUrl, profile);
          
          if (targetResult.isAnomaly) {
            progressState.flaggedTargets++;
            result.flaggedCount++;
          }
          if (targetResult.confirmedVuln) {
            progressState.confirmedVulns++;
            result.confirmedVulns++;
          }
          
          progressState.processedTargets++;
          result.processedCount++;

          // Update individual staged target record
          // Non-anomaly targets: Set to "pending" with currentStage = stageNumber so they auto-qualify for next stage
          // Anomaly targets: Set to "flagged" and require manual promotion
          const targetId = urlToTargetMap.get(targetUrl);
          if (targetId) {
            try {
              const isLastStage = stageNumber >= 5;
              const newStatus = targetResult.isAnomaly ? "flagged" : (isLastStage ? "completed" : "pending");
              const updateData: {
                status: string;
                currentStage: number;
                isAnomaly?: boolean;
                anomalyReason?: string;
                deviationDetails?: any;
              } = {
                // Non-anomaly targets advance automatically (status=pending, currentStage=stageNumber)
                // After Stage 1 with stageNumber=1: currentStage becomes 1, so Stage 2 (which filters for currentStage=1) will find it
                // Last stage completes regardless
                // Anomaly targets get flagged for review
                status: newStatus,
                currentStage: stageNumber,
              };
              
              // Log only every 100th target or anomalies to reduce log noise
              if (targetResult.isAnomaly || result.processedCount % 100 === 0) {
                console.log(`[StageExecutor] Target ${targetId}: stage=${stageNumber}, status=${newStatus}, isAnomaly=${targetResult.isAnomaly} (${result.processedCount} processed)`);
              }
              
              if (targetResult.isAnomaly) {
                updateData.isAnomaly = true;
                if (targetResult.anomalyReason) {
                  updateData.anomalyReason = targetResult.anomalyReason;
                }
                if (targetResult.deviationDetails) {
                  updateData.deviationDetails = targetResult.deviationDetails;
                }
              }
              
              await storage.updateStagedTarget(targetId, updateData);
            } catch (updateErr) {
              await this.log("warn", `Failed to update target ${targetUrl}: ${updateErr instanceof Error ? updateErr.message : String(updateErr)}`);
            }
          }

          onProgress({ ...progressState });
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          result.errors.push(`${targetUrl}: ${errorMsg}`);
          await this.log("error", `Error processing ${targetUrl}: ${errorMsg}`);
        } finally {
          this.concurrencyManager.releaseHigh();
        }
      });

      await Promise.all(batchPromises);
    }

    result.durationMs = Date.now() - startTime;
    await this.log("info", `Stage ${stageNumber} completed: ${result.processedCount} processed, ${result.flaggedCount} flagged, ${result.confirmedVulns} confirmed vulns in ${result.durationMs}ms`);

    return result;
  }

  private async executeTargetForStage(
    fileId: number,
    targetUrl: string,
    profile: StageProfile
  ): Promise<{ isAnomaly: boolean; confirmedVuln: boolean; anomalyReason?: string; deviationDetails?: any }> {
    const result = {
      isAnomaly: false,
      confirmedVuln: false,
      anomalyReason: undefined as string | undefined,
      deviationDetails: undefined as any,
    };

    try {
      if (profile.crawlOnly) {
        await this.executeDiscoveryStage(targetUrl);
        return result;
      }

      const baselineResponse = await makeRequest(targetUrl, {
        timeout: profile.zeroSpeedMode ? 60000 : 15000,
        signal: this.abortController.signal,
      });

      if (baselineResponse.error) {
        return result;
      }

      if (profile.enablePolyglotProbes) {
        const probeResult = await this.executeHeuristicProbing(targetUrl, baselineResponse, profile.quickRejection);
        if (probeResult.hasDeviation) {
          result.isAnomaly = true;
          result.anomalyReason = probeResult.reason;
          result.deviationDetails = probeResult.deviationDetails;
          await this.updateTargetAnomaly(fileId, targetUrl, probeResult.reason, probeResult.deviationDetails);
        }
      }

      if (profile.enableContextAwareTesting) {
        const contextResult = await this.executeContextAwareTesting(targetUrl, baselineResponse);
        if (contextResult.hasDeviation) {
          result.isAnomaly = true;
          result.anomalyReason = contextResult.reason;
          result.deviationDetails = contextResult.deviationDetails;
          await this.updateTargetAnomaly(fileId, targetUrl, contextResult.reason, contextResult.deviationDetails);
        }
      }

      if (profile.enableFullPayloadSuite) {
        const fuzzResult = await this.executeDeepFuzzing(targetUrl, baselineResponse, profile.zeroSpeedMode);
        if (fuzzResult.confirmed) {
          result.confirmedVuln = true;
        }
      }

      if (profile.enableMultiVectorVerification) {
        const verifyResult = await this.executeMultiVectorVerification(targetUrl, baselineResponse, profile.zeroSpeedMode);
        if (verifyResult.confirmed) {
          result.confirmedVuln = true;
        }
      }
    } catch (err) {
      await this.log("warn", `Target execution failed for ${targetUrl}: ${err instanceof Error ? err.message : String(err)}`);
    }

    return result;
  }

  private async executeDiscoveryStage(targetUrl: string): Promise<CrawlResult | null> {
    const crawlerOptions: CrawlerOptions = {
      maxDepth: 3,
      maxUrls: 100,
      focusedMode: true,
      parseJavaScript: true,
      detectApiEndpoints: true,
      concurrency: 50,
      blockNonEssentialAssets: true,
    };

    const crawler = new Crawler(
      targetUrl,
      async (level, message) => this.log(level, message),
      crawlerOptions
    );

    try {
      const crawlResult = await crawler.crawl();
      await this.log("info", `Discovery crawl completed: ${crawlResult.stats.urlsDiscovered} URLs, ${crawlResult.stats.parametersFound} parameters`);
      return crawlResult;
    } catch (err) {
      await this.log("error", `Crawl failed for ${targetUrl}: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }

  private async executeHeuristicProbing(
    targetUrl: string,
    baseline: RequestResult,
    quickRejection: boolean
  ): Promise<{ hasDeviation: boolean; reason: string; deviationDetails: any }> {
    const result = {
      hasDeviation: false,
      reason: "",
      deviationDetails: {
        responseTimeDeviation: 0,
        statusCodeChanged: false,
        sizeDeviation: 0,
        domStructureChanged: false,
        errorPatternsFound: [] as string[],
      },
    };

    const urlObj = new URL(targetUrl);
    const params = Array.from(urlObj.searchParams.entries());
    
    if (params.length === 0) {
      return result;
    }

    for (const probe of POLYGLOT_PROBES) {
      if (this.cancelled) break;

      for (const [paramName] of params) {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(paramName, probe);

        const probeResponse = await makeRequest(testUrl.toString(), {
          timeout: 10000,
          signal: this.abortController.signal,
        });

        if (probeResponse.error) continue;

        if (probeResponse.status !== baseline.status) {
          result.hasDeviation = true;
          result.deviationDetails.statusCodeChanged = true;
          result.reason = `Status code changed from ${baseline.status} to ${probeResponse.status} with probe: ${probe.substring(0, 20)}...`;
        }

        const sizeDiff = Math.abs((probeResponse.body?.length || 0) - (baseline.body?.length || 0));
        const sizeRatio = sizeDiff / Math.max(baseline.body?.length || 1, 1);
        if (sizeRatio > 0.1) {
          result.hasDeviation = true;
          result.deviationDetails.sizeDeviation = sizeRatio;
          result.reason = `Response size deviation of ${(sizeRatio * 100).toFixed(1)}% detected`;
        }

        const body = probeResponse.body || "";
        for (const pattern of ERROR_PATTERNS) {
          if (pattern.test(body)) {
            result.hasDeviation = true;
            result.deviationDetails.errorPatternsFound.push(pattern.source);
            result.reason = `SQL error pattern detected: ${pattern.source}`;
            break;
          }
        }

        if (quickRejection && result.hasDeviation) {
          return result;
        }
      }
    }

    return result;
  }

  private async executeContextAwareTesting(
    targetUrl: string,
    baseline: RequestResult
  ): Promise<{ hasDeviation: boolean; reason: string; deviationDetails: any }> {
    const result = {
      hasDeviation: false,
      reason: "",
      deviationDetails: {
        responseTimeDeviation: 0,
        statusCodeChanged: false,
        sizeDeviation: 0,
        domStructureChanged: false,
        errorPatternsFound: [] as string[],
      },
    };

    const booleanProbes = [
      { payload: "' AND '1'='1", expectTrue: true },
      { payload: "' AND '1'='2", expectFalse: true },
      { payload: "1 AND 1=1", expectTrue: true },
      { payload: "1 AND 1=2", expectFalse: true },
    ];

    const urlObj = new URL(targetUrl);
    const params = Array.from(urlObj.searchParams.entries());

    if (params.length === 0) {
      return result;
    }

    for (const [paramName] of params) {
      const trueResponses: RequestResult[] = [];
      const falseResponses: RequestResult[] = [];

      for (const probe of booleanProbes) {
        if (this.cancelled) break;

        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(paramName, probe.payload);

        const response = await makeRequest(testUrl.toString(), {
          timeout: 15000,
          signal: this.abortController.signal,
        });

        if (!response.error) {
          if (probe.expectTrue) {
            trueResponses.push(response);
          } else {
            falseResponses.push(response);
          }
        }
      }

      if (trueResponses.length > 0 && falseResponses.length > 0) {
        const trueAvgSize = trueResponses.reduce((sum, r) => sum + (r.body?.length || 0), 0) / trueResponses.length;
        const falseAvgSize = falseResponses.reduce((sum, r) => sum + (r.body?.length || 0), 0) / falseResponses.length;
        const sizeDiff = Math.abs(trueAvgSize - falseAvgSize);

        if (sizeDiff > 50 && sizeDiff / Math.max(trueAvgSize, falseAvgSize, 1) > 0.05) {
          result.hasDeviation = true;
          result.deviationDetails.sizeDeviation = sizeDiff / Math.max(trueAvgSize, falseAvgSize, 1);
          result.reason = `Boolean-based differential behavior detected: ${sizeDiff} bytes difference`;
        }

        const trueStatus = trueResponses[0]?.status;
        const falseStatus = falseResponses[0]?.status;
        if (trueStatus !== falseStatus) {
          result.hasDeviation = true;
          result.deviationDetails.statusCodeChanged = true;
          result.reason = `Boolean-based status code difference: TRUE=${trueStatus}, FALSE=${falseStatus}`;
        }
      }
    }

    return result;
  }

  private async executeDeepFuzzing(
    targetUrl: string,
    baseline: RequestResult,
    zeroSpeedMode: boolean
  ): Promise<{ confirmed: boolean; details?: string }> {
    const result = { confirmed: false, details: undefined as string | undefined };
    
    const payloads = globalPayloadRepository.getPayloadsByCategory("boolean_based")
      .concat(globalPayloadRepository.getPayloadsByCategory("error_based"))
      .concat(globalPayloadRepository.getPayloadsByCategory("time_based"));

    const urlObj = new URL(targetUrl);
    const params = Array.from(urlObj.searchParams.entries());

    if (params.length === 0) {
      return result;
    }

    const timeout = zeroSpeedMode ? 60000 : 15000;

    for (const payload of payloads.slice(0, 50)) {
      if (this.cancelled) break;

      for (const [paramName] of params) {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(paramName, payload.template);

        const startTime = Date.now();
        const response = await makeRequest(testUrl.toString(), {
          timeout,
          signal: this.abortController.signal,
        });
        const responseTime = Date.now() - startTime;

        if (response.error) continue;

        const body = response.body || "";
        for (const pattern of ERROR_PATTERNS) {
          if (pattern.test(body)) {
            result.confirmed = true;
            result.details = `Error-based SQLi confirmed with payload: ${payload.template.substring(0, 30)}...`;
            return result;
          }
        }

        if (payload.category === "time_based" && responseTime > (baseline.responseTime || 0) + 4000) {
          result.confirmed = true;
          result.details = `Time-based SQLi confirmed: ${responseTime}ms delay with payload: ${payload.template.substring(0, 30)}...`;
          return result;
        }
      }
    }

    return result;
  }

  private async executeMultiVectorVerification(
    targetUrl: string,
    baseline: RequestResult,
    zeroSpeedMode: boolean
  ): Promise<{ confirmed: boolean; details?: string }> {
    const result = { confirmed: false, details: undefined as string | undefined };
    
    const verificationVectors = [
      { type: "error", payloads: [`'`, `"`, `'--`, `"--`, `1'`, `1"`] },
      { type: "boolean", payloads: [`' OR '1'='1`, `' AND '1'='1`, `1 OR 1=1`, `1 AND 1=1`] },
      { type: "union", payloads: [`' UNION SELECT NULL--`, `' UNION SELECT 1--`, `1 UNION SELECT NULL--`] },
    ];

    const urlObj = new URL(targetUrl);
    const params = Array.from(urlObj.searchParams.entries());

    if (params.length === 0) {
      return result;
    }

    const timeout = zeroSpeedMode ? 60000 : 15000;
    let confirmedVectors = 0;

    for (const vector of verificationVectors) {
      let vectorConfirmed = false;

      for (const payload of vector.payloads) {
        if (this.cancelled || vectorConfirmed) break;

        for (const [paramName] of params) {
          const testUrl = new URL(targetUrl);
          testUrl.searchParams.set(paramName, payload);

          const response = await makeRequest(testUrl.toString(), {
            timeout,
            signal: this.abortController.signal,
          });

          if (response.error) continue;

          const body = response.body || "";
          for (const pattern of ERROR_PATTERNS) {
            if (pattern.test(body)) {
              vectorConfirmed = true;
              break;
            }
          }

          if (vector.type === "boolean") {
            const sizeDiff = Math.abs((response.body?.length || 0) - (baseline.body?.length || 0));
            if (sizeDiff > 100) {
              vectorConfirmed = true;
            }
          }

          if (vectorConfirmed) break;
        }
      }

      if (vectorConfirmed) {
        confirmedVectors++;
      }
    }

    if (confirmedVectors >= 2) {
      result.confirmed = true;
      result.details = `Multi-vector SQLi confirmed with ${confirmedVectors}/3 vectors`;
    }

    return result;
  }

  private async updateTargetAnomaly(
    fileId: number,
    targetUrl: string,
    anomalyReason: string,
    deviationDetails: any
  ): Promise<void> {
    try {
      const targets = await storage.getStagedTargetsByFile(fileId);
      const target = targets.find(t => t.url === targetUrl);
      
      if (target) {
        await storage.updateStagedTarget(target.id, {
          isAnomaly: true,
          anomalyReason,
          deviationDetails,
          status: "flagged",
        });
        await this.log("info", `Flagged target ${targetUrl}: ${anomalyReason}`);
      }
    } catch (err) {
      await this.log("warn", `Failed to update target anomaly: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  getStats(): { concurrency: any; logs: string[] } {
    return {
      concurrency: this.concurrencyManager.getStats(),
      logs: this.logs.slice(-100),
    };
  }
}
