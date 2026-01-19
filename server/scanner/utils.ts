import axios, { AxiosRequestConfig, AxiosResponse, AxiosError } from "axios";
import https from "https";
import http from "http";
import { EventEmitter } from "events";
import { storage } from "../storage";
import type { InsertTrafficLog } from "@shared/schema";

// MASS-SCAN CONCURRENCY: Increase EventEmitter limit for 5,000 concurrent workers
EventEmitter.defaultMaxListeners = 10000;

export interface RequestResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  responseTime: number;
  contentLength: number;
  error?: string;
  errorType?: "timeout" | "connection" | "ssl" | "redirect_loop" | "parse" | "aborted" | "unknown";
  retryCount?: number;
  isText?: boolean;
}

export interface Parameter {
  name: string;
  value: string;
  type: "query" | "body" | "path" | "header" | "cookie";
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  headers?: Record<string, string>;
  data?: any;
  timeout?: number;
  followRedirects?: boolean;
  maxRedirects?: number;
  retries?: number;
  retryDelay?: number;
  rejectUnauthorized?: boolean;
  signal?: AbortSignal;
  onResponse?: (result: RequestResult) => void;
}

export interface RateLimiterConfig {
  requestsPerSecond: number;
  burstLimit?: number;
}

const DEFAULT_TIMEOUT = 10000;
const DEFAULT_RETRIES = 3;
const DEFAULT_RETRY_DELAY = 1000;
const DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const MAX_REDIRECT_COUNT = 5;

const TRANSIENT_ERROR_CODES = ["ECONNRESET", "ETIMEDOUT", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"];
const RETRYABLE_STATUS_CODES = [408, 429, 500, 502, 503, 504];

const TEXT_CONTENT_TYPES = [
  "text/",
  "application/json",
  "application/xml",
  "application/javascript",
  "application/x-www-form-urlencoded",
];

export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private requestsPerSecond: number;
  private burstLimit: number;
  private queue: Array<{ resolve: () => void; timestamp: number }> = [];
  private processing = false;

  constructor(config: RateLimiterConfig) {
    this.requestsPerSecond = config.requestsPerSecond;
    this.burstLimit = config.burstLimit || config.requestsPerSecond * 2;
    this.tokens = this.burstLimit;
    this.lastRefill = Date.now();
  }

  private refillTokens(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    const tokensToAdd = elapsed * this.requestsPerSecond;
    this.tokens = Math.min(this.burstLimit, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  async acquire(): Promise<void> {
    return new Promise((resolve) => {
      this.queue.push({ resolve, timestamp: Date.now() });
      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    if (this.processing) return;
    this.processing = true;

    while (this.queue.length > 0) {
      this.refillTokens();

      if (this.tokens >= 1) {
        this.tokens -= 1;
        const request = this.queue.shift();
        if (request) {
          request.resolve();
        }
      } else {
        const waitTime = Math.ceil((1 - this.tokens) / this.requestsPerSecond * 1000);
        await sleep(Math.max(10, waitTime));
      }
    }

    this.processing = false;
  }
}

// MASS-SCAN: Connection pool for 5,000 concurrent workers with circuit breaker
class ConnectionPoolManager {
  private static instance: ConnectionPoolManager;
  private httpAgent: http.Agent;
  private httpsAgent: https.Agent;
  private activeConnections = 0;
  private failedConnections = 0;
  private lastReset = Date.now();
  
  // Circuit breaker state
  private circuitOpen = false;
  private circuitOpenTime = 0;
  private readonly CIRCUIT_TIMEOUT = 30000; // 30s before retry
  private readonly FAILURE_THRESHOLD = 100; // Open circuit after 100 failures
  
  private constructor() {
    // MASS-SCAN CONCURRENCY: Support 5,000 concurrent workers
    this.httpAgent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: 60000,      // Keep connections alive longer
      maxSockets: 5000,           // MASS-SCAN: 5,000 concurrent targets
      maxFreeSockets: 1000,       // Large pool of ready connections
      timeout: 45000,             // Slightly longer timeout for stability
      scheduling: 'fifo',         // FIFO scheduling for predictable behavior
    });
    
    this.httpsAgent = new https.Agent({
      keepAlive: true,
      keepAliveMsecs: 60000,
      maxSockets: 5000,           // MASS-SCAN: 5,000 concurrent targets
      maxFreeSockets: 1000,       // Large pool of ready connections
      timeout: 45000,
      scheduling: 'fifo',
      rejectUnauthorized: false,
    });
    
    // Periodic cleanup to prevent memory leaks
    setInterval(() => this.cleanupStaleConnections(), 60000);
  }
  
  static getInstance(): ConnectionPoolManager {
    if (!ConnectionPoolManager.instance) {
      ConnectionPoolManager.instance = new ConnectionPoolManager();
    }
    return ConnectionPoolManager.instance;
  }
  
  getHttpAgent() { return this.httpAgent; }
  getHttpsAgent() { return this.httpsAgent; }
  
  // Track connection usage for monitoring
  incrementActive() { this.activeConnections++; }
  decrementActive() { this.activeConnections--; }
  recordFailure() { 
    this.failedConnections++;
    if (this.failedConnections >= this.FAILURE_THRESHOLD && !this.circuitOpen) {
      this.circuitOpen = true;
      this.circuitOpenTime = Date.now();
      console.warn(`[ConnectionPool] Circuit breaker OPEN - ${this.failedConnections} failures`);
    }
  }
  
  isCircuitOpen(): boolean {
    if (this.circuitOpen && Date.now() - this.circuitOpenTime >= this.CIRCUIT_TIMEOUT) {
      this.circuitOpen = false;
      this.failedConnections = 0;
      console.log('[ConnectionPool] Circuit breaker CLOSED - resuming operations');
    }
    return this.circuitOpen;
  }
  
  private cleanupStaleConnections() {
    // Reset failure counter periodically
    if (Date.now() - this.lastReset > 60000) {
      this.failedConnections = Math.floor(this.failedConnections * 0.5);
      this.lastReset = Date.now();
    }
  }
  
  getStats() {
    return {
      activeConnections: this.activeConnections,
      failedConnections: this.failedConnections,
      circuitOpen: this.circuitOpen,
      httpSockets: (this.httpAgent as any).sockets ? Object.keys((this.httpAgent as any).sockets).length : 0,
      httpsSockets: (this.httpsAgent as any).sockets ? Object.keys((this.httpsAgent as any).sockets).length : 0,
    };
  }
}

export const connectionPool = ConnectionPoolManager.getInstance();

// MASS-SCAN: Configurable tiered concurrency for 5,000 concurrent workers
export interface TieredConcurrencyConfig {
  highLimit?: number;  // Default 5000 for mass-scan
  lowLimit?: number;   // Default 100 for time-based probes
  enableMetrics?: boolean;
}

export class TieredConcurrencyManager {
  private highConcurrencyLimit: number;
  private lowConcurrencyLimit: number;
  private highConcurrencyActive = 0;
  private lowConcurrencyActive = 0;
  private highQueue: Array<{ resolve: () => void; signal?: AbortSignal }> = [];
  private lowQueue: Array<{ resolve: () => void; signal?: AbortSignal }> = [];
  
  // Metrics for monitoring
  private totalAcquired = 0;
  private totalReleased = 0;
  private peakConcurrency = 0;
  private queueWaitTime: number[] = [];
  
  constructor(config?: TieredConcurrencyConfig) {
    // MASS-SCAN: Default to 5,000 concurrent workers
    this.highConcurrencyLimit = config?.highLimit ?? 5000;
    this.lowConcurrencyLimit = config?.lowLimit ?? 100;
  }
  
  // Dynamically adjust limits for different pipeline stages
  setLimits(highLimit: number, lowLimit: number) {
    this.highConcurrencyLimit = Math.max(1, Math.min(10000, highLimit));
    this.lowConcurrencyLimit = Math.max(1, Math.min(1000, lowLimit));
  }
  
  async acquireHigh(signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return false;
    
    if (this.highConcurrencyActive < this.highConcurrencyLimit) {
      this.highConcurrencyActive++;
      this.totalAcquired++;
      this.peakConcurrency = Math.max(this.peakConcurrency, this.highConcurrencyActive);
      return true;
    }
    
    const startWait = Date.now();
    return new Promise<boolean>(resolve => {
      const entry = { resolve: () => {
        this.queueWaitTime.push(Date.now() - startWait);
        if (this.queueWaitTime.length > 1000) this.queueWaitTime.shift();
        resolve(true);
      }, signal };
      this.highQueue.push(entry);
      
      if (signal) {
        const abortHandler = () => {
          const idx = this.highQueue.indexOf(entry);
          if (idx !== -1) {
            this.highQueue.splice(idx, 1);
            resolve(false);
          }
        };
        signal.addEventListener('abort', abortHandler, { once: true });
      }
    });
  }
  
  releaseHigh(): void {
    this.highConcurrencyActive--;
    this.totalReleased++;
    
    // Process queue without causing memory leaks
    let processed = 0;
    while (this.highQueue.length > 0 && processed < 100) {
      const next = this.highQueue.shift()!;
      processed++;
      if (!next.signal?.aborted) {
        this.highConcurrencyActive++;
        this.totalAcquired++;
        this.peakConcurrency = Math.max(this.peakConcurrency, this.highConcurrencyActive);
        next.resolve();
        break;
      }
    }
  }
  
  async acquireLow(signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return false;
    
    if (this.lowConcurrencyActive < this.lowConcurrencyLimit) {
      this.lowConcurrencyActive++;
      return true;
    }
    
    return new Promise<boolean>(resolve => {
      const entry = { resolve: () => resolve(true), signal };
      this.lowQueue.push(entry);
      
      if (signal) {
        const abortHandler = () => {
          const idx = this.lowQueue.indexOf(entry);
          if (idx !== -1) {
            this.lowQueue.splice(idx, 1);
            resolve(false);
          }
        };
        signal.addEventListener('abort', abortHandler, { once: true });
      }
    });
  }
  
  releaseLow(): void {
    this.lowConcurrencyActive--;
    let processed = 0;
    while (this.lowQueue.length > 0 && processed < 100) {
      const next = this.lowQueue.shift()!;
      processed++;
      if (!next.signal?.aborted) {
        this.lowConcurrencyActive++;
        next.resolve();
        break;
      }
    }
  }
  
  clearQueues(): void {
    this.highQueue = [];
    this.lowQueue = [];
    this.highConcurrencyActive = 0;
    this.lowConcurrencyActive = 0;
  }
  
  getStats() {
    const avgWaitTime = this.queueWaitTime.length > 0 
      ? this.queueWaitTime.reduce((a, b) => a + b, 0) / this.queueWaitTime.length 
      : 0;
    
    return {
      highActive: this.highConcurrencyActive,
      lowActive: this.lowConcurrencyActive,
      highQueued: this.highQueue.length,
      lowQueued: this.lowQueue.length,
      highLimit: this.highConcurrencyLimit,
      lowLimit: this.lowConcurrencyLimit,
      totalAcquired: this.totalAcquired,
      totalReleased: this.totalReleased,
      peakConcurrency: this.peakConcurrency,
      avgQueueWaitMs: Math.round(avgWaitTime),
    };
  }
  
  // Reset metrics (useful for stage transitions)
  resetMetrics() {
    this.totalAcquired = 0;
    this.totalReleased = 0;
    this.peakConcurrency = 0;
    this.queueWaitTime = [];
  }
}

export const tieredConcurrency = new TieredConcurrencyManager();

// Cache for non-injectable parameters and failed payload classes
export class NegativeResultCache {
  private cache = new Map<string, { timestamp: number; reason: string }>();
  private readonly TTL = 300000; // 5 minutes
  
  private generateKey(url: string, param: string, payloadClass?: string): string {
    const urlObj = new URL(url);
    const baseKey = `${urlObj.hostname}${urlObj.pathname}:${param}`;
    return payloadClass ? `${baseKey}:${payloadClass}` : baseKey;
  }
  
  isNegative(url: string, param: string, payloadClass?: string): boolean {
    const key = this.generateKey(url, param, payloadClass);
    const entry = this.cache.get(key);
    if (!entry) return false;
    
    // Check TTL
    if (Date.now() - entry.timestamp > this.TTL) {
      this.cache.delete(key);
      return false;
    }
    
    return true;
  }
  
  markNegative(url: string, param: string, reason: string, payloadClass?: string): void {
    const key = this.generateKey(url, param, payloadClass);
    this.cache.set(key, { timestamp: Date.now(), reason });
  }
  
  getReason(url: string, param: string, payloadClass?: string): string | null {
    const key = this.generateKey(url, param, payloadClass);
    return this.cache.get(key)?.reason || null;
  }
  
  clear(): void {
    this.cache.clear();
  }
  
  getStats() {
    return { entries: this.cache.size };
  }
}

export const negativeCache = new NegativeResultCache();

const defaultRateLimiter = new RateLimiter({ requestsPerSecond: 10, burstLimit: 20 });

function isTextContentType(contentType: string | undefined): boolean {
  if (!contentType) return true;
  return TEXT_CONTENT_TYPES.some(type => contentType.toLowerCase().includes(type));
}

function safeStringify(data: any): string {
  if (data === null || data === undefined) return "";
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) {
    try {
      return data.toString("utf-8");
    } catch {
      return "[Binary data]";
    }
  }
  try {
    return JSON.stringify(data);
  } catch {
    return String(data);
  }
}

function classifyError(error: AxiosError): { message: string; type: RequestResult["errorType"] } {
  const code = error.code;
  const message = error.message;

  if (code === "ERR_CANCELED" || axios.isCancel(error) || message.includes("aborted") || message.includes("canceled")) {
    return { message: "Request aborted", type: "aborted" };
  }

  if (code === "ECONNABORTED" || message.includes("timeout")) {
    return { message: `Connection timeout after ${DEFAULT_TIMEOUT}ms`, type: "timeout" };
  }

  if (code === "ERR_TLS_CERT_ALTNAME_INVALID" || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
      code === "CERT_HAS_EXPIRED" || code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
      message.includes("certificate") || message.includes("SSL")) {
    return { message: `SSL/TLS error: ${message}`, type: "ssl" };
  }

  if (code === "ERR_FR_TOO_MANY_REDIRECTS" || message.includes("redirect")) {
    return { message: `Redirect loop detected (max ${MAX_REDIRECT_COUNT} redirects)`, type: "redirect_loop" };
  }

  if (TRANSIENT_ERROR_CODES.includes(code || "")) {
    return { message: `Connection error: ${code} - ${message}`, type: "connection" };
  }

  return { message: message || "Unknown error", type: "unknown" };
}

function shouldRetry(error: AxiosError, attemptNumber: number, maxRetries: number): boolean {
  if (attemptNumber >= maxRetries) return false;
  
  const code = error.code;
  
  if (code === "ERR_CANCELED" || axios.isCancel(error)) return false;
  
  if (code && TRANSIENT_ERROR_CODES.includes(code)) return true;
  
  if (error.response) {
    const status = error.response.status;
    if (RETRYABLE_STATUS_CODES.includes(status)) return true;
  }

  if (error.code === "ECONNABORTED") return true;

  return false;
}

function calculateBackoff(attemptNumber: number, baseDelay: number): number {
  const delay = baseDelay * Math.pow(2, attemptNumber);
  const jitter = Math.random() * 0.3 * delay;
  return Math.min(delay + jitter, 30000);
}

export async function makeRequest(
  url: string,
  options: RequestOptions = {},
  rateLimiter?: RateLimiter
): Promise<RequestResult> {
  if (options.signal?.aborted) {
    return {
      url,
      status: 0,
      headers: {},
      body: "",
      responseTime: 0,
      contentLength: 0,
      error: "Request aborted",
      errorType: "aborted",
    };
  }

  const limiter = rateLimiter || defaultRateLimiter;
  await limiter.acquire();

  const maxRetries = options.retries ?? DEFAULT_RETRIES;
  const baseRetryDelay = options.retryDelay ?? DEFAULT_RETRY_DELAY;

  let lastError: RequestResult | null = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (options.signal?.aborted) {
      return {
        url,
        status: 0,
        headers: {},
        body: "",
        responseTime: 0,
        contentLength: 0,
        error: "Request aborted",
        errorType: "aborted",
      };
    }

    const startTime = Date.now();

    try {
      const config: AxiosRequestConfig = {
        method: options.method || "GET",
        url,
        headers: {
          "User-Agent": DEFAULT_USER_AGENT,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          ...options.headers,
        },
        data: options.data,
        timeout: options.timeout || DEFAULT_TIMEOUT,
        maxRedirects: options.maxRedirects ?? (options.followRedirects === false ? 0 : MAX_REDIRECT_COUNT),
        validateStatus: () => true,
        httpAgent: connectionPool.getHttpAgent(),
        httpsAgent: connectionPool.getHttpsAgent(),
        responseType: "arraybuffer",
        decompress: true,
        signal: options.signal,
      };

      const response: AxiosResponse<Buffer> = await axios(config);
      const responseTime = Date.now() - startTime;

      const contentType = response.headers["content-type"] as string | undefined;
      const isText = isTextContentType(contentType);

      let body: string;
      if (isText) {
        try {
          body = response.data.toString("utf-8");
        } catch {
          body = safeStringify(response.data);
        }
      } else {
        body = `[Binary content: ${contentType || "unknown type"}, ${response.data.length} bytes]`;
      }

      const result: RequestResult = {
        url,
        status: response.status,
        headers: response.headers as Record<string, string>,
        body,
        responseTime,
        contentLength: response.data?.length || 0,
        retryCount: attempt > 0 ? attempt : undefined,
        isText,
      };
      
      if (options.onResponse) {
        options.onResponse(result);
      }
      
      return result;

    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      const axiosError = error as AxiosError;
      const { message, type } = classifyError(axiosError);

      lastError = {
        url,
        status: axiosError.response?.status || 0,
        headers: (axiosError.response?.headers as Record<string, string>) || {},
        body: "",
        responseTime,
        contentLength: 0,
        error: message,
        errorType: type,
        retryCount: attempt,
      };

      if (shouldRetry(axiosError, attempt, maxRetries)) {
        const backoffDelay = calculateBackoff(attempt, baseRetryDelay);
        await sleep(backoffDelay);
        continue;
      }

      break;
    }
  }

  const finalResult = lastError || {
    url,
    status: 0,
    headers: {},
    body: "",
    responseTime: 0,
    contentLength: 0,
    error: "Unknown error after retries",
    errorType: "unknown",
  };
  
  if (options.onResponse) {
    options.onResponse(finalResult);
  }
  
  return finalResult;
}

export async function makeRequestWithContext(
  url: string,
  options: RequestOptions = {},
  context?: { parameter?: string; payload?: string }
): Promise<RequestResult & { context?: { parameter?: string; payload?: string } }> {
  const result = await makeRequest(url, options);
  return { ...result, context };
}

export function parseUrl(urlString: string): {
  protocol: string;
  host: string;
  port: string;
  path: string;
  query: Record<string, string>;
} {
  try {
    const url = new URL(urlString);
    const query: Record<string, string> = {};
    url.searchParams.forEach((value, key) => {
      query[key] = value;
    });

    return {
      protocol: url.protocol,
      host: url.hostname,
      port: url.port || (url.protocol === "https:" ? "443" : "80"),
      path: url.pathname,
      query,
    };
  } catch {
    return {
      protocol: "http:",
      host: "",
      port: "80",
      path: "/",
      query: {},
    };
  }
}

export function buildUrl(
  baseUrl: string,
  path: string = "",
  query: Record<string, string> = {}
): string {
  try {
    const url = new URL(path, baseUrl);
    Object.entries(query).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });
    return url.toString();
  } catch {
    return baseUrl + path;
  }
}

export function extractParameters(url: string): Parameter[] {
  const parameters: Parameter[] = [];
  
  try {
    const urlObj = new URL(url);
    urlObj.searchParams.forEach((value, name) => {
      parameters.push({ name, value, type: "query" });
    });
  } catch {}

  return parameters;
}

export function injectPayload(
  url: string,
  paramName: string,
  payload: string,
  type: "query" | "path" = "query"
): string {
  try {
    const urlObj = new URL(url);
    
    if (type === "query") {
      urlObj.searchParams.set(paramName, payload);
    } else if (type === "path") {
      urlObj.pathname = urlObj.pathname.replace(
        new RegExp(`/${paramName}(/|$)`),
        `/${payload}$1`
      );
    }
    
    return urlObj.toString();
  } catch {
    return url;
  }
}

export function compareResponses(
  baseline: RequestResult,
  test: RequestResult
): {
  statusChanged: boolean;
  sizeChanged: boolean;
  sizeDiff: number;
  timeDiff: number;
  contentChanged: boolean;
} {
  const sizeDiff = Math.abs(test.contentLength - baseline.contentLength);
  const timeDiff = test.responseTime - baseline.responseTime;

  return {
    statusChanged: test.status !== baseline.status,
    sizeChanged: sizeDiff > 10,
    sizeDiff,
    timeDiff,
    contentChanged: test.body !== baseline.body,
  };
}

export function normalizeUrl(url: string): string {
  try {
    const urlObj = new URL(url);
    urlObj.pathname = urlObj.pathname.replace(/\/$/, "") || "/";
    return urlObj.toString();
  } catch {
    return url;
  }
}

export function getDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

export function isSameDomain(url1: string, url2: string): boolean {
  return getDomain(url1) === getDomain(url2);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function escapeRegex(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function randomString(length: number = 8): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export function hashString(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

export function isValidUrl(urlString: string): boolean {
  try {
    new URL(urlString);
    return true;
  } catch {
    return false;
  }
}

export function safeParseJson<T = any>(json: string, fallback: T): T {
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

export function truncateString(str: string, maxLength: number = 100): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength) + "...";
}

export function formatErrorForLogging(error: unknown): { message: string; stack?: string } {
  if (error instanceof Error) {
    return { message: error.message, stack: error.stack };
  }
  return { message: String(error) };
}

export function createRequestQueue(concurrency: number = 5): RequestQueue {
  return new RequestQueue(concurrency);
}

export class RequestQueue {
  private queue: Array<() => Promise<any>> = [];
  private activeCount = 0;
  private concurrency: number;

  constructor(concurrency: number) {
    this.concurrency = concurrency;
  }

  async add<T>(task: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      this.queue.push(async () => {
        try {
          const result = await task();
          resolve(result);
        } catch (error) {
          reject(error);
        }
      });
      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    while (this.queue.length > 0 && this.activeCount < this.concurrency) {
      const task = this.queue.shift();
      if (task) {
        this.activeCount++;
        task().finally(() => {
          this.activeCount--;
          this.processQueue();
        });
      }
    }
  }

  get pending(): number {
    return this.queue.length;
  }

  get active(): number {
    return this.activeCount;
  }
}

// Traffic Logger for high-fidelity request/response logging
export class TrafficLogger {
  private scanId: number;
  private enabled: boolean = true;
  private logQueue: InsertTrafficLog[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private flushThreshold = 10;
  private flushIntervalMs = 2000;

  constructor(scanId: number, enabled: boolean = true) {
    this.scanId = scanId;
    this.enabled = enabled;
    
    if (enabled) {
      this.flushInterval = setInterval(() => this.flush(), this.flushIntervalMs);
    }
  }

  async log(entry: Omit<InsertTrafficLog, "scanId">): Promise<void> {
    if (!this.enabled) return;

    const fullEntry: InsertTrafficLog = {
      ...entry,
      scanId: this.scanId,
    };

    this.logQueue.push(fullEntry);

    if (this.logQueue.length >= this.flushThreshold) {
      await this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.logQueue.length === 0) return;

    const toFlush = [...this.logQueue];
    this.logQueue = [];

    try {
      for (const entry of toFlush) {
        await storage.createTrafficLog(entry);
      }
    } catch (error) {
      console.error("[TrafficLogger] Failed to flush logs:", error);
    }
  }

  async stop(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
    await this.flush();
  }

  // Convenience method to log a request with result
  async logRequest(
    url: string,
    method: string,
    result: RequestResult,
    options?: {
      payload?: string;
      parameterName?: string;
      payloadType?: string;
      encodingUsed?: string;
      detectionResult?: string;
      confidenceScore?: number;
      headers?: Record<string, string>;
    }
  ): Promise<void> {
    await this.log({
      requestUrl: url,
      requestMethod: method,
      requestHeaders: options?.headers || {},
      requestPayload: options?.payload || null,
      parameterName: options?.parameterName || null,
      payloadType: options?.payloadType || null,
      encodingUsed: options?.encodingUsed || null,
      responseStatus: result.status,
      responseTime: Math.round(result.responseTime),
      responseSize: result.contentLength,
      responseSnippet: result.body ? result.body.substring(0, 500) : null,
      detectionResult: options?.detectionResult || null,
      confidenceScore: options?.confidenceScore || null,
    });
  }
}
