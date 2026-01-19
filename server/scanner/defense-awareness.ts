import { makeRequest, RequestResult, sleep } from "./utils";
import { 
  globalPayloadRepository, 
  dynamicTampingTracker, 
  TampingStrategyName, 
  WAF_TAMPING_PROFILES,
  DynamicTampingState 
} from "./payload-repository";

export type EncodingStrategy = 
  | "none"
  | "url_encode"
  | "double_encode"
  | "unicode"
  | "hex"
  | "mixed_case"
  | "comment_split";

export const ENCODING_STRATEGIES: EncodingStrategy[] = [
  "none",
  "url_encode",
  "double_encode",
  "unicode",
  "hex",
  "mixed_case",
  "comment_split",
];

export interface WAFProfile {
  detected: boolean;
  vendor: string | null;
  signatures: string[];
  blockPatterns: string[];
  bypassStrategies: EncodingStrategy[];
}

export interface RateLimitStatus {
  detected: boolean;
  type: "http_429" | "delay_increase" | "captcha" | "ip_block" | null;
  evidence: string | null;
  consecutiveBlocks: number;
  lastBlockTime: number | null;
  recommendedDelay: number;
}

export interface DefenseLog {
  timestamp: number;
  type: "waf" | "rate_limit" | "captcha" | "ip_block";
  evidence: string;
  url: string;
  payload?: string;
  recommendedAction: string;
}

export interface AdaptivePacingState {
  baseDelay: number;
  currentDelay: number;
  maxDelay: number;
  consecutiveSuccesses: number;
  consecutiveFailures: number;
  isPaused: boolean;
  pauseReason: string | null;
  pauseUntil: number | null;
}

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
];

const ACCEPT_LANGUAGES = [
  "en-US,en;q=0.9",
  "en-GB,en;q=0.9,en-US;q=0.8",
  "en-US,en;q=0.9,fr;q=0.8",
  "en-US,en;q=0.9,de;q=0.8",
  "en-US,en;q=0.9,es;q=0.8",
];

const X_FORWARDED_FOR_BASES = [
  "192.168.1", "10.0.0", "172.16.0", "203.0.113", "198.51.100",
];

// UNRESTRICTED OFFENSIVE MODE: No mandatory pauses
const MANDATORY_PAUSE_MS = 0;

const WAF_BLOCK_PATTERNS = [
  { pattern: /Access Denied/i, vendor: "generic" },
  { pattern: /Request Blocked/i, vendor: "generic" },
  { pattern: /Forbidden.*firewall/i, vendor: "generic" },
  { pattern: /Security Violation/i, vendor: "generic" },
  { pattern: /Web Application Firewall/i, vendor: "generic" },
  { pattern: /cf-ray/i, vendor: "cloudflare" },
  { pattern: /cloudflare/i, vendor: "cloudflare" },
  { pattern: /__cfduid/i, vendor: "cloudflare" },
  { pattern: /Attention Required.*Cloudflare/i, vendor: "cloudflare" },
  { pattern: /akamai/i, vendor: "akamai" },
  { pattern: /akamaighost/i, vendor: "akamai" },
  { pattern: /AkamaiGHost/i, vendor: "akamai" },
  { pattern: /incapsula/i, vendor: "imperva" },
  { pattern: /imperva/i, vendor: "imperva" },
  { pattern: /visid_incap/i, vendor: "imperva" },
  { pattern: /Request unsuccessful.*Incapsula/i, vendor: "imperva" },
  { pattern: /awswaf/i, vendor: "aws_waf" },
  { pattern: /x-amzn-waf/i, vendor: "aws_waf" },
  { pattern: /mod_security/i, vendor: "modsecurity" },
  { pattern: /modsecurity/i, vendor: "modsecurity" },
  { pattern: /NOYB/i, vendor: "modsecurity" },
  { pattern: /sucuri/i, vendor: "sucuri" },
  { pattern: /x-sucuri/i, vendor: "sucuri" },
  { pattern: /Sucuri WebSite Firewall/i, vendor: "sucuri" },
  { pattern: /bigip/i, vendor: "f5_bigip" },
  { pattern: /f5-bigip/i, vendor: "f5_bigip" },
  { pattern: /TS\w{8}/i, vendor: "f5_bigip" },
  { pattern: /barracuda/i, vendor: "barracuda" },
  { pattern: /barra_counter_session/i, vendor: "barracuda" },
  { pattern: /fortigate/i, vendor: "fortiweb" },
  { pattern: /fortiweb/i, vendor: "fortiweb" },
  { pattern: /wordfence/i, vendor: "wordfence" },
  { pattern: /Your access to this site has been limited/i, vendor: "wordfence" },
];

const CAPTCHA_PATTERNS = [
  /captcha/i,
  /recaptcha/i,
  /hcaptcha/i,
  /challenge.*required/i,
  /verify.*human/i,
  /are.*you.*robot/i,
  /bot.*detection/i,
  /g-recaptcha/i,
  /cf-turnstile/i,
];

const IP_BLOCK_PATTERNS = [
  /your.*ip.*blocked/i,
  /ip.*address.*banned/i,
  /access.*denied.*from.*ip/i,
  /too.*many.*requests.*from/i,
  /temporarily.*blocked/i,
  /rate.*limit.*exceeded/i,
];

export class DefenseAwareness {
  private wafProfile: WAFProfile;
  private rateLimitStatus: RateLimitStatus;
  private adaptivePacing: AdaptivePacingState;
  private defenseLogs: DefenseLog[] = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private onBlock: (() => void) | null = null;
  private currentEncodingIndex: number = 0;
  private responseTimeSamples: number[] = [];
  private baselineResponseTime: number = 0;
  private currentUserAgentIndex: number = 0;
  private currentXForwardedIndex: number = 0;
  private wafAttemptCounters: Map<string, number> = new Map();
  private lastAppliedStrategies: TampingStrategyName[] = [];

  constructor(onLog: (level: string, message: string) => Promise<void>, onBlock?: () => void) {
    this.onLog = onLog;
    this.onBlock = onBlock || null;
    
    this.wafProfile = {
      detected: false,
      vendor: null,
      signatures: [],
      blockPatterns: [],
      bypassStrategies: [],
    };

    this.rateLimitStatus = {
      detected: false,
      type: null,
      evidence: null,
      consecutiveBlocks: 0,
      lastBlockTime: null,
      recommendedDelay: 100,
    };

    this.adaptivePacing = {
      baseDelay: 100,
      currentDelay: 100,
      maxDelay: 5000,
      consecutiveSuccesses: 0,
      consecutiveFailures: 0,
      isPaused: false,
      pauseReason: null,
      pauseUntil: null,
    };
  }

  async analyzeResponse(response: RequestResult, url: string, payload?: string): Promise<{
    isBlocked: boolean;
    blockType: "waf" | "rate_limit" | "captcha" | "ip_block" | null;
    shouldRetry: boolean;
    recommendedDelay: number;
  }> {
    const result = {
      isBlocked: false,
      blockType: null as "waf" | "rate_limit" | "captcha" | "ip_block" | null,
      shouldRetry: false,
      recommendedDelay: 0, // UNRESTRICTED: No delays
    };

    // UNRESTRICTED OFFENSIVE MODE: Log blocks, rotate headers, track metrics, continue immediately
    
    if (response.status === 429) {
      result.isBlocked = true;
      result.blockType = "rate_limit";
      result.shouldRetry = true; // Retry with rotated headers immediately
      // Call handler for header rotation and logging (no pauses)
      await this.handleRateLimitOffensive(url, "HTTP 429 Rate Limit", payload);
      // Track block for War Room dashboard
      if (this.onBlock) this.onBlock();
      // Rotate headers for next request
      this.rotateHeaders();
      return result;
    }

    if (response.status === 403 || response.status === 406) {
      const wafResult = this.detectWAFFromResponse(response);
      if (wafResult.detected) {
        result.isBlocked = true;
        result.blockType = "waf";
        result.shouldRetry = true; // Retry with different encoding
        // Call handler for WAF bypass strategies (no pauses)
        await this.handleWAFOffensive(url, wafResult.vendor, wafResult.signatures, payload);
        // Track block for War Room dashboard
        if (this.onBlock) this.onBlock();
        // Rotate headers and select bypass encoding
        this.rotateHeaders();
        this.selectNextBypassEncoding();
        return result;
      }
      // 403 without WAF - just continue
      await this.onLog("debug", `[Offensive] 403 at ${url} - Continuing anyway`);
    }

    if (this.detectCaptcha(response)) {
      result.isBlocked = true;
      result.blockType = "captcha";
      result.shouldRetry = false; // Don't retry CAPTCHA, just move to next target
      await this.handleCaptchaOffensive(url, payload);
      if (this.onBlock) this.onBlock();
      return result;
    }

    if (this.detectIPBlock(response)) {
      result.isBlocked = true;
      result.blockType = "ip_block";
      result.shouldRetry = false; // Can't retry IP block, move on
      await this.handleIPBlockOffensive(url, payload);
      if (this.onBlock) this.onBlock();
      return result;
    }

    this.recordResponseTime(response.responseTime);
    this.recordInternalSuccess();
    return result;
  }
  
  // UNRESTRICTED OFFENSIVE MODE handlers - log and adapt but NEVER pause
  private async handleWAFOffensive(url: string, vendor: string | null, signatures: string[], payload?: string): Promise<void> {
    this.wafProfile.detected = true;
    this.wafProfile.vendor = vendor || this.wafProfile.vendor;
    this.wafProfile.signatures = Array.from(new Set([...this.wafProfile.signatures, ...signatures]));
    
    const bypassStrategies = this.getBypassStrategiesForWAF(vendor);
    this.wafProfile.bypassStrategies = bypassStrategies;

    const normalizedVendor = (vendor || "generic").toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const currentAttempt = this.getWAFAttemptCount(normalizedVendor);
    this.incrementWAFAttempt(normalizedVendor);
    
    dynamicTampingTracker.recordBlock(normalizedVendor);
    
    const dynamicStrategies = dynamicTampingTracker.getDynamicTamping(normalizedVendor, currentAttempt);
    this.lastAppliedStrategies = dynamicStrategies;
    
    const strategyDisplay = dynamicStrategies.join(" + ");
    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "waf",
      evidence: `WAF block: ${vendor || "Unknown"} - ${signatures.slice(0, 2).join(", ")}`,
      url,
      payload,
      recommendedAction: `WAF bypass attempt #${currentAttempt + 1}: Applying ${strategyDisplay}`,
    };
    this.defenseLogs.push(log);

    await this.onLog("info", `[WAF Bypass] WAF bypass attempt #${currentAttempt + 1}: Applying ${strategyDisplay} for ${vendor || "Unknown"}`);
  }
  
  private async handleRateLimitOffensive(url: string, evidence: string, payload?: string): Promise<void> {
    this.rateLimitStatus.detected = true;
    this.rateLimitStatus.type = evidence.includes("429") ? "http_429" : "delay_increase";
    this.rateLimitStatus.evidence = evidence;
    this.rateLimitStatus.consecutiveBlocks++;
    this.rateLimitStatus.lastBlockTime = Date.now();

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "rate_limit",
      evidence,
      url,
      payload,
      recommendedAction: "Header rotation applied, continuing",
    };
    this.defenseLogs.push(log);

    await this.onLog("debug", `[Offensive] Rate limit at ${url} - Headers rotated, continuing immediately`);
  }
  
  private async handleCaptchaOffensive(url: string, payload?: string): Promise<void> {
    this.rateLimitStatus.detected = true;
    this.rateLimitStatus.type = "captcha";
    this.rateLimitStatus.evidence = "CAPTCHA detected";

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "captcha",
      evidence: "CAPTCHA challenge detected",
      url,
      payload,
      recommendedAction: "Moving to next target",
    };
    this.defenseLogs.push(log);

    await this.onLog("debug", `[Offensive] CAPTCHA at ${url} - Block recorded, moving to next target`);
  }
  
  private async handleIPBlockOffensive(url: string, payload?: string): Promise<void> {
    this.rateLimitStatus.detected = true;
    this.rateLimitStatus.type = "ip_block";
    this.rateLimitStatus.evidence = "IP block detected";

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "ip_block",
      evidence: "IP block page detected",
      url,
      payload,
      recommendedAction: "Moving to next endpoint",
    };
    this.defenseLogs.push(log);

    await this.onLog("debug", `[Offensive] IP Block at ${url} - Block recorded, moving to next endpoint`);
  }
  
  private selectNextBypassEncoding(): void {
    const strategies = this.wafProfile.bypassStrategies.length > 0 
      ? this.wafProfile.bypassStrategies 
      : ENCODING_STRATEGIES;
    this.currentEncodingIndex = (this.currentEncodingIndex + 1) % strategies.length;
  }

  private detectWAFFromResponse(response: RequestResult): {
    detected: boolean;
    vendor: string | null;
    signatures: string[];
  } {
    const signatures: string[] = [];
    let vendor: string | null = null;

    const headersStr = JSON.stringify(response.headers).toLowerCase();
    const bodyLower = response.body.toLowerCase();
    const combined = headersStr + " " + bodyLower;

    for (const { pattern, vendor: v } of WAF_BLOCK_PATTERNS) {
      if (pattern.test(combined)) {
        signatures.push(pattern.source);
        if (!vendor && v !== "generic") {
          vendor = v;
        }
      }
    }

    return {
      detected: signatures.length > 0,
      vendor,
      signatures,
    };
  }

  private detectCaptcha(response: RequestResult): boolean {
    const content = response.body.toLowerCase();
    return CAPTCHA_PATTERNS.some(pattern => pattern.test(content));
  }

  private detectIPBlock(response: RequestResult): boolean {
    const content = response.body.toLowerCase();
    return IP_BLOCK_PATTERNS.some(pattern => pattern.test(content));
  }

  private recordResponseTime(time: number): void {
    this.responseTimeSamples.push(time);
    if (this.responseTimeSamples.length > 20) {
      this.responseTimeSamples.shift();
    }

    if (this.responseTimeSamples.length <= 5) {
      this.baselineResponseTime = this.responseTimeSamples.reduce((a, b) => a + b, 0) / this.responseTimeSamples.length;
    }
  }

  private detectDelayIncrease(): boolean {
    if (this.responseTimeSamples.length < 10) return false;

    const recentSamples = this.responseTimeSamples.slice(-5);
    const recentAvg = recentSamples.reduce((a, b) => a + b, 0) / recentSamples.length;

    return recentAvg > this.baselineResponseTime * 3 && recentAvg > 2000;
  }

  private async handleWAFDetection(url: string, vendor: string | null, signatures: string[], payload?: string): Promise<void> {
    this.wafProfile.detected = true;
    this.wafProfile.vendor = vendor || this.wafProfile.vendor;
    this.wafProfile.signatures = Array.from(new Set([...this.wafProfile.signatures, ...signatures]));
    
    const bypassStrategies = this.getBypassStrategiesForWAF(vendor);
    this.wafProfile.bypassStrategies = bypassStrategies;

    this.adaptivePacing.consecutiveFailures++;
    this.adaptivePacing.consecutiveSuccesses = 0;
    this.adaptivePacing.currentDelay = Math.min(
      this.adaptivePacing.currentDelay * 1.5,
      this.adaptivePacing.maxDelay
    );

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "waf",
      evidence: `WAF block detected: ${vendor || "Unknown"} - Signatures: ${signatures.slice(0, 3).join(", ")}`,
      url,
      payload,
      recommendedAction: `Try encoding strategies: ${bypassStrategies.slice(0, 3).join(", ")}`,
    };
    this.defenseLogs.push(log);

    await this.onLog("warn", `[Defense] WAF detected: ${vendor || "Unknown"} at ${url}. Recommended: ${bypassStrategies[0] || "encode"} encoding`);
  }

  private async handleRateLimitDetection(url: string, evidence: string, payload?: string): Promise<void> {
    this.rateLimitStatus.detected = true;
    this.rateLimitStatus.type = evidence.includes("429") ? "http_429" : "delay_increase";
    this.rateLimitStatus.evidence = evidence;
    this.rateLimitStatus.consecutiveBlocks++;
    this.rateLimitStatus.lastBlockTime = Date.now();

    this.adaptivePacing.consecutiveFailures++;
    this.adaptivePacing.consecutiveSuccesses = 0;
    
    const multiplier = Math.min(Math.pow(2, this.rateLimitStatus.consecutiveBlocks), 16);
    this.adaptivePacing.currentDelay = Math.min(
      this.adaptivePacing.baseDelay * multiplier,
      this.adaptivePacing.maxDelay
    );
    this.rateLimitStatus.recommendedDelay = this.adaptivePacing.currentDelay;

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "rate_limit",
      evidence,
      url,
      payload,
      recommendedAction: `Increase delay to ${this.adaptivePacing.currentDelay}ms, consecutive blocks: ${this.rateLimitStatus.consecutiveBlocks}`,
    };
    this.defenseLogs.push(log);

    await this.onLog("warn", `[Defense] Rate limiting detected at ${url}. Delay increased to ${this.adaptivePacing.currentDelay}ms`);
  }

  private async handleCaptchaDetection(url: string, payload?: string): Promise<void> {
    this.rateLimitStatus.detected = true;
    this.rateLimitStatus.type = "captcha";
    this.rateLimitStatus.evidence = "CAPTCHA challenge detected";

    this.adaptivePacing.isPaused = true;
    this.adaptivePacing.pauseReason = "CAPTCHA detected - automated scanning blocked";
    this.adaptivePacing.pauseUntil = Date.now() + 60000;

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "captcha",
      evidence: "CAPTCHA challenge page detected in response",
      url,
      payload,
      recommendedAction: "Pause scanning - CAPTCHA required. Consider manual intervention or using different IP.",
    };
    this.defenseLogs.push(log);

    await this.onLog("error", `[Defense] CAPTCHA detected at ${url}. Scanning paused for this target.`);
  }

  private async handleIPBlockDetection(url: string, payload?: string): Promise<void> {
    this.rateLimitStatus.detected = true;
    this.rateLimitStatus.type = "ip_block";
    this.rateLimitStatus.evidence = "IP-based block detected";

    this.adaptivePacing.isPaused = true;
    this.adaptivePacing.pauseReason = "IP address blocked by target";
    this.adaptivePacing.pauseUntil = Date.now() + 300000;

    const log: DefenseLog = {
      timestamp: Date.now(),
      type: "ip_block",
      evidence: "IP block page detected in response",
      url,
      payload,
      recommendedAction: "IP blocked - requires different source IP or proxy to continue.",
    };
    this.defenseLogs.push(log);

    await this.onLog("error", `[Defense] IP blocked at ${url}. Cannot continue scanning from this IP.`);
  }

  private recordInternalSuccess(): void {
    this.adaptivePacing.consecutiveSuccesses++;
    this.adaptivePacing.consecutiveFailures = 0;
    
    if (this.rateLimitStatus.consecutiveBlocks > 0) {
      this.rateLimitStatus.consecutiveBlocks = Math.max(0, this.rateLimitStatus.consecutiveBlocks - 1);
    }

    if (this.adaptivePacing.consecutiveSuccesses >= 5 && this.adaptivePacing.currentDelay > this.adaptivePacing.baseDelay) {
      this.adaptivePacing.currentDelay = Math.max(
        this.adaptivePacing.baseDelay,
        this.adaptivePacing.currentDelay * 0.8
      );
    }
  }

  private getBypassStrategiesForWAF(vendor: string | null): EncodingStrategy[] {
    const vendorStrategies: Record<string, EncodingStrategy[]> = {
      cloudflare: ["unicode", "double_encode", "comment_split", "mixed_case"],
      akamai: ["hex", "unicode", "double_encode"],
      imperva: ["comment_split", "unicode", "mixed_case"],
      aws_waf: ["double_encode", "unicode", "comment_split"],
      modsecurity: ["unicode", "comment_split", "hex", "mixed_case"],
      sucuri: ["double_encode", "unicode", "comment_split"],
      f5_bigip: ["unicode", "hex", "double_encode"],
      wordfence: ["comment_split", "unicode", "mixed_case"],
      default: ["url_encode", "double_encode", "unicode", "comment_split", "mixed_case", "hex"],
    };

    return vendorStrategies[vendor || "default"] || vendorStrategies.default;
  }

  encodePayload(payload: string, strategy: EncodingStrategy): string {
    switch (strategy) {
      case "none":
        return payload;

      case "url_encode":
        return encodeURIComponent(payload);

      case "double_encode":
        return encodeURIComponent(encodeURIComponent(payload));

      case "unicode":
        return this.toUnicodeEncoding(payload);

      case "hex":
        return this.toHexEncoding(payload);

      case "mixed_case":
        return this.toMixedCase(payload);

      case "comment_split":
        return this.commentSplit(payload);

      default:
        return payload;
    }
  }

  private toUnicodeEncoding(payload: string): string {
    const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "OR", "AND", "WHERE", "FROM"];
    let result = payload;
    
    for (const keyword of keywords) {
      const regex = new RegExp(keyword, "gi");
      result = result.replace(regex, (match) => {
        return match.split("").map(char => {
          if (Math.random() > 0.5) {
            return `%u00${char.charCodeAt(0).toString(16).padStart(2, "0")}`;
          }
          return char;
        }).join("");
      });
    }
    
    return result;
  }

  private toHexEncoding(payload: string): string {
    const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "OR", "AND"];
    let result = payload;
    
    for (const keyword of keywords) {
      const hexValue = "0x" + Buffer.from(keyword).toString("hex");
      const regex = new RegExp(`'${keyword}'`, "gi");
      result = result.replace(regex, hexValue);
    }
    
    return result;
  }

  private toMixedCase(payload: string): string {
    const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "AND", "OR"];
    let result = payload;
    
    for (const keyword of keywords) {
      const regex = new RegExp(keyword, "gi");
      result = result.replace(regex, () => {
        return keyword.split("").map((char, i) => 
          i % 2 === 0 ? char.toLowerCase() : char.toUpperCase()
        ).join("");
      });
    }
    
    return result;
  }

  private commentSplit(payload: string): string {
    const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "AND", "OR"];
    let result = payload;
    
    for (const keyword of keywords) {
      const regex = new RegExp(keyword, "gi");
      result = result.replace(regex, (match) => {
        if (match.length <= 2) return match;
        const midpoint = Math.floor(match.length / 2);
        return match.slice(0, midpoint) + "/**/" + match.slice(midpoint);
      });
    }
    
    return result;
  }

  getNextEncodingStrategy(): EncodingStrategy {
    const strategies = this.wafProfile.detected && this.wafProfile.bypassStrategies.length > 0
      ? this.wafProfile.bypassStrategies
      : ENCODING_STRATEGIES;
    
    const strategy = strategies[this.currentEncodingIndex % strategies.length];
    this.currentEncodingIndex++;
    return strategy;
  }

  resetEncodingIndex(): void {
    this.currentEncodingIndex = 0;
  }

  async waitForPacing(): Promise<void> {
    // UNRESTRICTED OFFENSIVE MODE: No waiting, no pacing
    // Just rotate headers and continue at maximum speed
    this.adaptivePacing.isPaused = false;
    this.adaptivePacing.pauseReason = null;
    this.adaptivePacing.pauseUntil = null;
    // No sleep - proceed immediately
  }

  getCurrentDelay(): number {
    return this.adaptivePacing.currentDelay;
  }

  setBaseDelay(delay: number): void {
    this.adaptivePacing.baseDelay = delay;
    this.adaptivePacing.currentDelay = delay;
  }

  getWAFProfile(): WAFProfile {
    return { ...this.wafProfile };
  }

  getRateLimitStatus(): RateLimitStatus {
    return { ...this.rateLimitStatus };
  }

  getDefenseLogs(): DefenseLog[] {
    return [...this.defenseLogs];
  }

  isPaused(): boolean {
    return this.adaptivePacing.isPaused;
  }

  isBlocked(): boolean {
    return this.rateLimitStatus.type === "ip_block" || this.rateLimitStatus.type === "captcha";
  }

  getDefenseSummary(): {
    wafDetected: boolean;
    wafVendor: string | null;
    rateLimitDetected: boolean;
    rateLimitType: string | null;
    currentDelay: number;
    totalBlocks: number;
    bypassStrategies: EncodingStrategy[];
  } {
    return {
      wafDetected: this.wafProfile.detected,
      wafVendor: this.wafProfile.vendor,
      rateLimitDetected: this.rateLimitStatus.detected,
      rateLimitType: this.rateLimitStatus.type,
      currentDelay: this.adaptivePacing.currentDelay,
      totalBlocks: this.rateLimitStatus.consecutiveBlocks,
      bypassStrategies: this.wafProfile.bypassStrategies,
    };
  }

  private getWAFAttemptCount(wafVendor: string): number {
    return this.wafAttemptCounters.get(wafVendor) || 0;
  }

  private incrementWAFAttempt(wafVendor: string): void {
    const current = this.getWAFAttemptCount(wafVendor);
    this.wafAttemptCounters.set(wafVendor, current + 1);
  }

  resetWAFAttempts(wafVendor?: string): void {
    if (wafVendor) {
      const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
      this.wafAttemptCounters.delete(normalizedVendor);
      dynamicTampingTracker.resetState(normalizedVendor);
    } else {
      this.wafAttemptCounters.clear();
    }
  }

  getDynamicTampingStrategies(wafVendor?: string): TampingStrategyName[] {
    const vendor = wafVendor || this.wafProfile.vendor || "generic";
    const normalizedVendor = vendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const attemptCount = this.getWAFAttemptCount(normalizedVendor);
    return dynamicTampingTracker.getDynamicTamping(normalizedVendor, attemptCount);
  }

  applyDynamicTamping(payload: string, wafVendor?: string): string {
    const strategies = this.getDynamicTampingStrategies(wafVendor);
    return globalPayloadRepository.applyDynamicTamping(payload, strategies);
  }

  getLastAppliedStrategies(): TampingStrategyName[] {
    return [...this.lastAppliedStrategies];
  }

  getTampingState(wafVendor?: string): DynamicTampingState | undefined {
    const vendor = wafVendor || this.wafProfile.vendor || "generic";
    const normalizedVendor = vendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    return dynamicTampingTracker.getState(normalizedVendor);
  }

  getWAFAttemptStats(): Map<string, number> {
    return new Map(this.wafAttemptCounters);
  }

  recordSuccess(wafVendor?: string): void {
    if (wafVendor) {
      const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
      dynamicTampingTracker.recordSuccess(normalizedVendor);
      const current = this.getWAFAttemptCount(normalizedVendor);
      if (current > 0) {
        this.wafAttemptCounters.set(normalizedVendor, Math.max(0, current - 1));
      }
    }
  }

  private async applyMandatoryPause(reason: string): Promise<void> {
    // UNRESTRICTED OFFENSIVE MODE: No mandatory pauses
    // Just log and continue at maximum speed
    await this.onLog("debug", `[Offensive] Would have paused for: ${reason} - SKIPPED, continuing`);
  }

  // Force rotation of headers for next request
  rotateHeaders(): void {
    this.currentUserAgentIndex++;
    this.currentXForwardedIndex++;
  }
  
  getRotatedHeaders(): Record<string, string> {
    const userAgent = USER_AGENTS[this.currentUserAgentIndex % USER_AGENTS.length];
    this.currentUserAgentIndex++;

    const acceptLanguage = ACCEPT_LANGUAGES[Math.floor(Math.random() * ACCEPT_LANGUAGES.length)];

    const xForwardedBase = X_FORWARDED_FOR_BASES[this.currentXForwardedIndex % X_FORWARDED_FOR_BASES.length];
    const xForwardedFor = `${xForwardedBase}.${Math.floor(Math.random() * 254) + 1}`;
    this.currentXForwardedIndex++;

    return {
      "User-Agent": userAgent,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
      "Accept-Language": acceptLanguage,
      "Accept-Encoding": "gzip, deflate, br",
      "X-Forwarded-For": xForwardedFor,
      "X-Real-IP": xForwardedFor,
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "DNT": "1",
      "Upgrade-Insecure-Requests": "1",
    };
  }

  getStatisticalTimingThreshold(baselineSamples: number[]): { mean: number; stdDev: number; threshold: number } {
    if (baselineSamples.length < 5) {
      return { mean: 500, stdDev: 200, threshold: 1100 };
    }

    const mean = baselineSamples.reduce((a, b) => a + b, 0) / baselineSamples.length;
    
    const squaredDiffs = baselineSamples.map(x => Math.pow(x - mean, 2));
    const variance = squaredDiffs.reduce((a, b) => a + b, 0) / baselineSamples.length;
    const stdDev = Math.sqrt(variance);

    const threshold = mean + (3 * stdDev);

    return { mean, stdDev, threshold };
  }

  isTimingSignificant(responseTime: number, baselineSamples: number[]): boolean {
    const { threshold } = this.getStatisticalTimingThreshold(baselineSamples);
    return responseTime > threshold;
  }
}
