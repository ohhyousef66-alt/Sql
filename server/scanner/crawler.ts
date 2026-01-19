import * as cheerio from "cheerio";
import { makeRequest, parseUrl, normalizeUrl, isSameDomain, extractParameters, RequestResult } from "./utils";

export interface CrawlStats {
  urlsDiscovered: number;
  formsFound: number;
  parametersFound: number;
  apiEndpoints: number;
  jsFilesAnalyzed: number;
  depth: number;
  webSocketEndpoints: number;
  authEndpointsFound: number;
  sensitiveEndpointsFound: number;
  formWorkflowsDetected: number;
}

export interface ParameterSource {
  name: string;
  source: "url" | "cookie" | "header" | "body" | "path";
  sampleValue?: string;
  sensitive?: boolean;
}

export interface FormField {
  name: string;
  type: string;
  value?: string;
  isHidden: boolean;
  isRequired: boolean;
}

export interface FormStep {
  url: string;
  method: string;
  fields: FormField[];
  requiredTokens: string[];
}

export interface FormWorkflow {
  id: string;
  steps: FormStep[];
  tokens: string[];
  dependencies: Record<string, string[]>;
}

export interface CrawlResult {
  urls: string[];
  forms: FormData[];
  apiEndpoints: string[];
  parameters: Map<string, Set<string>>;
  parameterSources: ParameterSource[];
  formWorkflows: FormWorkflow[];
  authEndpoints: string[];
  sensitiveEndpoints: string[];
  webSocketEndpoints: string[];
  dynamicRoutes: string[];
  headerParameters: string[];
  hiddenFields: Map<string, string[]>;
  stats: CrawlStats;
}

export interface FormData {
  action: string;
  method: string;
  inputs: Array<{
    name: string;
    type: string;
    value?: string;
    isHidden: boolean;
    isRequired: boolean;
  }>;
  enctype?: string;
  id?: string;
  hasFileUpload?: boolean;
  csrfToken?: string;
  step?: number;
  totalSteps?: number;
}

export interface CrawlerOptions {
  maxDepth?: number;
  maxUrls?: number;
  focusedMode?: boolean;
  parseJavaScript?: boolean;
  detectApiEndpoints?: boolean;
  concurrency?: number;
  blockNonEssentialAssets?: boolean;
  headlessFirst?: boolean;
  onResponse?: (result: RequestResult) => void;
}

const API_PATTERNS = [
  /\/api\//i,
  /\/v[0-9]+\//i,
  /\/rest\//i,
  /\/graphql/i,
  /\/webhook/i,
  /\/oauth/i,
  /\/auth\//i,
  /\/users?\/[0-9]+/i,
  /\.json$/i,
  /\.xml$/i,
];

const AUTH_ENDPOINT_PATTERNS = [
  /\/login\/?$/i,
  /\/signin\/?$/i,
  /\/sign-in\/?$/i,
  /\/logout\/?$/i,
  /\/signout\/?$/i,
  /\/sign-out\/?$/i,
  /\/register\/?$/i,
  /\/signup\/?$/i,
  /\/sign-up\/?$/i,
  /\/auth\/?$/i,
  /\/authenticate\/?$/i,
  /\/oauth\/?/i,
  /\/oauth2\/?/i,
  /\/callback\/?$/i,
  /\/authorize\/?$/i,
  /\/token\/?$/i,
  /\/refresh-token\/?$/i,
  /\/forgot-password\/?$/i,
  /\/reset-password\/?$/i,
  /\/password-reset\/?$/i,
  /\/change-password\/?$/i,
  /\/verify-email\/?$/i,
  /\/confirm\/?$/i,
  /\/sso\/?$/i,
  /\/saml\/?$/i,
  /\/oidc\/?$/i,
  /\/2fa\/?$/i,
  /\/mfa\/?$/i,
  /\/otp\/?$/i,
];

const SENSITIVE_ENDPOINT_PATTERNS = [
  /\/admin\/?/i,
  /\/administrator\/?/i,
  /\/dashboard\/?$/i,
  /\/panel\/?$/i,
  /\/control\/?$/i,
  /\/manage\/?$/i,
  /\/management\/?$/i,
  /\/config\/?/i,
  /\/configuration\/?/i,
  /\/settings\/?$/i,
  /\/system\/?$/i,
  /\/internal\/?/i,
  /\/private\/?/i,
  /\/debug\/?$/i,
  /\/console\/?$/i,
  /\/phpinfo/i,
  /\/phpmyadmin/i,
  /\/adminer/i,
  /\/wp-admin/i,
  /\/wp-login/i,
  /\/administrator/i,
  /\/\.env/i,
  /\/\.git/i,
  /\/backup/i,
  /\/dump/i,
  /\/export/i,
  /\/import/i,
  /\/upload/i,
  /\/uploads/i,
  /\/api-key/i,
  /\/secret/i,
  /\/credentials/i,
  /\/actuator/i,
  /\/health\/?$/i,
  /\/metrics\/?$/i,
  /\/trace\/?$/i,
  /\/env\/?$/i,
];

const SENSITIVE_PARAM_NAMES = new Set([
  "token", "access_token", "accesstoken", "auth_token", "authtoken",
  "api_key", "apikey", "api-key", "key", "secret", "password", "passwd",
  "pwd", "session", "sessionid", "session_id", "csrf", "csrf_token",
  "csrftoken", "_token", "nonce", "bearer", "jwt", "authorization",
  "auth", "x-auth", "x-token", "x-api-key", "x-access-token",
  "refresh_token", "refreshtoken", "id_token", "idtoken", "oauth_token",
  "client_secret", "client_id", "private_key", "privatekey",
]);

const JS_URL_PATTERNS = [
  /fetch\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /axios\s*\(\s*(?:{[^}]*url\s*:\s*)?["'`]([^"'`]+)["'`]/g,
  /\$\.(?:ajax|get|post)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /XMLHttpRequest[^;]*\.open\s*\(\s*["'`]\w+["'`]\s*,\s*["'`]([^"'`]+)["'`]/g,
  /new\s+Request\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /(?:endpoint|api(?:Url)?|url|href|path|route)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
  /["'`](\/api\/[^"'`]+)["'`]/g,
  /["'`](\/v[0-9]+\/[^"'`]+)["'`]/g,
  /["'`](\/rest\/[^"'`]+)["'`]/g,
  /["'`](\/graphql[^"'`]*)["'`]/g,
];

const WEBSOCKET_PATTERNS = [
  /new\s+WebSocket\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /new\s+WebSocket\s*\(\s*\`([^`]+)\`/g,
  /(?:ws|wss):\/\/[^\s"'`<>)}\]]+/g,
  /io\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /io\.connect\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /socket(?:Url|Endpoint|Path)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi,
];

const DYNAMIC_ROUTE_PATTERNS = [
  /["'`]([^"'`]*\$\{[^}]+\}[^"'`]*)["'`]/g,
  /["'`]([^"'`]*:\w+[^"'`]*)["'`]/g,
  /["'`](\/[^"'`]*\[\w+\][^"'`]*)["'`]/g,
  /\.replace\s*\(\s*["'`]:(\w+)["'`]/g,
  /params\.(\w+)/g,
  /route\s*\.\s*params\s*\.\s*(\w+)/g,
  /useParams\s*\(\s*\)/g,
];

const AUTH_TOKEN_PATTERNS = [
  /(?:localStorage|sessionStorage)\s*\.\s*(?:get|set)Item\s*\(\s*["'`]([^"'`]*(?:token|auth|session|jwt|bearer)[^"'`]*)["'`]/gi,
  /(?:localStorage|sessionStorage)\s*\[\s*["'`]([^"'`]*(?:token|auth|session|jwt|bearer)[^"'`]*)["'`]/gi,
  /document\.cookie\s*=\s*["'`]([^"'`]+)["'`]/g,
  /Cookies?\.(?:get|set)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /headers\s*\[\s*["'`](Authorization|X-Auth[^"'`]*|X-Token[^"'`]*|X-API-Key)["'`]/gi,
  /setHeader\s*\(\s*["'`](Authorization|X-[^"'`]+)["'`]/gi,
  /Bearer\s+[^\s"'`]+/g,
];

const INTERCEPTOR_PATTERNS = [
  /axios\.interceptors\.(?:request|response)\.use\s*\(/g,
  /fetch\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/g,
  /\.interceptors\s*\.\s*(?:request|response)/g,
  /beforeRequest\s*[:=]/g,
  /afterResponse\s*[:=]/g,
  /requestInterceptor\s*[:=]/g,
  /responseInterceptor\s*[:=]/g,
];

const GRAPHQL_PATTERNS = [
  /query\s+(\w+)\s*(?:\([^)]*\))?\s*\{/g,
  /mutation\s+(\w+)\s*(?:\([^)]*\))?\s*\{/g,
  /subscription\s+(\w+)\s*(?:\([^)]*\))?\s*\{/g,
  /\$(\w+)\s*:\s*\w+/g,
  /gql\s*`([^`]+)`/g,
  /graphql\s*\(\s*["'`]([^"'`]+)["'`]/g,
];

const SWAGGER_PATHS = [
  "/swagger.json",
  "/swagger/v1/swagger.json",
  "/api-docs",
  "/api/swagger.json",
  "/openapi.json",
  "/openapi.yaml",
  "/v2/api-docs",
  "/v3/api-docs",
  "/.well-known/openapi.json",
];

const CSRF_TOKEN_NAMES = new Set([
  "csrf", "csrf_token", "csrftoken", "_csrf", "xsrf", "xsrf_token",
  "xsrftoken", "_xsrf", "_token", "authenticity_token", "__requestverificationtoken",
  "anticsrf", "anti-csrf", "nonce", "state",
]);

const LOGGABLE_HEADERS = [
  "User-Agent",
  "Referer",
  "X-Forwarded-For",
  "X-Real-IP",
  "Accept-Language",
  "Authorization",
  "X-Requested-With",
  "X-Custom-Header",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Client-IP",
  "X-Host",
  "X-Originating-IP",
  "Client-IP",
  "True-Client-IP",
  "Forwarded",
  "Forwarded-For",
  "X-Remote-IP",
  "X-Remote-Addr",
];

export class Crawler {
  private targetUrl: string;
  private domain: string;
  private visitedUrls: Set<string> = new Set();
  private foundUrls: Set<string> = new Set();
  private foundForms: FormData[] = [];
  private apiEndpoints: Set<string> = new Set();
  private jsFiles: Set<string> = new Set();
  private parameters: Map<string, Set<string>> = new Map();
  private parameterSources: ParameterSource[] = [];
  private formWorkflows: FormWorkflow[] = [];
  private authEndpoints: Set<string> = new Set();
  private sensitiveEndpoints: Set<string> = new Set();
  private webSocketEndpoints: Set<string> = new Set();
  private dynamicRoutes: Set<string> = new Set();
  private discoveredCookies: Map<string, string> = new Map();
  private discoveredHeaders: Map<string, string> = new Map();
  private graphqlOperations: Set<string> = new Set();
  private headerParameters: Set<string> = new Set();
  private hiddenFields: Map<string, string[]> = new Map();
  private maxDepth: number;
  private maxUrls: number;
  private focusedMode: boolean;
  private parseJavaScript: boolean;
  private detectApiEndpoints: boolean;
  private jsFilesAnalyzed: number = 0;
  private concurrency: number;
  private urlQueue: Array<{ url: string; depth: number }> = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private blockNonEssentialAssets: boolean;
  private headlessFirst: boolean;
  private onResponse?: (result: RequestResult) => void;
  
  private static readonly BLOCKED_RESOURCE_TYPES = ["image", "font", "stylesheet", "media"];
  private static readonly BLOCKED_DOMAINS = [
    "google-analytics.com", "googletagmanager.com", "facebook.com", "twitter.com",
    "doubleclick.net", "googlesyndication.com", "hotjar.com", "clarity.ms",
    "segment.io", "mixpanel.com", "cdn.jsdelivr.net/npm/font"
  ];

  constructor(
    targetUrl: string,
    onLog: (level: string, message: string) => Promise<void>,
    options: CrawlerOptions = {}
  ) {
    this.targetUrl = normalizeUrl(targetUrl);
    this.domain = parseUrl(targetUrl).host;
    this.focusedMode = options.focusedMode ?? false;
    // CRITICAL FIX: Increase depth and URL limits for proper deep crawling
    // Minimum 5 levels deep to find product pages, categories, etc.
    this.maxDepth = options.maxDepth ?? (this.focusedMode ? 8 : 5);
    this.maxUrls = options.maxUrls ?? (this.focusedMode ? 500 : 300);
    this.parseJavaScript = options.parseJavaScript ?? true;
    this.detectApiEndpoints = options.detectApiEndpoints ?? true;
    this.concurrency = options.concurrency ?? 10;
    this.blockNonEssentialAssets = options.blockNonEssentialAssets ?? true;
    this.headlessFirst = options.headlessFirst ?? true;
    this.onLog = onLog;
    this.onResponse = options.onResponse;
  }
  
  private async request(url: string, options: Parameters<typeof makeRequest>[1] = {}): Promise<RequestResult> {
    const result = await makeRequest(url, options);
    
    if (this.onResponse) {
      this.onResponse(result);
    }
    
    return result;
  }
  
  shouldBlockResource(resourceType: string, url: string): boolean {
    if (!this.blockNonEssentialAssets) return false;
    
    if (Crawler.BLOCKED_RESOURCE_TYPES.includes(resourceType)) return true;
    
    for (const domain of Crawler.BLOCKED_DOMAINS) {
      if (url.includes(domain)) return true;
    }
    
    return false;
  }

  async crawl(): Promise<CrawlResult> {
    await this.onLog("info", `Starting enhanced crawler on ${this.targetUrl}`);
    await this.onLog("info", `Configuration: maxDepth=${this.maxDepth}, maxUrls=${this.maxUrls}, focusedMode=${this.focusedMode}, concurrency=${this.concurrency}`);
    
    // Use parallel queue-based crawling for performance
    await this.parallelCrawl();

    if (this.detectApiEndpoints) {
      await this.discoverApiEndpoints();
    }

    if (this.parseJavaScript && this.jsFiles.size > 0) {
      await this.analyzeJsFiles();
    }

    this.detectFormWorkflows();

    this.consolidateParameterSources();

    this.discoverLoggableHeaders();

    this.consolidateHiddenFields();

    const stats: CrawlStats = {
      urlsDiscovered: this.foundUrls.size,
      formsFound: this.foundForms.length,
      parametersFound: this.parameterSources.length,
      apiEndpoints: this.apiEndpoints.size,
      jsFilesAnalyzed: this.jsFilesAnalyzed,
      depth: this.maxDepth,
      webSocketEndpoints: this.webSocketEndpoints.size,
      authEndpointsFound: this.authEndpoints.size,
      sensitiveEndpointsFound: this.sensitiveEndpoints.size,
      formWorkflowsDetected: this.formWorkflows.length,
    };

    await this.onLog("info", `Crawling complete. URLs: ${stats.urlsDiscovered}, Forms: ${stats.formsFound}, API Endpoints: ${stats.apiEndpoints}, JS Files: ${stats.jsFilesAnalyzed}`);
    await this.onLog("info", `Auth Endpoints: ${stats.authEndpointsFound}, Sensitive Endpoints: ${stats.sensitiveEndpointsFound}, WebSocket Endpoints: ${stats.webSocketEndpoints}`);
    await this.onLog("info", `Form Workflows: ${stats.formWorkflowsDetected}, Parameters: ${stats.parametersFound}`);
    await this.onLog("info", `Header Parameters: ${this.headerParameters.size}, Hidden Fields: ${this.hiddenFields.size}`);

    return {
      urls: Array.from(this.foundUrls),
      forms: this.foundForms,
      apiEndpoints: Array.from(this.apiEndpoints),
      parameters: this.parameters,
      parameterSources: this.parameterSources,
      formWorkflows: this.formWorkflows,
      authEndpoints: Array.from(this.authEndpoints),
      sensitiveEndpoints: Array.from(this.sensitiveEndpoints),
      webSocketEndpoints: Array.from(this.webSocketEndpoints),
      dynamicRoutes: Array.from(this.dynamicRoutes),
      headerParameters: Array.from(this.headerParameters),
      hiddenFields: this.hiddenFields,
      stats,
    };
  }

  private async parallelCrawl(): Promise<void> {
    // Initialize queue with the target URL
    this.urlQueue.push({ url: this.targetUrl, depth: 0 });
    
    // Process URLs in parallel batches
    while (this.urlQueue.length > 0 && this.visitedUrls.size < this.maxUrls) {
      // Take a batch of URLs to process in parallel
      const batchSize = Math.min(this.concurrency, this.urlQueue.length);
      const batch = this.urlQueue.splice(0, batchSize);
      
      // Process batch in parallel
      const results = await Promise.allSettled(
        batch.map(item => this.processUrl(item.url, item.depth))
      );
      
      // Log progress every 50 URLs
      if (this.visitedUrls.size % 50 === 0 && this.visitedUrls.size > 0) {
        await this.onLog("info", `[Crawler] Progress: ${this.visitedUrls.size} URLs visited, ${this.urlQueue.length} in queue`);
      }
    }
    
    await this.onLog("info", `[Crawler] Finished: ${this.visitedUrls.size} URLs visited total`);
  }

  private async processUrl(url: string, depth: number): Promise<string[]> {
    if (depth > this.maxDepth) return [];
    if (this.visitedUrls.size >= this.maxUrls) return [];
    if (this.visitedUrls.has(url)) return [];

    this.visitedUrls.add(url);
    this.foundUrls.add(url);

    if (this.isApiEndpoint(url)) {
      this.apiEndpoints.add(url);
    }

    if (this.isAuthEndpoint(url)) {
      this.authEndpoints.add(url);
    }

    if (this.isSensitiveEndpoint(url)) {
      this.sensitiveEndpoints.add(url);
    }

    const params = extractParameters(url);
    if (params.length > 0) {
      if (!this.parameters.has(url)) {
        this.parameters.set(url, new Set());
      }
      params.forEach(p => {
        this.parameters.get(url)!.add(p.name);
        this.addParameterSource(p.name, "url", p.value, this.isSensitiveParam(p.name));
      });
    }

    this.extractPathParameters(url);
    const newUrls: string[] = [];

    try {
      const response = await this.request(url, { timeout: 15000, maxRedirects: 5 });
      
      if (response.error) {
        await this.onLog("debug", `[Crawler] Failed to fetch ${url}: ${response.error}`);
        return [];
      }
      
      if (response.status >= 400) {
        await this.onLog("debug", `[Crawler] HTTP ${response.status} for ${url}`);
        return [];
      }

      if (depth <= 2) {
        await this.onLog("info", `[Crawler] Depth ${depth}: ${url} (${response.status})`);
      }
      
      this.extractApiFromHeaders(response.headers, url);
      this.extractCookies(response.headers);
      this.extractSecurityHeaders(response.headers);

      const contentType = response.headers["content-type"] || "";
      
      if (contentType.includes("application/json")) {
        this.extractFromJson(response.body, url);
        this.mineParametersFromJson(response.body, url);
        return [];
      }
      
      if (!contentType.includes("text/html") && !contentType.includes("application/xhtml")) {
        return [];
      }

      const $ = cheerio.load(response.body);

      const linkCount = $("a[href]").length;
      const formCount = $("form").length;
      if (depth <= 2 && (linkCount > 0 || formCount > 0)) {
        await this.onLog("info", `[Crawler] Found ${linkCount} links, ${formCount} forms on ${url}`);
      }

      // Extract links and add to queue instead of recursive calls
      const discoveredUrls = await this.extractLinksToQueue($, url, depth);
      this.extractForms($, url);
      this.extractInlineScripts($, url);
      this.extractScriptSources($, url);
      this.extractMetaTags($, url);

      return discoveredUrls;
    } catch (error: any) {
      await this.onLog("debug", `[Crawler] Error crawling ${url}: ${error.message}`);
      return [];
    }
  }

  private async extractLinksToQueue($: cheerio.CheerioAPI, baseUrl: string, depth: number): Promise<string[]> {
    const links: string[] = [];
    const newUrls: string[] = [];

    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href) links.push(href);
    });

    $("form[action]").each((_, el) => {
      const action = $(el).attr("action");
      if (action) links.push(action);
    });

    $("iframe[src], frame[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (src) links.push(src);
    });

    $("link[href]").each((_, el) => {
      const href = $(el).attr("href");
      const rel = $(el).attr("rel");
      if (href && (rel === "alternate" || rel === "canonical")) {
        links.push(href);
      }
    });

    $("[data-url], [data-href], [data-src], [data-api]").each((_, el) => {
      const attrs = ["data-url", "data-href", "data-src", "data-api"];
      attrs.forEach(attr => {
        const val = $(el).attr(attr);
        if (val) links.push(val);
      });
    });

    for (const link of links) {
      try {
        const absoluteUrl = this.resolveUrl(link, baseUrl);
        
        if (!absoluteUrl) continue;
        if (!isSameDomain(absoluteUrl, this.targetUrl)) continue;
        if (this.shouldSkipUrl(absoluteUrl)) continue;

        this.foundUrls.add(absoluteUrl);

        if (this.isApiEndpoint(absoluteUrl)) {
          this.apiEndpoints.add(absoluteUrl);
        }

        if (this.isAuthEndpoint(absoluteUrl)) {
          this.authEndpoints.add(absoluteUrl);
        }

        if (this.isSensitiveEndpoint(absoluteUrl)) {
          this.sensitiveEndpoints.add(absoluteUrl);
        }

        // Add to queue instead of recursive call
        if (!this.visitedUrls.has(absoluteUrl) && depth + 1 <= this.maxDepth) {
          this.urlQueue.push({ url: absoluteUrl, depth: depth + 1 });
          newUrls.push(absoluteUrl);
        }
      } catch {}
    }

    return newUrls;
  }

  private async crawlUrl(url: string, depth: number): Promise<void> {
    if (depth > this.maxDepth) return;
    if (this.visitedUrls.size >= this.maxUrls) return;
    if (this.visitedUrls.has(url)) return;

    this.visitedUrls.add(url);
    this.foundUrls.add(url);

    if (this.isApiEndpoint(url)) {
      this.apiEndpoints.add(url);
    }

    if (this.isAuthEndpoint(url)) {
      this.authEndpoints.add(url);
    }

    if (this.isSensitiveEndpoint(url)) {
      this.sensitiveEndpoints.add(url);
    }

    const params = extractParameters(url);
    if (params.length > 0) {
      if (!this.parameters.has(url)) {
        this.parameters.set(url, new Set());
      }
      params.forEach(p => {
        this.parameters.get(url)!.add(p.name);
        this.addParameterSource(p.name, "url", p.value, this.isSensitiveParam(p.name));
      });
    }

    this.extractPathParameters(url);

    try {
      const response = await this.request(url, { timeout: 15000, maxRedirects: 5 });
      
      // CRITICAL FIX: Accept any successful response, not just 200
      // 2xx = success, 3xx = already followed by axios
      if (response.error) {
        await this.onLog("debug", `[Crawler] Failed to fetch ${url}: ${response.error}`);
        return;
      }
      
      if (response.status >= 400) {
        // Log but don't stop - continue crawling other URLs
        await this.onLog("debug", `[Crawler] HTTP ${response.status} for ${url}`);
        return;
      }

      // Log successful page fetch
      if (depth <= 2) {
        await this.onLog("info", `[Crawler] Depth ${depth}: ${url} (${response.status})`);
      }
      
      this.extractApiFromHeaders(response.headers, url);
      this.extractCookies(response.headers);
      this.extractSecurityHeaders(response.headers);

      const contentType = response.headers["content-type"] || "";
      
      if (contentType.includes("application/json")) {
        this.extractFromJson(response.body, url);
        this.mineParametersFromJson(response.body, url);
        return;
      }
      
      // Accept HTML and XHTML content
      if (!contentType.includes("text/html") && !contentType.includes("application/xhtml")) {
        return;
      }

      const $ = cheerio.load(response.body);

      // Count links found for debugging
      const linkCount = $("a[href]").length;
      const formCount = $("form").length;
      if (depth <= 2 && (linkCount > 0 || formCount > 0)) {
        await this.onLog("info", `[Crawler] Found ${linkCount} links, ${formCount} forms on ${url}`);
      }

      await this.extractLinks($, url, depth);
      this.extractForms($, url);
      this.extractInlineScripts($, url);
      this.extractScriptSources($, url);
      this.extractMetaTags($, url);

    } catch (error: any) {
      await this.onLog("debug", `[Crawler] Error crawling ${url}: ${error.message}`);
    }
  }

  private extractPathParameters(url: string): void {
    try {
      const parsed = new URL(url);
      const pathSegments = parsed.pathname.split("/").filter(Boolean);
      
      for (let i = 0; i < pathSegments.length; i++) {
        const segment = pathSegments[i];
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
          this.addParameterSource(`path_segment_${i}_uuid`, "path", segment, false);
        } else if (/^\d+$/.test(segment)) {
          this.addParameterSource(`path_segment_${i}_id`, "path", segment, false);
        } else if (/^[a-zA-Z0-9_-]{20,}$/.test(segment)) {
          this.addParameterSource(`path_segment_${i}_token`, "path", segment, true);
        }
      }
    } catch {}
  }

  private extractCookies(headers: Record<string, string>): void {
    const setCookie = headers["set-cookie"];
    if (!setCookie) return;

    const cookieStrings = Array.isArray(setCookie) ? setCookie : [setCookie];
    
    for (const cookie of cookieStrings) {
      const match = cookie.match(/^([^=]+)=([^;]*)/);
      if (match) {
        const [, name, value] = match;
        this.discoveredCookies.set(name, value);
        this.addParameterSource(name, "cookie", value.substring(0, 50), this.isSensitiveParam(name));
      }
    }
  }

  private extractSecurityHeaders(headers: Record<string, string>): void {
    const interestingHeaders = [
      "x-csrf-token", "x-xsrf-token", "x-request-id", "x-correlation-id",
      "x-api-key", "x-auth-token", "authorization", "x-forwarded-for",
      "x-real-ip", "x-custom-auth",
    ];

    for (const header of interestingHeaders) {
      const value = headers[header.toLowerCase()];
      if (value) {
        this.discoveredHeaders.set(header, value);
        this.addParameterSource(header, "header", value.substring(0, 50), this.isSensitiveParam(header));
      }
    }
  }

  private mineParametersFromJson(body: string, url: string): void {
    try {
      const json = JSON.parse(body);
      this.extractJsonParameters(json, "", url);
    } catch {}
  }

  private extractJsonParameters(obj: any, prefix: string, url: string, depth: number = 0): void {
    if (depth > 10 || !obj) return;

    if (typeof obj === "object" && !Array.isArray(obj)) {
      for (const key of Object.keys(obj)) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        const value = obj[key];
        
        if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
          this.addParameterSource(key, "body", String(value).substring(0, 50), this.isSensitiveParam(key));
        }
        
        if (typeof value === "object") {
          this.extractJsonParameters(value, fullKey, url, depth + 1);
        }
      }
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        this.extractJsonParameters(item, prefix, url, depth + 1);
      }
    }
  }

  private extractMetaTags($: cheerio.CheerioAPI, url: string): void {
    $("meta[name='csrf-token'], meta[name='csrf_token']").each((_, el) => {
      const content = $(el).attr("content");
      if (content) {
        this.addParameterSource("csrf-token", "header", content.substring(0, 50), true);
      }
    });

    $("meta[name='api-key'], meta[name='apiKey']").each((_, el) => {
      const content = $(el).attr("content");
      if (content) {
        this.addParameterSource("api-key", "header", content.substring(0, 50), true);
      }
    });
  }

  private addParameterSource(name: string, source: ParameterSource["source"], sampleValue?: string, sensitive?: boolean): void {
    const exists = this.parameterSources.some(p => p.name === name && p.source === source);
    if (!exists) {
      this.parameterSources.push({
        name,
        source,
        sampleValue,
        sensitive: sensitive || this.isSensitiveParam(name),
      });
    }
  }

  private isSensitiveParam(name: string): boolean {
    const lowerName = name.toLowerCase();
    return SENSITIVE_PARAM_NAMES.has(lowerName) ||
           /token|auth|key|secret|password|session|jwt|bearer|credential|private/i.test(lowerName);
  }

  private isAuthEndpoint(url: string): boolean {
    return AUTH_ENDPOINT_PATTERNS.some(pattern => pattern.test(url));
  }

  private isSensitiveEndpoint(url: string): boolean {
    return SENSITIVE_ENDPOINT_PATTERNS.some(pattern => pattern.test(url));
  }

  private consolidateParameterSources(): void {
    this.parameters.forEach((paramSet, url) => {
      paramSet.forEach(param => {
        const exists = this.parameterSources.some(p => p.name === param);
        if (!exists) {
          this.addParameterSource(param, "url", undefined, this.isSensitiveParam(param));
        }
      });
    });
  }

  private discoverLoggableHeaders(): void {
    for (const header of LOGGABLE_HEADERS) {
      const headerParam = `header:${header}`;
      this.headerParameters.add(headerParam);
      this.addParameterSource(headerParam, "header", undefined, false);
    }

    Array.from(this.discoveredCookies.entries()).forEach(([cookieName]) => {
      const cookieParam = `header:Cookie:${cookieName}`;
      this.headerParameters.add(cookieParam);
      this.addParameterSource(cookieParam, "cookie", undefined, this.isSensitiveParam(cookieName));
    });

    Array.from(this.discoveredHeaders.entries()).forEach(([headerName, headerValue]) => {
      const headerParam = `header:${headerName}`;
      if (!this.headerParameters.has(headerParam)) {
        this.headerParameters.add(headerParam);
        this.addParameterSource(headerParam, "header", headerValue?.substring(0, 50), this.isSensitiveParam(headerName));
      }
    });
  }

  private consolidateHiddenFields(): void {
    for (const form of this.foundForms) {
      const hiddenInputs = form.inputs.filter(input => input.isHidden);
      if (hiddenInputs.length > 0) {
        const hiddenFieldNames: string[] = [];
        for (const input of hiddenInputs) {
          const hiddenParam = `hidden:${input.name}`;
          hiddenFieldNames.push(input.name);
          
          const exists = this.parameterSources.some(p => p.name === hiddenParam);
          if (!exists) {
            this.parameterSources.push({
              name: hiddenParam,
              source: "body",
              sampleValue: input.value?.substring(0, 50),
              sensitive: this.isSensitiveParam(input.name),
            });
          }
        }
        
        if (hiddenFieldNames.length > 0) {
          this.hiddenFields.set(form.action, hiddenFieldNames);
        }
      }

      if (form.action && form.action.includes("?")) {
        const actionParams = extractParameters(form.action);
        for (const param of actionParams) {
          if (!form.inputs.some(i => i.name === param.name)) {
            this.addParameterSource(param.name, "url", param.value, this.isSensitiveParam(param.name));
          }
        }
      }
    }
  }

  private detectFormWorkflows(): void {
    const formsByAction = new Map<string, FormData[]>();
    
    for (const form of this.foundForms) {
      const baseAction = form.action.split("?")[0];
      if (!formsByAction.has(baseAction)) {
        formsByAction.set(baseAction, []);
      }
      formsByAction.get(baseAction)!.push(form);
    }

    let workflowId = 0;
    
    const entries = Array.from(formsByAction.entries());
    for (const [action, forms] of entries) {
      const steppedForms = forms.filter((f: FormData) => f.step !== undefined && f.totalSteps !== undefined);
      if (steppedForms.length > 1) {
        const workflow = this.createFormWorkflow(steppedForms, `workflow_${workflowId++}`);
        this.formWorkflows.push(workflow);
        continue;
      }

      if (forms.length > 1) {
        const tokens = new Set<string>();
        const dependencies: Record<string, string[]> = {};
        
        for (const form of forms) {
          for (const input of form.inputs) {
            if (this.isTokenField(input.name)) {
              tokens.add(input.name);
            }
            if (input.isHidden && input.value) {
              dependencies[input.name] = [];
            }
          }
        }

        if (tokens.size > 0) {
          const workflow: FormWorkflow = {
            id: `workflow_${workflowId++}`,
            steps: forms.map((form: FormData, idx: number) => ({
              url: form.action,
              method: form.method,
              fields: form.inputs.map((i: FormData["inputs"][number]) => ({
                name: i.name,
                type: i.type,
                value: i.value,
                isHidden: i.isHidden,
                isRequired: i.isRequired,
              })),
              requiredTokens: form.inputs.filter((i: FormData["inputs"][number]) => this.isTokenField(i.name)).map((i: FormData["inputs"][number]) => i.name),
            })),
            tokens: Array.from(tokens),
            dependencies,
          };
          this.formWorkflows.push(workflow);
        }
      }
    }

    const complexForms = this.foundForms.filter(f => {
      const hiddenTokens = f.inputs.filter(i => i.isHidden && this.isTokenField(i.name));
      return hiddenTokens.length >= 2;
    });

    for (const form of complexForms) {
      const existsInWorkflow = this.formWorkflows.some(w => 
        w.steps.some(s => s.url === form.action)
      );
      
      if (!existsInWorkflow) {
        const tokens = form.inputs
          .filter(i => this.isTokenField(i.name))
          .map(i => i.name);
        
        const workflow: FormWorkflow = {
          id: `workflow_${workflowId++}`,
          steps: [{
            url: form.action,
            method: form.method,
            fields: form.inputs.map(i => ({
              name: i.name,
              type: i.type,
              value: i.value,
              isHidden: i.isHidden,
              isRequired: i.isRequired,
            })),
            requiredTokens: tokens,
          }],
          tokens,
          dependencies: {},
        };
        this.formWorkflows.push(workflow);
      }
    }
  }

  private createFormWorkflow(forms: FormData[], id: string): FormWorkflow {
    const sortedForms = forms.sort((a, b) => (a.step || 0) - (b.step || 0));
    const tokens = new Set<string>();
    const dependencies: Record<string, string[]> = {};

    for (const form of sortedForms) {
      for (const input of form.inputs) {
        if (this.isTokenField(input.name)) {
          tokens.add(input.name);
        }
      }
    }

    return {
      id,
      steps: sortedForms.map(form => ({
        url: form.action,
        method: form.method,
        fields: form.inputs.map(i => ({
          name: i.name,
          type: i.type,
          value: i.value,
          isHidden: i.isHidden,
          isRequired: i.isRequired,
        })),
        requiredTokens: form.inputs
          .filter(i => this.isTokenField(i.name))
          .map(i => i.name),
      })),
      tokens: Array.from(tokens),
      dependencies,
    };
  }

  private isTokenField(name: string): boolean {
    const lowerName = name.toLowerCase();
    return CSRF_TOKEN_NAMES.has(lowerName) || 
           /csrf|xsrf|token|nonce|state|captcha/i.test(lowerName);
  }

  private async extractLinks($: cheerio.CheerioAPI, baseUrl: string, depth: number): Promise<void> {
    const links: string[] = [];

    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (href) links.push(href);
    });

    $("form[action]").each((_, el) => {
      const action = $(el).attr("action");
      if (action) links.push(action);
    });

    $("iframe[src], frame[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (src) links.push(src);
    });

    $("link[href]").each((_, el) => {
      const href = $(el).attr("href");
      const rel = $(el).attr("rel");
      if (href && (rel === "alternate" || rel === "canonical")) {
        links.push(href);
      }
    });

    $("[data-url], [data-href], [data-src], [data-api]").each((_, el) => {
      const attrs = ["data-url", "data-href", "data-src", "data-api"];
      attrs.forEach(attr => {
        const val = $(el).attr(attr);
        if (val) links.push(val);
      });
    });

    for (const link of links) {
      try {
        const absoluteUrl = this.resolveUrl(link, baseUrl);
        
        if (!absoluteUrl) continue;
        if (!isSameDomain(absoluteUrl, this.targetUrl)) continue;
        if (this.shouldSkipUrl(absoluteUrl)) continue;

        this.foundUrls.add(absoluteUrl);

        if (this.isApiEndpoint(absoluteUrl)) {
          this.apiEndpoints.add(absoluteUrl);
        }

        if (this.isAuthEndpoint(absoluteUrl)) {
          this.authEndpoints.add(absoluteUrl);
        }

        if (this.isSensitiveEndpoint(absoluteUrl)) {
          this.sensitiveEndpoints.add(absoluteUrl);
        }

        if (!this.visitedUrls.has(absoluteUrl)) {
          await this.crawlUrl(absoluteUrl, depth + 1);
        }
      } catch {}
    }
  }

  private extractForms($: cheerio.CheerioAPI, baseUrl: string): void {
    $("form").each((_, form) => {
      const $form = $(form);
      const action = $form.attr("action") || baseUrl;
      const method = ($form.attr("method") || "GET").toUpperCase();
      const enctype = $form.attr("enctype");
      const formId = $form.attr("id");

      const inputs: FormData["inputs"] = [];
      let hasFileUpload = false;
      let csrfToken: string | undefined;
      let step: number | undefined;
      let totalSteps: number | undefined;

      $form.find("[data-step]").each((_, el) => {
        const stepAttr = $(el).attr("data-step");
        if (stepAttr) step = parseInt(stepAttr, 10);
      });

      $form.find("[data-total-steps]").each((_, el) => {
        const totalAttr = $(el).attr("data-total-steps");
        if (totalAttr) totalSteps = parseInt(totalAttr, 10);
      });

      if (formId) {
        if (/step[_-]?(\d+)/i.test(formId)) {
          const match = formId.match(/step[_-]?(\d+)/i);
          if (match) step = parseInt(match[1], 10);
        }
      }

      $form.find("input, textarea, select").each((_, input) => {
        const $input = $(input);
        const name = $input.attr("name");
        const type = $input.attr("type") || ($input.is("textarea") ? "textarea" : $input.is("select") ? "select" : "text");
        const value = $input.attr("value") || $input.val()?.toString();
        const isHidden = type === "hidden";
        const isRequired = $input.attr("required") !== undefined || $input.attr("aria-required") === "true";

        if (type === "file") {
          hasFileUpload = true;
        }

        if (name && isHidden && this.isTokenField(name) && value) {
          csrfToken = value;
        }

        if (name) {
          inputs.push({ name, type, value, isHidden, isRequired });
          this.addParameterSource(name, "body", value?.substring(0, 50), this.isSensitiveParam(name));
        }
      });

      $form.find("button[name]").each((_, btn) => {
        const $btn = $(btn);
        const name = $btn.attr("name");
        const value = $btn.attr("value");
        if (name) {
          inputs.push({ name, type: "button", value, isHidden: false, isRequired: false });
        }
      });

      if (inputs.length > 0) {
        const absoluteAction = this.resolveUrl(action, baseUrl) || action;
        
        this.foundForms.push({
          action: absoluteAction,
          method,
          inputs,
          enctype,
          id: formId,
          hasFileUpload,
          csrfToken,
          step,
          totalSteps,
        });

        if (!this.parameters.has(absoluteAction)) {
          this.parameters.set(absoluteAction, new Set());
        }
        inputs.forEach(input => {
          this.parameters.get(absoluteAction)!.add(input.name);
        });

        if (this.isAuthEndpoint(absoluteAction)) {
          this.authEndpoints.add(absoluteAction);
        }
      }
    });
  }

  private extractInlineScripts($: cheerio.CheerioAPI, url: string): void {
    $("script:not([src])").each((_, script) => {
      const content = $(script).html();
      if (content) {
        this.extractUrlsFromJavaScript(content, url);
        this.extractWebSocketEndpoints(content, url);
        this.extractDynamicRoutes(content);
        this.extractAuthTokenPatterns(content);
        this.extractInterceptorPatterns(content, url);
        this.extractGraphQLOperations(content);
      }
    });
  }

  private extractWebSocketEndpoints(content: string, sourceUrl: string): void {
    for (const pattern of WEBSOCKET_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let wsUrl = match[1] || match[0];
        
        if (wsUrl.startsWith("ws://") || wsUrl.startsWith("wss://")) {
          this.webSocketEndpoints.add(wsUrl);
        } else if (wsUrl.startsWith("/")) {
          try {
            const parsed = new URL(sourceUrl);
            const protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
            const fullWsUrl = `${protocol}//${parsed.host}${wsUrl}`;
            this.webSocketEndpoints.add(fullWsUrl);
          } catch {}
        }
      }
    }
  }

  private extractDynamicRoutes(content: string): void {
    for (const pattern of DYNAMIC_ROUTE_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const route = match[1] || match[0];
        if (route && route.length < 200) {
          this.dynamicRoutes.add(route);
          
          const paramMatch = route.match(/\$\{(\w+)\}|:(\w+)|\[(\w+)\]/g);
          if (paramMatch) {
            for (const param of paramMatch) {
              const cleanParam = param.replace(/[\$\{\}:\[\]]/g, "");
              if (cleanParam) {
                this.addParameterSource(cleanParam, "path", undefined, this.isSensitiveParam(cleanParam));
              }
            }
          }
        }
      }
    }
  }

  private extractAuthTokenPatterns(content: string): void {
    for (const pattern of AUTH_TOKEN_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const tokenName = match[1];
        if (tokenName) {
          this.addParameterSource(tokenName, "header", undefined, true);
        }
      }
    }
  }

  private extractInterceptorPatterns(content: string, sourceUrl: string): void {
    for (const pattern of INTERCEPTOR_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const headerPatterns = [
          /headers\s*\[\s*["'`]([^"'`]+)["'`]\s*\]\s*=/g,
          /setHeader\s*\(\s*["'`]([^"'`]+)["'`]/g,
          /headers\s*:\s*\{([^}]+)\}/g,
        ];

        for (const hp of headerPatterns) {
          hp.lastIndex = 0;
          let match;
          while ((match = hp.exec(content)) !== null) {
            const headerContent = match[1];
            if (headerContent) {
              const headerNames = headerContent.match(/["'`]([^"'`]+)["'`]\s*:/g);
              if (headerNames) {
                for (const h of headerNames) {
                  const name = h.replace(/["'`:]/g, "").trim();
                  if (name) {
                    this.addParameterSource(name, "header", undefined, this.isSensitiveParam(name));
                  }
                }
              } else if (!headerContent.includes(":")) {
                this.addParameterSource(headerContent, "header", undefined, this.isSensitiveParam(headerContent));
              }
            }
          }
        }
      }
    }
  }

  private extractGraphQLOperations(content: string): void {
    for (const pattern of GRAPHQL_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const operationOrContent = match[1];
        if (operationOrContent) {
          this.graphqlOperations.add(operationOrContent);
          
          const variableMatches = operationOrContent.match(/\$(\w+)/g);
          if (variableMatches) {
            for (const v of variableMatches) {
              const varName = v.replace("$", "");
              this.addParameterSource(varName, "body", undefined, this.isSensitiveParam(varName));
            }
          }
        }
      }
    }
  }

  private extractScriptSources($: cheerio.CheerioAPI, baseUrl: string): void {
    $("script[src]").each((_, script) => {
      const src = $(script).attr("src");
      if (src) {
        const absoluteSrc = this.resolveUrl(src, baseUrl);
        if (absoluteSrc && isSameDomain(absoluteSrc, this.targetUrl)) {
          this.jsFiles.add(absoluteSrc);
        }
      }
    });
  }

  private async analyzeJsFiles(): Promise<void> {
    await this.onLog("info", `Analyzing ${this.jsFiles.size} JavaScript files for endpoints...`);
    
    for (const jsUrl of Array.from(this.jsFiles)) {
      if (this.visitedUrls.size >= this.maxUrls) break;
      
      try {
        const response = await this.request(jsUrl, { timeout: 15000 });
        if (response.error || response.status !== 200) continue;
        
        this.extractUrlsFromJavaScript(response.body, jsUrl);
        this.extractWebSocketEndpoints(response.body, jsUrl);
        this.extractDynamicRoutes(response.body);
        this.extractAuthTokenPatterns(response.body);
        this.extractInterceptorPatterns(response.body, jsUrl);
        this.extractGraphQLOperations(response.body);
        this.jsFilesAnalyzed++;
      } catch {}
    }
  }

  private extractUrlsFromJavaScript(content: string, sourceUrl: string): void {
    for (const pattern of JS_URL_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const captured = match[1];
        if (!captured) continue;

        if (captured.startsWith("/") || captured.startsWith("http")) {
          try {
            const endpointUrl = this.resolveUrl(captured, sourceUrl);
            if (endpointUrl && isSameDomain(endpointUrl, this.targetUrl)) {
              this.foundUrls.add(endpointUrl);
              
              if (this.isApiEndpoint(endpointUrl)) {
                this.apiEndpoints.add(endpointUrl);
              }

              if (this.isAuthEndpoint(endpointUrl)) {
                this.authEndpoints.add(endpointUrl);
              }

              if (this.isSensitiveEndpoint(endpointUrl)) {
                this.sensitiveEndpoints.add(endpointUrl);
              }
            }
          } catch {}
        }
      }
    }

    const paramPatterns = [
      /[?&](\w+)=/g,
      /params\s*[\[.]?\s*["']?(\w+)/g,
      /query\s*[\[.]?\s*["']?(\w+)/g,
      /body\s*[\[.]?\s*["']?(\w+)/g,
      /formData\.(?:append|set)\s*\(\s*["'](\w+)/g,
      /["'](\w+)["']\s*:\s*(?:["'\d]|true|false|null|\[|\{)/g,
    ];

    const keywords = new Set([
      "function", "return", "const", "let", "var", "if", "else", "true", "false", 
      "null", "undefined", "for", "while", "do", "switch", "case", "break", 
      "continue", "new", "this", "class", "extends", "import", "export", 
      "default", "async", "await", "try", "catch", "finally", "throw",
      "typeof", "instanceof", "in", "of", "delete", "void", "yield",
      "get", "set", "static", "public", "private", "protected",
    ]);

    for (const pattern of paramPatterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const paramName = match[1];
        if (paramName && 
            /^[a-zA-Z_]\w{1,30}$/.test(paramName) && 
            !keywords.has(paramName.toLowerCase())) {
          if (!this.parameters.has(sourceUrl)) {
            this.parameters.set(sourceUrl, new Set());
          }
          this.parameters.get(sourceUrl)!.add(paramName);
          this.addParameterSource(paramName, "body", undefined, this.isSensitiveParam(paramName));
        }
      }
    }
  }

  private async discoverApiEndpoints(): Promise<void> {
    await this.onLog("info", "Discovering OpenAPI/Swagger endpoints...");
    
    for (const path of SWAGGER_PATHS) {
      try {
        const url = this.resolveUrl(path, this.targetUrl);
        if (!url) continue;
        
        const response = await this.request(url, { timeout: 5000 });
        if (response.status === 200) {
          await this.onLog("info", `Found API documentation at ${url}`);
          this.apiEndpoints.add(url);
          
          try {
            const doc = JSON.parse(response.body);
            this.extractFromOpenApiDoc(doc);
          } catch {}
        }
      } catch {}
    }
  }

  private extractFromOpenApiDoc(doc: any): void {
    if (!doc) return;

    const basePath = doc.basePath || "";
    const paths = doc.paths || {};

    for (const path of Object.keys(paths)) {
      const fullPath = basePath + path;
      const endpoint = this.resolveUrl(fullPath, this.targetUrl);
      if (endpoint) {
        this.apiEndpoints.add(endpoint);
        this.foundUrls.add(endpoint);

        if (this.isAuthEndpoint(endpoint)) {
          this.authEndpoints.add(endpoint);
        }

        if (this.isSensitiveEndpoint(endpoint)) {
          this.sensitiveEndpoints.add(endpoint);
        }

        const methods = paths[path];
        for (const method of Object.keys(methods)) {
          const operation = methods[method];
          if (operation.parameters) {
            if (!this.parameters.has(endpoint)) {
              this.parameters.set(endpoint, new Set());
            }
            for (const param of operation.parameters) {
              if (param.name) {
                this.parameters.get(endpoint)!.add(param.name);
                const source = param.in === "query" ? "url" : 
                              param.in === "header" ? "header" :
                              param.in === "path" ? "path" : "body";
                this.addParameterSource(param.name, source as ParameterSource["source"], undefined, this.isSensitiveParam(param.name));
              }
            }
          }
        }
      }
    }
  }

  private extractApiFromHeaders(headers: Record<string, string>, url: string): void {
    const linkHeader = headers["link"];
    if (linkHeader) {
      const linkMatches = linkHeader.match(/<([^>]+)>/g);
      if (linkMatches) {
        for (const match of linkMatches) {
          const linkUrl = match.slice(1, -1);
          const resolved = this.resolveUrl(linkUrl, url);
          if (resolved && isSameDomain(resolved, this.targetUrl)) {
            this.foundUrls.add(resolved);
            if (this.isApiEndpoint(resolved)) {
              this.apiEndpoints.add(resolved);
            }
          }
        }
      }
    }

    const apiHeader = headers["x-api-url"] || headers["api-url"];
    if (apiHeader) {
      const resolved = this.resolveUrl(apiHeader, url);
      if (resolved) {
        this.apiEndpoints.add(resolved);
      }
    }
  }

  private extractFromJson(body: string, url: string): void {
    try {
      const json = JSON.parse(body);
      this.extractUrlsFromObject(json, url);
    } catch {}
  }

  private extractUrlsFromObject(obj: any, baseUrl: string, depth: number = 0): void {
    if (depth > 5 || !obj) return;

    if (typeof obj === "string") {
      if (obj.startsWith("/") || obj.startsWith("http")) {
        try {
          const resolved = this.resolveUrl(obj, baseUrl);
          if (resolved && isSameDomain(resolved, this.targetUrl)) {
            this.foundUrls.add(resolved);
            if (this.isApiEndpoint(resolved)) {
              this.apiEndpoints.add(resolved);
            }
            if (this.isAuthEndpoint(resolved)) {
              this.authEndpoints.add(resolved);
            }
            if (this.isSensitiveEndpoint(resolved)) {
              this.sensitiveEndpoints.add(resolved);
            }
          }
        } catch {}
      }
      return;
    }

    if (Array.isArray(obj)) {
      for (const item of obj) {
        this.extractUrlsFromObject(item, baseUrl, depth + 1);
      }
      return;
    }

    if (typeof obj === "object") {
      for (const key of Object.keys(obj)) {
        const urlKeys = ["url", "href", "link", "endpoint", "api", "path", "uri", "src"];
        if (urlKeys.includes(key.toLowerCase())) {
          const value = obj[key];
          if (typeof value === "string") {
            this.extractUrlsFromObject(value, baseUrl, depth + 1);
          }
        }
        this.extractUrlsFromObject(obj[key], baseUrl, depth + 1);
      }
    }
  }

  private isApiEndpoint(url: string): boolean {
    return API_PATTERNS.some(pattern => pattern.test(url));
  }

  private resolveUrl(href: string, baseUrl: string): string | null {
    try {
      if (href.startsWith("javascript:")) return null;
      if (href.startsWith("mailto:")) return null;
      if (href.startsWith("tel:")) return null;
      if (href.startsWith("#")) return null;
      if (href.startsWith("data:")) return null;
      if (href.startsWith("blob:")) return null;

      const resolved = new URL(href, baseUrl);
      
      if (!["http:", "https:"].includes(resolved.protocol)) {
        return null;
      }

      return normalizeUrl(resolved.toString());
    } catch {
      return null;
    }
  }

  private shouldSkipUrl(url: string): boolean {
    const skipExtensions = [
      ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
      ".css", ".map", ".scss", ".less",
      ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
      ".zip", ".tar", ".gz", ".rar", ".7z",
      ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".flv",
      ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ];

    const lowerUrl = url.toLowerCase();
    return skipExtensions.some(ext => lowerUrl.endsWith(ext));
  }
}
