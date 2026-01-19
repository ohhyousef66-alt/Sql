import { chromium, Browser, Page, BrowserContext, Request, Response } from "playwright";
import { CrawlResult, CrawlStats, FormData, ParameterSource, FormWorkflow } from "./crawler";

export interface PlaywrightCrawlerOptions {
  maxDepth?: number;
  maxUrls?: number;
  timeout?: number;
  waitForNetworkIdle?: boolean;
  captureXHR?: boolean;
  captureFragments?: boolean;
  headless?: boolean;
}

export interface XHRCapture {
  url: string;
  method: string;
  postData?: string;
  headers: Record<string, string>;
  responseStatus?: number;
  responseBody?: string;
}

export interface FragmentCapture {
  hash: string;
  parameters: { name: string; value: string }[];
}

export class PlaywrightCrawler {
  private targetUrl: string;
  private domain: string;
  private visitedUrls: Set<string> = new Set();
  private foundUrls: Set<string> = new Set();
  private foundForms: FormData[] = [];
  private apiEndpoints: Set<string> = new Set();
  private xhrCaptures: XHRCapture[] = [];
  private fragmentCaptures: FragmentCapture[] = [];
  private parameterSources: ParameterSource[] = [];
  private hiddenInputs: Map<string, { name: string; value: string; form?: string }[]> = new Map();
  private options: Required<PlaywrightCrawlerOptions>;
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private onLog: (level: string, message: string) => Promise<void>;

  constructor(
    targetUrl: string,
    onLog: (level: string, message: string) => Promise<void>,
    options: PlaywrightCrawlerOptions = {}
  ) {
    this.targetUrl = targetUrl;
    try {
      this.domain = new URL(targetUrl).hostname;
    } catch {
      this.domain = targetUrl;
    }
    this.onLog = onLog;
    this.options = {
      maxDepth: options.maxDepth ?? 8,
      maxUrls: options.maxUrls ?? 500,
      timeout: options.timeout ?? 30000,
      waitForNetworkIdle: options.waitForNetworkIdle ?? true,
      captureXHR: options.captureXHR ?? true,
      captureFragments: options.captureFragments ?? true,
      headless: options.headless ?? true,
    };
  }

  async crawl(): Promise<CrawlResult & { xhrCaptures: XHRCapture[]; fragmentCaptures: FragmentCapture[] }> {
    await this.onLog("info", `[Playwright] Starting deep crawl on ${this.targetUrl}`);
    await this.onLog("info", `[Playwright] Config: maxDepth=${this.options.maxDepth}, maxUrls=${this.options.maxUrls}, captureXHR=${this.options.captureXHR}`);

    try {
      this.browser = await chromium.launch({
        headless: this.options.headless,
        args: [
          "--no-sandbox",
          "--disable-setuid-sandbox",
          "--disable-dev-shm-usage",
          "--disable-accelerated-2d-canvas",
          "--disable-gpu",
        ],
      });

      this.context = await this.browser.newContext({
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        viewport: { width: 1920, height: 1080 },
        ignoreHTTPSErrors: true,
      });

      await this.crawlUrl(this.targetUrl, 0);

    } catch (error: any) {
      await this.onLog("error", `[Playwright] Crawl error: ${error.message}`);
    } finally {
      if (this.browser) {
        await this.browser.close();
      }
    }

    const stats: CrawlStats = {
      urlsDiscovered: this.foundUrls.size,
      formsFound: this.foundForms.length,
      parametersFound: this.parameterSources.length,
      apiEndpoints: this.apiEndpoints.size,
      jsFilesAnalyzed: 0,
      depth: this.options.maxDepth,
      webSocketEndpoints: 0,
      authEndpointsFound: 0,
      sensitiveEndpointsFound: 0,
      formWorkflowsDetected: 0,
    };

    await this.onLog("info", `[Playwright] Crawl complete. URLs: ${stats.urlsDiscovered}, Forms: ${stats.formsFound}, XHR: ${this.xhrCaptures.length}`);

    return {
      urls: Array.from(this.foundUrls),
      forms: this.foundForms,
      apiEndpoints: Array.from(this.apiEndpoints),
      parameters: new Map(),
      parameterSources: this.parameterSources,
      formWorkflows: [],
      authEndpoints: [],
      sensitiveEndpoints: [],
      webSocketEndpoints: [],
      dynamicRoutes: [],
      headerParameters: [],
      hiddenFields: new Map(),
      stats,
      xhrCaptures: this.xhrCaptures,
      fragmentCaptures: this.fragmentCaptures,
    };
  }

  private async crawlUrl(url: string, depth: number): Promise<void> {
    if (depth > this.options.maxDepth) return;
    if (this.visitedUrls.size >= this.options.maxUrls) return;
    if (this.visitedUrls.has(url)) return;

    this.visitedUrls.add(url);
    this.foundUrls.add(url);

    if (!this.context) return;

    const page = await this.context.newPage();

    try {
      if (this.options.captureXHR) {
        this.setupNetworkInterception(page, url);
      }

      await this.onLog("debug", `[Playwright] Navigating to ${url} (depth: ${depth})`);

      const response = await page.goto(url, {
        timeout: this.options.timeout,
        waitUntil: this.options.waitForNetworkIdle ? "networkidle" : "domcontentloaded",
      });

      if (!response) {
        await this.onLog("debug", `[Playwright] No response for ${url}`);
        return;
      }

      const status = response.status();
      if (status >= 400) {
        await this.onLog("debug", `[Playwright] HTTP ${status} for ${url}`);
        return;
      }

      await this.onLog("info", `[Playwright] Loaded ${url} (${status})`);

      await this.extractForms(page, url);
      await this.extractHiddenInputs(page, url);
      await this.extractLinks(page, url, depth);
      
      if (this.options.captureFragments) {
        await this.extractFragments(page, url);
      }

      await this.triggerDynamicContent(page);

    } catch (error: any) {
      await this.onLog("debug", `[Playwright] Error on ${url}: ${error.message}`);
    } finally {
      await page.close();
    }
  }

  private setupNetworkInterception(page: Page, sourceUrl: string): void {
    page.on("request", (request: Request) => {
      const url = request.url();
      const method = request.method();
      
      if (this.isApiRequest(url) || method !== "GET") {
        this.xhrCaptures.push({
          url,
          method,
          postData: request.postData() || undefined,
          headers: request.headers(),
        });
        
        if (this.isApiRequest(url)) {
          this.apiEndpoints.add(url);
        }
        
        this.extractParametersFromRequest(request);
      }
    });

    page.on("response", async (response: Response) => {
      const url = response.url();
      const request = response.request();
      
      if (this.isApiRequest(url) || request.method() !== "GET") {
        const existingCapture = this.xhrCaptures.find(c => c.url === url);
        if (existingCapture) {
          existingCapture.responseStatus = response.status();
          try {
            const body = await response.text();
            existingCapture.responseBody = body.substring(0, 10000);
          } catch {}
        }
      }
    });
  }

  private extractParametersFromRequest(request: Request): void {
    const url = request.url();
    const method = request.method();
    
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((value, name) => {
        this.addParameterSource(name, "url", value);
      });
    } catch {}

    const postData = request.postData();
    if (postData && method === "POST") {
      if (postData.startsWith("{")) {
        try {
          const json = JSON.parse(postData);
          this.extractJsonParameters(json, "");
        } catch {}
      } else {
        const params = new URLSearchParams(postData);
        params.forEach((value, name) => {
          this.addParameterSource(name, "body", value);
        });
      }
    }

    const headers = request.headers();
    const interestingHeaders = ["authorization", "x-api-key", "x-auth-token", "x-csrf-token"];
    for (const header of interestingHeaders) {
      if (headers[header]) {
        this.addParameterSource(header, "header", headers[header].substring(0, 50));
      }
    }
  }

  private extractJsonParameters(obj: any, prefix: string, depth: number = 0): void {
    if (depth > 10 || !obj) return;

    if (typeof obj === "object" && !Array.isArray(obj)) {
      for (const key of Object.keys(obj)) {
        const value = obj[key];
        if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
          this.addParameterSource(key, "body", String(value).substring(0, 50));
        } else if (typeof value === "object") {
          this.extractJsonParameters(value, `${prefix}.${key}`, depth + 1);
        }
      }
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        this.extractJsonParameters(item, prefix, depth + 1);
      }
    }
  }

  private async extractForms(page: Page, sourceUrl: string): Promise<void> {
    const forms = await page.evaluate(() => {
      const formElements = document.querySelectorAll("form");
      return Array.from(formElements).map(form => {
        const inputs = Array.from(form.querySelectorAll("input, select, textarea")).map(input => {
          const el = input as HTMLInputElement;
          return {
            name: el.name || el.id || "",
            type: el.type || "text",
            value: el.value || "",
            isHidden: el.type === "hidden",
            isRequired: el.required || false,
          };
        }).filter(i => i.name);

        return {
          action: form.action || window.location.href,
          method: (form.method || "GET").toUpperCase(),
          inputs,
          enctype: form.enctype || undefined,
          id: form.id || undefined,
        };
      });
    });

    for (const form of forms) {
      this.foundForms.push(form as FormData);
      
      for (const input of form.inputs) {
        this.addParameterSource(input.name, "body", input.value);
      }
    }

    await this.onLog("debug", `[Playwright] Found ${forms.length} forms on ${sourceUrl}`);
  }

  private async extractHiddenInputs(page: Page, sourceUrl: string): Promise<void> {
    const hiddenInputs = await page.evaluate(() => {
      const inputs = document.querySelectorAll('input[type="hidden"]');
      return Array.from(inputs).map(input => {
        const el = input as HTMLInputElement;
        const form = el.closest("form");
        return {
          name: el.name || el.id || "",
          value: el.value || "",
          form: form?.id || form?.action || undefined,
        };
      }).filter(i => i.name);
    });

    this.hiddenInputs.set(sourceUrl, hiddenInputs);
    
    for (const input of hiddenInputs) {
      this.addParameterSource(input.name, "body", input.value);
    }

    await this.onLog("debug", `[Playwright] Found ${hiddenInputs.length} hidden inputs on ${sourceUrl}`);
  }

  private async extractLinks(page: Page, sourceUrl: string, depth: number): Promise<void> {
    const links = await page.evaluate(() => {
      const anchors = document.querySelectorAll("a[href]");
      return Array.from(anchors).map(a => (a as HTMLAnchorElement).href).filter(href => href);
    });

    const sameDomainLinks = links.filter(link => {
      try {
        return new URL(link).hostname === this.domain;
      } catch {
        return false;
      }
    });

    await this.onLog("debug", `[Playwright] Found ${sameDomainLinks.length} same-domain links on ${sourceUrl}`);

    for (const link of sameDomainLinks) {
      if (!this.visitedUrls.has(link) && this.visitedUrls.size < this.options.maxUrls) {
        await this.crawlUrl(link, depth + 1);
      }
    }
  }

  private async extractFragments(page: Page, sourceUrl: string): Promise<void> {
    const fragments = await page.evaluate(() => {
      const anchors = document.querySelectorAll('a[href*="#"]');
      const hashes: { hash: string; parameters: { name: string; value: string }[] }[] = [];
      
      for (const anchor of Array.from(anchors)) {
        const href = (anchor as HTMLAnchorElement).href;
        try {
          const url = new URL(href);
          if (url.hash && url.hash.length > 1) {
            const hash = url.hash.substring(1);
            const params: { name: string; value: string }[] = [];
            
            if (hash.includes("=")) {
              const hashParams = new URLSearchParams(hash);
              hashParams.forEach((value, name) => {
                params.push({ name, value });
              });
            }
            
            hashes.push({ hash, parameters: params });
          }
        } catch {}
      }
      
      return hashes;
    });

    this.fragmentCaptures.push(...fragments);
    
    for (const fragment of fragments) {
      for (const param of fragment.parameters) {
        this.addParameterSource(param.name, "url", param.value);
      }
    }
  }

  private async triggerDynamicContent(page: Page): Promise<void> {
    try {
      await page.evaluate(() => {
        window.scrollTo(0, document.body.scrollHeight);
      });
      await page.waitForTimeout(500);

      const buttons = await page.$$('button, [role="button"], .btn');
      for (const button of buttons.slice(0, 3)) {
        try {
          const isVisible = await button.isVisible();
          if (isVisible) {
            await button.click({ timeout: 1000 }).catch(() => {});
            await page.waitForTimeout(300);
          }
        } catch {}
      }

      const expandables = await page.$$('[data-toggle], [aria-expanded], .accordion, .collapse');
      for (const el of expandables.slice(0, 3)) {
        try {
          await el.click({ timeout: 500 }).catch(() => {});
        } catch {}
      }

    } catch {}
  }

  private isApiRequest(url: string): boolean {
    const apiPatterns = [
      /\/api\//i,
      /\/v[0-9]+\//i,
      /\/rest\//i,
      /\/graphql/i,
      /\.json$/i,
      /\/ajax\//i,
      /\/xhr\//i,
    ];
    return apiPatterns.some(pattern => pattern.test(url));
  }

  private addParameterSource(name: string, source: ParameterSource["source"], sampleValue?: string): void {
    const exists = this.parameterSources.some(p => p.name === name && p.source === source);
    if (!exists && name) {
      this.parameterSources.push({
        name,
        source,
        sampleValue,
        sensitive: this.isSensitiveParam(name),
      });
    }
  }

  private isSensitiveParam(name: string): boolean {
    const sensitivePatterns = /token|auth|key|secret|password|session|jwt|bearer|credential|private|csrf|nonce/i;
    return sensitivePatterns.test(name);
  }
}
