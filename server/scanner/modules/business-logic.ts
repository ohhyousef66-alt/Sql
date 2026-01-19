import { makeRequest, RequestResult, sleep, extractParameters, injectPayload, randomString, hashString, parseUrl } from "../utils";
import { InsertVulnerability, VerificationStatus } from "@shared/schema";
import { ParameterSource } from "../crawler";

type LogCallback = (level: string, message: string) => Promise<void>;
type VulnCallback = (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;

interface FormData {
  action: string;
  method: string;
  inputs: Array<{
    name: string;
    type: string;
    value?: string;
  }>;
}

interface BusinessLogicResult {
  vulnerable: boolean;
  type: "parameter-tampering" | "idor" | "access-control" | "method-override";
  subType: string;
  payload: string;
  evidence: string;
  url: string;
  parameter?: string;
  confidence: number;
  verificationStatus: VerificationStatus;
  verificationDetails: string;
}

interface ResponseSignature {
  status: number;
  size: number;
  bodyHash: string;
  hasUserData: boolean;
  dataPatterns: string[];
}

const PARAMETER_TAMPERING_PAYLOADS = {
  price: [
    { value: "0", description: "zero price" },
    { value: "-1", description: "negative price" },
    { value: "0.01", description: "minimal price" },
    { value: "0.001", description: "sub-cent price" },
    { value: "-9999", description: "large negative" },
  ],
  quantity: [
    { value: "999999", description: "excessive quantity" },
    { value: "-1", description: "negative quantity" },
    { value: "0", description: "zero quantity" },
    { value: "2147483647", description: "integer overflow" },
  ],
  role: [
    { value: "admin", description: "admin role" },
    { value: "administrator", description: "administrator role" },
    { value: "root", description: "root role" },
    { value: "superuser", description: "superuser role" },
    { value: "1", description: "numeric admin" },
  ],
  privilege: [
    { value: "true", description: "boolean true" },
    { value: "1", description: "numeric true" },
    { value: "yes", description: "yes string" },
    { value: "admin", description: "admin string" },
  ],
  id: [
    { value: "1", description: "first user ID" },
    { value: "0", description: "zero ID" },
    { value: "-1", description: "negative ID" },
  ],
  limit: [
    { value: "99999", description: "excessive limit" },
    { value: "-1", description: "negative limit" },
    { value: "0", description: "zero limit" },
    { value: "2147483647", description: "max integer" },
  ],
  offset: [
    { value: "-1", description: "negative offset" },
    { value: "0", description: "zero offset" },
    { value: "999999999", description: "large offset" },
  ],
};

const SENSITIVE_PARAM_PATTERNS = {
  price: /price|cost|amount|total|subtotal|fee|charge/i,
  quantity: /qty|quantity|count|num|number|units/i,
  role: /role|user_?type|account_?type|permission|access_?level/i,
  privilege: /is_?admin|admin|is_?super|is_?staff|is_?mod|privileged|elevated/i,
  id: /user_?id|account_?id|customer_?id|owner_?id|author_?id|profile_?id/i,
  limit: /limit|per_?page|page_?size|max_?results|count/i,
  offset: /offset|skip|start|page|from/i,
};

const ADMIN_PATHS = [
  "/admin",
  "/administrator",
  "/admin.php",
  "/wp-admin",
  "/config",
  "/configuration",
  "/settings",
  "/debug",
  "/console",
  "/dashboard",
  "/manage",
  "/management",
  "/panel",
  "/control",
  "/system",
  "/internal",
  "/private",
  "/api/admin",
  "/api/internal",
];

const METHOD_OVERRIDE_HEADERS = [
  "X-HTTP-Method-Override",
  "X-HTTP-Method",
  "X-Method-Override",
];

const MAX_ADJACENT_IDS = 3;
const MIN_RESPONSE_DIFFERENCE_THRESHOLD = 0.15;

export class BusinessLogicModule {
  private targetUrl: string;
  private foundVulnerabilities: BusinessLogicResult[] = [];
  private onLog: LogCallback;
  private onVuln: VulnCallback;
  private testedEndpoints: Set<string> = new Set();
  private abortSignal?: AbortSignal;

  constructor(
    targetUrl: string,
    onLog: LogCallback,
    onVuln: VulnCallback,
    abortSignal?: AbortSignal
  ) {
    this.targetUrl = targetUrl;
    this.onLog = onLog;
    this.onVuln = onVuln;
    this.abortSignal = abortSignal;
  }

  private async request(url: string, options: Parameters<typeof makeRequest>[1] = {}): Promise<ReturnType<typeof makeRequest>> {
    return makeRequest(url, { ...options, signal: this.abortSignal });
  }

  async scan(
    urls: string[],
    parameters: ParameterSource[] = [],
    forms: FormData[] = []
  ): Promise<void> {
    await this.onLog("info", "Starting Business Logic vulnerability scan...");

    await this.testParameterTampering(urls, parameters);
    await this.testIDOR(urls);
    await this.testAccessControlBypass(urls);
    await this.testMethodOverride(urls);

    if (forms.length > 0) {
      await this.testFormParameterTampering(forms);
    }

    await this.onLog("info", `Business Logic scan complete. Found ${this.foundVulnerabilities.length} potential issues.`);
  }

  private async testParameterTampering(urls: string[], parameters: ParameterSource[]): Promise<void> {
    await this.onLog("info", "Testing for parameter tampering vulnerabilities...");

    for (const url of urls) {
      const urlParams = extractParameters(url);
      
      for (const param of urlParams) {
        await this.testParameterForTampering(url, param.name, param.value);
      }
    }

    for (const param of parameters) {
      if (param.source === "url" || param.source === "body") {
        const baseValue = param.sampleValue || this.getDefaultValueForParam(param.name);
        const testUrl = this.constructTestUrl(param.name, baseValue);
        await this.testParameterForTampering(testUrl, param.name, baseValue);
      }
    }
  }

  private getDefaultValueForParam(paramName: string): string {
    const lowerName = paramName.toLowerCase();
    
    if (SENSITIVE_PARAM_PATTERNS.price.test(lowerName)) {
      return "100";
    }
    if (SENSITIVE_PARAM_PATTERNS.quantity.test(lowerName)) {
      return "1";
    }
    if (SENSITIVE_PARAM_PATTERNS.id.test(lowerName)) {
      return "1";
    }
    if (SENSITIVE_PARAM_PATTERNS.limit.test(lowerName)) {
      return "10";
    }
    if (SENSITIVE_PARAM_PATTERNS.offset.test(lowerName)) {
      return "0";
    }
    if (SENSITIVE_PARAM_PATTERNS.role.test(lowerName)) {
      return "user";
    }
    if (SENSITIVE_PARAM_PATTERNS.privilege.test(lowerName)) {
      return "false";
    }
    
    return "";
  }

  private constructTestUrl(paramName: string, paramValue: string): string {
    const separator = this.targetUrl.includes("?") ? "&" : "?";
    return `${this.targetUrl}${separator}${encodeURIComponent(paramName)}=${encodeURIComponent(paramValue)}`;
  }

  private async testParameterForTampering(url: string, paramName: string, originalValue: string): Promise<void> {
    const testKey = `${url}:${paramName}:tampering`;
    if (this.testedEndpoints.has(testKey)) return;
    this.testedEndpoints.add(testKey);

    const baseline = await this.getResponseSignature(url);
    if (!baseline) return;

    const lowerParamName = paramName.toLowerCase();

    for (const [category, pattern] of Object.entries(SENSITIVE_PARAM_PATTERNS)) {
      if (pattern.test(lowerParamName)) {
        const payloads = PARAMETER_TAMPERING_PAYLOADS[category as keyof typeof PARAMETER_TAMPERING_PAYLOADS];
        if (payloads) {
          await this.onLog("info", `Testing '${paramName}' for ${category} tampering...`);
          
          for (const payload of payloads) {
            const result = await this.testTamperPayload(url, paramName, payload.value, payload.description, baseline, category);
            if (result) {
              this.foundVulnerabilities.push(result);
              await this.reportVulnerability(result);
              return;
            }
            await sleep(100);
          }
        }
        break;
      }
    }
  }

  private async testTamperPayload(
    url: string,
    paramName: string,
    payload: string,
    description: string,
    baseline: ResponseSignature,
    category: string
  ): Promise<BusinessLogicResult | null> {
    const testUrl = injectPayload(url, paramName, payload);
    const response = await this.request(testUrl, { timeout: 10000 });

    if (response.error || response.status === 0) return null;

    const testSignature = this.extractSignature(response);
    const analysis = this.analyzeResponseDifference(baseline, testSignature, category);

    if (analysis.isSuspicious) {
      const controlUrl = injectPayload(url, paramName, `${randomString(8)}_control`);
      const controlResponse = await this.request(controlUrl, { timeout: 10000 });
      const controlSignature = this.extractSignature(controlResponse);

      if (this.signaturesMatch(testSignature, controlSignature)) {
        return null;
      }

      const verifyUrl = injectPayload(url, paramName, payload);
      const verifyResponse = await this.request(verifyUrl, { timeout: 10000 });
      const verifySignature = this.extractSignature(verifyResponse);

      if (!this.signaturesMatch(testSignature, verifySignature)) {
        return null;
      }

      return {
        vulnerable: true,
        type: "parameter-tampering",
        subType: category,
        payload: `${paramName}=${payload}`,
        evidence: analysis.evidence,
        url,
        parameter: paramName,
        confidence: analysis.confidence,
        verificationStatus: analysis.confidence >= 90 ? "confirmed" : "potential",
        verificationDetails: `Parameter tampering (${category}): ${description} accepted. ${analysis.details}. Control test passed - random values produce different response. Verification test passed - consistent behavior on retry.`,
      };
    }

    return null;
  }

  private async testIDOR(urls: string[]): Promise<void> {
    await this.onLog("info", "Testing for IDOR vulnerabilities (safe enumeration)...");

    const idPatterns = [
      /\/users?\/(\d+)/i,
      /\/accounts?\/(\d+)/i,
      /\/profiles?\/(\d+)/i,
      /\/orders?\/(\d+)/i,
      /\/invoices?\/(\d+)/i,
      /\/documents?\/(\d+)/i,
      /\/files?\/(\d+)/i,
      /\/messages?\/(\d+)/i,
      /\/posts?\/(\d+)/i,
      /\/comments?\/(\d+)/i,
      /\/items?\/(\d+)/i,
      /\/products?\/(\d+)/i,
      /\/transactions?\/(\d+)/i,
      /[?&]id=(\d+)/i,
      /[?&]user_?id=(\d+)/i,
      /[?&]account_?id=(\d+)/i,
      /[?&]doc_?id=(\d+)/i,
    ];

    for (const url of urls) {
      const testKey = `${url}:idor`;
      if (this.testedEndpoints.has(testKey)) continue;

      for (const pattern of idPatterns) {
        const match = url.match(pattern);
        if (match && match[1]) {
          const originalId = parseInt(match[1], 10);
          if (!isNaN(originalId) && originalId > 0) {
            this.testedEndpoints.add(testKey);
            await this.testIDOREndpoint(url, originalId, pattern);
            break;
          }
        }
      }
    }
  }

  private async testIDOREndpoint(url: string, originalId: number, pattern: RegExp): Promise<void> {
    await this.onLog("info", `Testing IDOR at ${url.substring(0, 80)}...`);

    const originalResponse = await this.request(url, { timeout: 10000 });
    if (originalResponse.error || originalResponse.status === 0) return;

    const baselineSignature = this.extractSignature(originalResponse);

    const adjacentIds: number[] = [];
    if (originalId > 1) adjacentIds.push(originalId - 1);
    if (originalId > 2) adjacentIds.push(originalId - 2);
    adjacentIds.push(originalId + 1);

    const limitedIds = adjacentIds.slice(0, MAX_ADJACENT_IDS);

    let successfulAccess = 0;
    let differentDataFound = false;
    let accessedIds: number[] = [];
    let evidence = "";

    for (const testId of limitedIds) {
      const testUrl = url.replace(pattern, (match) => {
        return match.replace(originalId.toString(), testId.toString());
      });

      const testResponse = await this.request(testUrl, { timeout: 10000 });

      if (testResponse.error || testResponse.status === 0) continue;

      if (testResponse.status === 200) {
        const testSignature = this.extractSignature(testResponse);
        
        if (testSignature.hasUserData && !this.signaturesMatch(baselineSignature, testSignature)) {
          differentDataFound = true;
          successfulAccess++;
          accessedIds.push(testId);
          
          if (!evidence) {
            evidence = `Accessed ID ${testId} returned different user data (status: ${testResponse.status}, size: ${testResponse.contentLength} vs baseline ${originalResponse.contentLength})`;
          }
        }
      }

      await sleep(200);
    }

    if (differentDataFound && successfulAccess >= 2) {
      const confidence = successfulAccess >= 3 ? 95 : (successfulAccess >= 2 ? 85 : 70);
      
      const result: BusinessLogicResult = {
        vulnerable: true,
        type: "idor",
        subType: "sequential-id-access",
        payload: `Tested IDs: ${accessedIds.join(", ")}`,
        evidence,
        url,
        confidence,
        verificationStatus: confidence >= 90 ? "confirmed" : "potential",
        verificationDetails: `IDOR detected: Successfully accessed ${successfulAccess} adjacent IDs with different data. Testing limited to ${MAX_ADJACENT_IDS} adjacent IDs per endpoint. Response signatures differ significantly, indicating access to different user records.`,
      };

      this.foundVulnerabilities.push(result);
      await this.reportVulnerability(result);
    }
  }

  private async testAccessControlBypass(urls: string[]): Promise<void> {
    await this.onLog("info", "Testing for access control bypass vulnerabilities...");

    const baseUrl = new URL(this.targetUrl).origin;

    for (const adminPath of ADMIN_PATHS) {
      await this.testAdminPath(baseUrl, adminPath);
    }

    for (const url of urls.slice(0, 10)) {
      await this.testCaseVariation(url);
    }
  }

  private async testAdminPath(baseUrl: string, path: string): Promise<void> {
    const testKey = `${baseUrl}${path}:access`;
    if (this.testedEndpoints.has(testKey)) return;
    this.testedEndpoints.add(testKey);

    const testUrl = `${baseUrl}${path}`;

    const response = await this.request(testUrl, { timeout: 10000 });

    if (response.error || response.status === 0) return;

    if (response.status === 200 && response.contentLength > 100) {
      const hasAdminContent = this.detectAdminContent(response.body);
      
      if (hasAdminContent) {
        const retryResponse = await this.request(testUrl, { timeout: 10000 });
        
        if (retryResponse.status === 200 && this.detectAdminContent(retryResponse.body)) {
          const confidence = this.calculateAdminAccessConfidence(response, path);
          
          const result: BusinessLogicResult = {
            vulnerable: true,
            type: "access-control",
            subType: "admin-path-exposure",
            payload: path,
            evidence: `Admin path accessible without authentication. Response contains administrative content.`,
            url: testUrl,
            confidence,
            verificationStatus: confidence >= 90 ? "confirmed" : "potential",
            verificationDetails: `Access control bypass: Admin path '${path}' returned HTTP 200 with ${response.contentLength} bytes of content. Page contains administrative keywords/functionality. Verified with retry request.`,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result);
        }
      }
    }

    await sleep(100);
  }

  private detectAdminContent(body: string): boolean {
    const adminKeywords = [
      /admin\s*(panel|dashboard|console|area)/i,
      /user\s*management/i,
      /system\s*settings/i,
      /configuration\s*options/i,
      /<form[^>]*(?:action|method)[^>]*(?:user|config|setting)/i,
      /delete\s*user/i,
      /manage\s*users/i,
      /role\s*assignment/i,
      /permission\s*settings/i,
      /database\s*(?:config|settings)/i,
    ];

    const matchCount = adminKeywords.filter(pattern => pattern.test(body)).length;
    return matchCount >= 2;
  }

  private calculateAdminAccessConfidence(response: RequestResult, path: string): number {
    let confidence = 70;

    if (response.contentLength > 500) confidence += 5;
    if (response.contentLength > 2000) confidence += 5;

    const criticalPaths = ["/admin", "/wp-admin", "/administrator", "/dashboard"];
    if (criticalPaths.includes(path.toLowerCase())) confidence += 10;

    if (response.body.includes("<form")) confidence += 5;

    return Math.min(confidence, 95);
  }

  private async testCaseVariation(url: string): Promise<void> {
    const parsed = parseUrl(url);
    const path = parsed.path;

    if (!path || path === "/") return;

    const variations = [
      path.toUpperCase(),
      path.charAt(0).toUpperCase() + path.slice(1).toLowerCase(),
      path.toLowerCase(),
    ].filter(v => v !== path);

    const baseUrl = `${parsed.protocol}//${parsed.host}${parsed.port !== "80" && parsed.port !== "443" ? `:${parsed.port}` : ""}`;
    const originalResponse = await this.request(url, { timeout: 10000 });

    if (originalResponse.error || originalResponse.status !== 403 && originalResponse.status !== 401) {
      return;
    }

    for (const variation of variations) {
      const testUrl = `${baseUrl}${variation}`;
      const testResponse = await this.request(testUrl, { timeout: 10000 });

      if (!testResponse.error && testResponse.status === 200 && testResponse.contentLength > 100) {
        const retryResponse = await this.request(testUrl, { timeout: 10000 });
        
        if (retryResponse.status === 200) {
          const result: BusinessLogicResult = {
            vulnerable: true,
            type: "access-control",
            subType: "case-sensitivity-bypass",
            payload: variation,
            evidence: `Original path returned ${originalResponse.status}, case-varied path '${variation}' returned 200 OK`,
            url: testUrl,
            confidence: 85,
            verificationStatus: "potential",
            verificationDetails: `Access control bypass via case variation: Path '${path}' blocked (${originalResponse.status}) but '${variation}' accessible (200). This may indicate case-insensitive filesystem but case-sensitive authorization check.`,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result);
          break;
        }
      }

      await sleep(100);
    }
  }

  private async testMethodOverride(urls: string[]): Promise<void> {
    await this.onLog("info", "Testing for HTTP method override vulnerabilities...");

    for (const url of urls.slice(0, 10)) {
      await this.testMethodOverrideOnUrl(url);
    }
  }

  private async testMethodOverrideOnUrl(url: string): Promise<void> {
    const testKey = `${url}:method-override`;
    if (this.testedEndpoints.has(testKey)) return;
    this.testedEndpoints.add(testKey);

    const getResponse = await this.request(url, { method: "GET", timeout: 10000 });
    if (getResponse.error) return;

    for (const header of METHOD_OVERRIDE_HEADERS) {
      const overrideResponse = await this.request(url, {
        method: "GET",
        headers: { [header]: "DELETE" },
        timeout: 10000,
      });

      if (!overrideResponse.error && this.detectMethodOverrideSuccess(getResponse, overrideResponse, "DELETE")) {
        const verifyResponse = await this.request(url, {
          method: "GET",
          headers: { [header]: "DELETE" },
          timeout: 10000,
        });

        if (this.detectMethodOverrideSuccess(getResponse, verifyResponse, "DELETE")) {
          const result: BusinessLogicResult = {
            vulnerable: true,
            type: "method-override",
            subType: "header-override",
            payload: `${header}: DELETE`,
            evidence: `GET request with ${header}: DELETE header produced different response than standard GET`,
            url,
            confidence: 80,
            verificationStatus: "potential",
            verificationDetails: `HTTP method override detected: Server accepts ${header} header to change request method. GET with override header produced status ${overrideResponse.status} vs normal GET status ${getResponse.status}. This may allow bypassing method-based access controls.`,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result);
          return;
        }
      }

      await sleep(100);
    }

    const methodParamUrl = url.includes("?") ? `${url}&_method=DELETE` : `${url}?_method=DELETE`;
    const paramOverrideResponse = await this.request(methodParamUrl, {
      method: "GET",
      timeout: 10000,
    });

    if (!paramOverrideResponse.error && this.detectMethodOverrideSuccess(getResponse, paramOverrideResponse, "DELETE")) {
      const verifyUrl = url.includes("?") ? `${url}&_method=DELETE` : `${url}?_method=DELETE`;
      const verifyResponse = await this.request(verifyUrl, {
        method: "GET",
        timeout: 10000,
      });

      if (this.detectMethodOverrideSuccess(getResponse, verifyResponse, "DELETE")) {
        const result: BusinessLogicResult = {
          vulnerable: true,
          type: "method-override",
          subType: "param-override",
          payload: "_method=DELETE",
          evidence: `GET request with _method=DELETE parameter produced different response than standard GET`,
          url,
          confidence: 75,
          verificationStatus: "potential",
          verificationDetails: `HTTP method override via parameter detected: Server accepts _method query parameter to change request method. This is a common pattern but may allow bypassing method-based access controls if not properly validated.`,
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result);
      }
    }
  }

  private detectMethodOverrideSuccess(originalResponse: RequestResult, overrideResponse: RequestResult, targetMethod: string): boolean {
    if (overrideResponse.status !== originalResponse.status) {
      if (overrideResponse.status === 405) return false;
      if (overrideResponse.status >= 200 && overrideResponse.status < 400) {
        return true;
      }
    }

    const sizeDiff = Math.abs(overrideResponse.contentLength - originalResponse.contentLength);
    const percentDiff = originalResponse.contentLength > 0 ? sizeDiff / originalResponse.contentLength : 0;

    if (percentDiff > 0.3) {
      return true;
    }

    const deleteIndicators = [
      /deleted/i,
      /removed/i,
      /success.*delete/i,
      /delete.*success/i,
    ];

    for (const indicator of deleteIndicators) {
      if (indicator.test(overrideResponse.body) && !indicator.test(originalResponse.body)) {
        return true;
      }
    }

    return false;
  }

  private async testFormParameterTampering(forms: FormData[]): Promise<void> {
    await this.onLog("info", "Testing form parameters for tampering vulnerabilities...");

    for (const form of forms) {
      for (const input of form.inputs) {
        if (input.type === "hidden" || input.type === "text" || input.type === "number") {
          const lowerName = input.name.toLowerCase();
          
          for (const [category, pattern] of Object.entries(SENSITIVE_PARAM_PATTERNS)) {
            if (pattern.test(lowerName)) {
              await this.onLog("info", `Found sensitive form field: ${input.name} (${category})`);
              
              const result: BusinessLogicResult = {
                vulnerable: true,
                type: "parameter-tampering",
                subType: `form-${category}`,
                payload: `Form field: ${input.name}`,
                evidence: `Sensitive ${category} parameter found in form as ${input.type} input`,
                url: form.action,
                parameter: input.name,
                confidence: input.type === "hidden" ? 75 : 60,
                verificationStatus: "potential",
                verificationDetails: `Business logic risk: Form contains ${input.type} field '${input.name}' that appears to control ${category}. Hidden fields are particularly risky as they may be trusted by the server without validation. Manual testing recommended.`,
              };

              this.foundVulnerabilities.push(result);
              await this.reportVulnerability(result);
              break;
            }
          }
        }
      }
    }
  }

  private async getResponseSignature(url: string): Promise<ResponseSignature | null> {
    const response = await this.request(url, { timeout: 10000 });
    if (response.error || response.status === 0) return null;
    return this.extractSignature(response);
  }

  private extractSignature(response: RequestResult): ResponseSignature {
    const dataPatterns: string[] = [];

    const emailMatch = response.body.match(/[\w.-]+@[\w.-]+\.\w+/g);
    if (emailMatch) dataPatterns.push(`emails:${emailMatch.length}`);

    const phoneMatch = response.body.match(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g);
    if (phoneMatch) dataPatterns.push(`phones:${phoneMatch.length}`);

    const nameMatch = response.body.match(/"name"\s*:\s*"[^"]+"/g);
    if (nameMatch) dataPatterns.push(`names:${nameMatch.length}`);

    const hasUserData = dataPatterns.length > 0 || 
      /user|profile|account|email|name|address/i.test(response.body);

    return {
      status: response.status,
      size: response.contentLength,
      bodyHash: hashString(response.body),
      hasUserData,
      dataPatterns,
    };
  }

  private signaturesMatch(sig1: ResponseSignature, sig2: ResponseSignature): boolean {
    if (sig1.status !== sig2.status) return false;
    if (sig1.bodyHash === sig2.bodyHash) return true;

    const sizeDiff = Math.abs(sig1.size - sig2.size);
    const percentDiff = sig1.size > 0 ? sizeDiff / sig1.size : 0;

    return percentDiff < 0.05;
  }

  private analyzeResponseDifference(
    baseline: ResponseSignature,
    test: ResponseSignature,
    category: string
  ): { isSuspicious: boolean; confidence: number; evidence: string; details: string } {
    const result = {
      isSuspicious: false,
      confidence: 50,
      evidence: "",
      details: "",
    };

    if (test.status !== baseline.status) {
      if (test.status >= 200 && test.status < 300) {
        result.isSuspicious = true;
        result.confidence = 70;
        result.evidence = `Status changed from ${baseline.status} to ${test.status}`;
        result.details = `Server accepted manipulated ${category} value with success status`;
      }
      return result;
    }

    const sizeDiff = Math.abs(test.size - baseline.size);
    const percentDiff = baseline.size > 0 ? sizeDiff / baseline.size : 0;

    if (percentDiff > MIN_RESPONSE_DIFFERENCE_THRESHOLD) {
      if (test.bodyHash !== baseline.bodyHash) {
        result.isSuspicious = true;
        result.confidence = test.hasUserData ? 80 : 65;
        result.evidence = `Response size changed by ${Math.round(percentDiff * 100)}% (${baseline.size} → ${test.size} bytes)`;
        result.details = `Significant response difference suggests server processed the manipulated ${category} value`;
      }
    }

    if (category === "price" || category === "quantity") {
      if (test.status === 200 && percentDiff > 0.1) {
        result.confidence = Math.min(result.confidence + 10, 90);
        result.details += ". Price/quantity manipulation may affect business calculations";
      }
    }

    if (category === "role" || category === "privilege") {
      if (test.hasUserData && test.dataPatterns.length > baseline.dataPatterns.length) {
        result.isSuspicious = true;
        result.confidence = 85;
        result.evidence = `Additional data exposed after privilege escalation attempt`;
        result.details = `Response contains more user data patterns after role/privilege manipulation`;
      }
    }

    return result;
  }

  private async reportVulnerability(result: BusinessLogicResult): Promise<void> {
    const severityMap: Record<string, string> = {
      "idor": "High",
      "access-control": "High",
      "parameter-tampering": "Medium",
      "method-override": "Medium",
    };

    const typeDescriptions: Record<string, string> = {
      "parameter-tampering": "Parameter Tampering",
      "idor": "Insecure Direct Object Reference (IDOR)",
      "access-control": "Access Control Bypass",
      "method-override": "HTTP Method Override",
    };

    await this.onLog(
      result.confidence >= 90 ? "warn" : "info",
      `[${result.verificationStatus.toUpperCase()}] ${typeDescriptions[result.type]} detected: ${result.subType} at ${result.url.substring(0, 60)}...`
    );

    await this.onVuln({
      type: typeDescriptions[result.type],
      severity: severityMap[result.type] || "Medium",
      verificationStatus: result.verificationStatus,
      confidence: result.confidence,
      url: result.url,
      path: new URL(result.url).pathname,
      parameter: result.parameter,
      payload: result.payload,
      evidence: result.evidence,
      verificationDetails: result.verificationDetails,
      description: this.getDescription(result),
      remediation: this.getRemediation(result),
    });
  }

  private getDescription(result: BusinessLogicResult): string {
    const descriptions: Record<string, string> = {
      "parameter-tampering": `The application may be vulnerable to parameter tampering. The '${result.parameter}' parameter appears to accept manipulated values that could affect business logic, pricing, or access controls.`,
      "idor": `The application may be vulnerable to Insecure Direct Object Reference (IDOR). By manipulating object identifiers, an attacker may be able to access resources belonging to other users without proper authorization.`,
      "access-control": `The application may have access control weaknesses. Administrative or sensitive functionality appears to be accessible without proper authentication or authorization.`,
      "method-override": `The application accepts HTTP method override headers or parameters. This could allow attackers to bypass method-based access controls or trigger unintended actions.`,
    };

    return descriptions[result.type] || "Business logic vulnerability detected.";
  }

  private getRemediation(result: BusinessLogicResult): string {
    const remediations: Record<string, string> = {
      "parameter-tampering": "Implement server-side validation for all business-critical parameters. Never trust client-side values for pricing, quantities, roles, or permissions. Use session-stored values for sensitive calculations.",
      "idor": "Implement proper authorization checks before accessing any resource. Verify that the authenticated user has permission to access the requested object. Consider using UUIDs instead of sequential IDs.",
      "access-control": "Implement role-based access control (RBAC) for all administrative functionality. Ensure authentication and authorization checks are performed on every request to sensitive endpoints.",
      "method-override": "Disable HTTP method override functionality unless strictly required. If needed, implement strict validation and ensure the override doesn't bypass security controls. Prefer explicit endpoints over method-based routing.",
    };

    return remediations[result.type] || "Review and strengthen business logic validation.";
  }
}
