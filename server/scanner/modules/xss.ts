import { XSS_PAYLOADS } from "../payloads";
import { makeRequest, extractParameters, injectPayload, sleep, randomString, compareResponses } from "../utils";
import { InsertVulnerability, VerificationStatus } from "@shared/schema";
import { DefenseAwareness, EncodingStrategy } from "../defense-awareness";

interface FormData {
  action: string;
  method: string;
  inputs: Array<{
    name: string;
    type: string;
    value?: string;
  }>;
}

type ReflectionContext = 
  | "html-body"
  | "html-attribute"
  | "url-attribute"
  | "event-handler"
  | "javascript"
  | "javascript-string"
  | "css"
  | "html-comment"
  | "unknown";

interface ContextInfo {
  context: ReflectionContext;
  riskLevel: "critical" | "high" | "medium" | "low";
  baseConfidence: number;
  description: string;
}

interface XSSResult {
  vulnerable: boolean;
  type: "reflected" | "dom" | "stored";
  payload: string;
  evidence: string;
  parameter: string;
  context: ReflectionContext;
  confidence: number;
  verificationStatus: VerificationStatus;
  verificationDetails: string;
  contextInfo: ContextInfo;
}

interface DOMSink {
  sink: string;
  pattern: RegExp;
  context: string;
  riskLevel: "critical" | "high" | "medium";
}

interface ExecutableCheckResult {
  isExecutable: boolean;
  evidence: string;
  context: ReflectionContext;
  isEncoded: boolean;
  encodingType?: string;
}

export class XSSModule {
  private targetUrl: string;
  private foundVulnerabilities: XSSResult[] = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;
  private skippedParams: Set<string> = new Set();

  private readonly domSinks: DOMSink[] = [
    { sink: "eval", pattern: /eval\s*\(\s*['"]*\w+/, context: "eval execution", riskLevel: "critical" },
    { sink: "innerHTML", pattern: /\.innerHTML\s*=/, context: "HTML injection", riskLevel: "critical" },
    { sink: "outerHTML", pattern: /\.outerHTML\s*=/, context: "HTML injection", riskLevel: "critical" },
    { sink: "document.write", pattern: /document\.write\s*\(/, context: "document write", riskLevel: "critical" },
    { sink: "insertAdjacentHTML", pattern: /insertAdjacentHTML\s*\(/, context: "HTML injection", riskLevel: "high" },
  ];

  private readonly contextRiskMap: Record<ReflectionContext, ContextInfo> = {
    "html-body": {
      context: "html-body",
      riskLevel: "critical",
      baseConfidence: 95,
      description: "Payload reflected in HTML body - high risk if unencoded, script tags execute directly"
    },
    "html-attribute": {
      context: "html-attribute",
      riskLevel: "high",
      baseConfidence: 85,
      description: "Payload reflected in HTML attribute - high risk with proper attribute breakout"
    },
    "url-attribute": {
      context: "url-attribute",
      riskLevel: "high",
      baseConfidence: 85,
      description: "Payload reflected in URL attribute (href/src) - exploitable via javascript: protocol"
    },
    "event-handler": {
      context: "event-handler",
      riskLevel: "critical",
      baseConfidence: 95,
      description: "Payload reflected in event handler attribute - directly executable JavaScript context"
    },
    "javascript": {
      context: "javascript",
      riskLevel: "critical",
      baseConfidence: 90,
      description: "Payload reflected inside JavaScript block - high risk if in executable context"
    },
    "javascript-string": {
      context: "javascript-string",
      riskLevel: "high",
      baseConfidence: 80,
      description: "Payload reflected in JavaScript string - exploitable with string breakout"
    },
    "css": {
      context: "css",
      riskLevel: "medium",
      baseConfidence: 60,
      description: "Payload reflected in CSS context - lower risk but can enable CSS injection attacks"
    },
    "html-comment": {
      context: "html-comment",
      riskLevel: "low",
      baseConfidence: 50,
      description: "Payload reflected in HTML comment - may be exploitable with comment breakout"
    },
    "unknown": {
      context: "unknown",
      riskLevel: "medium",
      baseConfidence: 55,
      description: "Payload reflected in unknown context - requires manual verification"
    }
  };

  private abortSignal?: AbortSignal;

  constructor(
    targetUrl: string,
    onLog: (level: string, message: string) => Promise<void>,
    onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>,
    private defenseAwareness?: DefenseAwareness,
    private executionController?: { recordRequest: () => Promise<void> },
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

  private getEncodedPayload(payload: string): string {
    if (!this.defenseAwareness) return payload;
    const wafProfile = this.defenseAwareness.getWAFProfile();
    if (!wafProfile.detected) return payload;
    const strategy = wafProfile.bypassStrategies[0] || "url_encode";
    return this.defenseAwareness.encodePayload(payload, strategy);
  }

  private getNextDelay(): number {
    return this.defenseAwareness?.getCurrentDelay() || 50;
  }

  private async trackAndPace(): Promise<void> {
    try {
      await this.executionController?.recordRequest();
    } catch (error) {
    }
    const delay = this.getNextDelay();
    if (delay > 0) {
      await sleep(delay);
    }
  }

  async scan(urlsToTest: string[], forms: FormData[] = []): Promise<XSSResult[]> {
    await this.onLog("info", "Starting XSS scan module with confidence scoring...");
    
    for (const url of urlsToTest) {
      const params = extractParameters(url);
      
      if (params.length === 0) {
        const testUrls = [
          `${url}?q=test`,
          `${url}?search=test`,
          `${url}?query=test`,
          `${url}?name=test`,
        ];
        
        for (const testUrl of testUrls) {
          await this.testUrl(testUrl);
        }
      } else {
        await this.testUrl(url);
      }

      await this.testDomBasedXss(url);
    }

    if (forms.length > 0) {
      await this.onLog("info", `Testing ${forms.length} forms for stored XSS with persistence verification...`);
      for (const form of forms) {
        await this.testStoredXSS(form);
      }
    }

    return this.foundVulnerabilities;
  }

  private async testUrl(url: string): Promise<void> {
    const params = extractParameters(url);
    
    for (const param of params) {
      if (this.skippedParams.has(param.name)) {
        continue;
      }

      await this.onLog("info", `Testing parameter '${param.name}' for reflected XSS...`);
      
      await this.trackAndPace();
      const baselineResponse = await this.request(url);
      if (baselineResponse.error) continue;

      const shouldSkip = await this.performControlTest(url, param.name, baselineResponse);
      if (shouldSkip) {
        await this.onLog("info", `Skipping XSS tests for '${param.name}' - site reflects arbitrary input in responses (not XSS)`);
        this.skippedParams.add(param.name);
        continue;
      }

      await this.testPayloads(url, param.name, baselineResponse);
    }
  }

  private async performControlTest(url: string, paramName: string, baseline: { body: string }): Promise<boolean> {
    const controlProbes = [
      `control${randomString(8)}test`,
      `probe${randomString(6)}value`,
      `check${randomString(10)}data`,
    ];

    let reflectedCount = 0;

    for (const probe of controlProbes) {
      await this.trackAndPace();
      const testUrl = injectPayload(url, paramName, probe);
      const response = await this.request(testUrl);
      
      if (response.error) continue;

      if (response.body.includes(probe) && !baseline.body.includes(probe)) {
        reflectedCount++;
      }
      
      await sleep(50);
    }

    return reflectedCount >= 2;
  }

  private detectContext(body: string, probe: string): ContextInfo {
    const probeIndex = body.indexOf(probe);
    if (probeIndex === -1) return this.contextRiskMap["unknown"];

    const before = body.substring(Math.max(0, probeIndex - 100), probeIndex);
    const after = body.substring(probeIndex + probe.length, probeIndex + probe.length + 100);

    if (before.includes("<script") && !before.includes("</script")) {
      if (/["']\s*$/.test(before) || /^\s*["']/.test(after)) {
        return this.contextRiskMap["javascript-string"];
      }
      return this.contextRiskMap["javascript"];
    }

    if (/on\w+\s*=\s*["']?[^"'>]*$/.test(before)) {
      return this.contextRiskMap["event-handler"];
    }

    if (/=["']$/.test(before) || /^["']/.test(after)) {
      if (/href\s*=\s*["']?$/.test(before) || /src\s*=\s*["']?$/.test(before)) {
        return this.contextRiskMap["url-attribute"];
      }
      return this.contextRiskMap["html-attribute"];
    }

    if (before.includes("<style") || /style\s*=\s*["']?[^"'>]*$/.test(before)) {
      return this.contextRiskMap["css"];
    }

    if (before.includes("<!--") && !before.includes("-->")) {
      return this.contextRiskMap["html-comment"];
    }

    return this.contextRiskMap["html-body"];
  }

  private async testPayloads(url: string, paramName: string, baselineResponse: { body: string; status: number; contentLength: number; responseTime: number }): Promise<void> {
    const testPayloads = [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      "<svg onload=alert(1)>",
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>",
    ];

    for (const payload of testPayloads) {
      await this.trackAndPace();
      await this.testPayload(url, paramName, payload, baselineResponse);
      
      if (this.foundVulnerabilities.some(v => v.parameter === paramName && v.type === "reflected")) {
        break;
      }
    }
  }

  private async testPayload(
    url: string,
    paramName: string,
    payload: string,
    baselineResponse?: { body: string; status: number; contentLength: number; responseTime: number }
  ): Promise<void> {
    const encodedPayload = this.getEncodedPayload(payload);
    await this.trackAndPace();
    const testUrl = injectPayload(url, paramName, encodedPayload);
    const response = await this.request(testUrl);

    if (response.error) return;

    const executableCheck = this.isPayloadExecutable(response.body, payload);
    const contextInfo = this.detectContext(response.body, payload);

    if (executableCheck.isExecutable) {
      if (baselineResponse) {
        const comparison = compareResponses(
          { ...baselineResponse, url: "", headers: {}, error: undefined },
          response
        );
        if (!comparison.contentChanged) {
          await sleep(50);
          return;
        }
      }

      const confidence = this.calculateConfidence(executableCheck, contextInfo);
      const verificationStatus = this.determineVerificationStatus(confidence, executableCheck);
      const verificationDetails = this.buildVerificationDetails(
        payload,
        executableCheck,
        contextInfo,
        verificationStatus,
        confidence
      );

      const result: XSSResult = {
        vulnerable: true,
        type: "reflected",
        payload,
        evidence: executableCheck.evidence,
        parameter: paramName,
        context: executableCheck.context,
        confidence,
        verificationStatus,
        verificationDetails,
        contextInfo,
      };

      const isDuplicate = this.foundVulnerabilities.some(
        v => v.parameter === paramName && v.type === "reflected"
      );

      if (!isDuplicate) {
        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
      }
      return;
    }

    if (response.body.includes(payload) && executableCheck.isEncoded) {
      const confidence = Math.max(50, contextInfo.baseConfidence - 30);
      const verificationStatus: VerificationStatus = "potential";
      const verificationDetails = `XSS potential: payload ${payload.substring(0, 30)}... reflected but encoded (${executableCheck.encodingType || "HTML entities"}) in ${contextInfo.context} context. May require bypass techniques.`;

      const result: XSSResult = {
        vulnerable: true,
        type: "reflected",
        payload,
        evidence: `Payload reflected with encoding: ${executableCheck.encodingType || "HTML entities"}`,
        parameter: paramName,
        context: contextInfo.context,
        confidence,
        verificationStatus,
        verificationDetails,
        contextInfo,
      };

      const isDuplicate = this.foundVulnerabilities.some(
        v => v.parameter === paramName && v.type === "reflected"
      );

      if (!isDuplicate) {
        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
      }
    }

    await sleep(50);
  }

  private calculateConfidence(execCheck: ExecutableCheckResult, contextInfo: ContextInfo): number {
    let confidence = contextInfo.baseConfidence;

    if (execCheck.isExecutable && !execCheck.isEncoded) {
      confidence = Math.min(100, confidence + 5);
    }

    if (execCheck.isEncoded) {
      confidence = Math.max(50, confidence - 25);
    }

    if (contextInfo.riskLevel === "critical") {
      confidence = Math.min(100, confidence + 5);
    } else if (contextInfo.riskLevel === "low") {
      confidence = Math.max(50, confidence - 10);
    }

    return Math.round(confidence);
  }

  private determineVerificationStatus(confidence: number, execCheck: ExecutableCheckResult): VerificationStatus {
    if (confidence >= 90 && execCheck.isExecutable && !execCheck.isEncoded) {
      return "confirmed";
    }
    return "potential";
  }

  private buildVerificationDetails(
    payload: string,
    execCheck: ExecutableCheckResult,
    contextInfo: ContextInfo,
    status: VerificationStatus,
    confidence: number
  ): string {
    const payloadSnippet = payload.length > 40 ? payload.substring(0, 40) + "..." : payload;
    
    if (status === "confirmed") {
      return `XSS confirmed: payload ${payloadSnippet} reflected unencoded in ${contextInfo.context} context, executable in browser. ${contextInfo.description}`;
    }
    
    const reasons: string[] = [];
    if (execCheck.isEncoded) {
      reasons.push(`encoding detected (${execCheck.encodingType || "HTML entities"})`);
    }
    if (confidence < 90) {
      reasons.push(`confidence ${confidence}% below confirmation threshold`);
    }
    if (contextInfo.riskLevel === "low" || contextInfo.riskLevel === "medium") {
      reasons.push(`${contextInfo.riskLevel} risk context`);
    }
    
    return `XSS potential: payload ${payloadSnippet} reflected in ${contextInfo.context} context. ${reasons.join(", ")}. ${contextInfo.description}`;
  }

  private isPayloadExecutable(body: string, payload: string): ExecutableCheckResult {
    const lowerBody = body.toLowerCase();
    const lowerPayload = payload.toLowerCase();
    
    const encodedPatterns = [
      { encoded: "&lt;", original: "<", type: "HTML entity" },
      { encoded: "&gt;", original: ">", type: "HTML entity" },
      { encoded: "&#60;", original: "<", type: "HTML numeric entity" },
      { encoded: "&#62;", original: ">", type: "HTML numeric entity" },
      { encoded: "&#x3c;", original: "<", type: "HTML hex entity" },
      { encoded: "&#x3e;", original: ">", type: "HTML hex entity" },
      { encoded: "%3c", original: "<", type: "URL encoding" },
      { encoded: "%3e", original: ">", type: "URL encoding" },
      { encoded: "\\u003c", original: "<", type: "Unicode escape" },
      { encoded: "\\u003e", original: ">", type: "Unicode escape" },
    ];
    
    let isEncoded = false;
    let encodingType: string | undefined;
    
    for (const pattern of encodedPatterns) {
      if (lowerPayload.includes(pattern.original) && lowerBody.includes(pattern.encoded)) {
        if (!lowerBody.includes(pattern.original)) {
          isEncoded = true;
          encodingType = pattern.type;
          break;
        }
      }
    }

    if (lowerPayload.includes("<script")) {
      const scriptRegex = /<script[^>]*>[\s\S]*?<\/script>/gi;
      const matches = body.match(scriptRegex);
      if (matches) {
        for (const match of matches) {
          if (match.toLowerCase().includes("alert") && !match.includes("&lt;") && !match.includes("&gt;")) {
            return { 
              isExecutable: true, 
              evidence: `Unencoded script tag executed: ${match.substring(0, 50)}`,
              context: "html-body",
              isEncoded: false
            };
          }
        }
      }
    }

    const eventHandlerPatterns = [
      { regex: /<img[^>]+onerror\s*=\s*["']?[^"'>]*alert/i, name: "img onerror", context: "event-handler" as ReflectionContext },
      { regex: /<svg[^>]+onload\s*=\s*["']?[^"'>]*alert/i, name: "svg onload", context: "event-handler" as ReflectionContext },
      { regex: /<body[^>]+onload\s*=\s*["']?[^"'>]*alert/i, name: "body onload", context: "event-handler" as ReflectionContext },
      { regex: /<[^>]+onclick\s*=\s*["']?[^"'>]*alert/i, name: "onclick", context: "event-handler" as ReflectionContext },
      { regex: /<[^>]+onmouseover\s*=\s*["']?[^"'>]*alert/i, name: "onmouseover", context: "event-handler" as ReflectionContext },
      { regex: /<[^>]+onfocus\s*=\s*["']?[^"'>]*alert/i, name: "onfocus", context: "event-handler" as ReflectionContext },
    ];

    for (const pattern of eventHandlerPatterns) {
      if (pattern.regex.test(body)) {
        const match = body.match(pattern.regex);
        if (match && !match[0].includes("&lt;") && !match[0].includes("&gt;")) {
          return { 
            isExecutable: true, 
            evidence: `Event handler XSS (${pattern.name}): ${match[0].substring(0, 60)}`,
            context: pattern.context,
            isEncoded: false
          };
        }
      }
    }

    if (lowerPayload.includes("javascript:")) {
      const jsProtocolRegex = /(href|src)\s*=\s*["']?\s*javascript:/i;
      if (jsProtocolRegex.test(body)) {
        const match = body.match(jsProtocolRegex);
        if (match) {
          return { 
            isExecutable: true, 
            evidence: `JavaScript protocol in attribute: ${match[0]}`,
            context: "url-attribute",
            isEncoded: false
          };
        }
      }
    }

    return { 
      isExecutable: false, 
      evidence: "",
      context: "unknown",
      isEncoded,
      encodingType
    };
  }

  private async testDomBasedXss(url: string): Promise<void> {
    await this.trackAndPace();
    const response = await this.request(url);
    if (response.error) return;

    const detectedSinks = this.detectDomSinks(response.body);
    
    if (detectedSinks.length > 0) {
      for (const sink of detectedSinks) {
        await this.onLog("info", `Potential DOM-based XSS sink detected: ${sink.sink} in ${sink.context}`);

        const params = extractParameters(url);
        for (const param of params) {
          const probe = `xssdom${randomString(4)}`;
          await this.trackAndPace();
          const testUrl = injectPayload(url, param.name, probe);
          const sinkResponse = await this.request(testUrl);

          if (sinkResponse.body.includes(probe)) {
            const probeIndex = sinkResponse.body.indexOf(probe);
            const context = sinkResponse.body.substring(
              Math.max(0, probeIndex - 200),
              Math.min(sinkResponse.body.length, probeIndex + 200)
            );

            if (this.containsDangerousSinkWithInput(context, probe)) {
              const contextInfo = this.contextRiskMap["javascript"];
              const confidence = sink.riskLevel === "critical" ? 75 : 65;
              const verificationStatus: VerificationStatus = "potential";
              const verificationDetails = `DOM XSS potential: user input flows to dangerous sink '${sink.sink}' (${sink.context}). Requires JavaScript execution to confirm exploitability. Risk level: ${sink.riskLevel}.`;

              const result: XSSResult = {
                vulnerable: true,
                type: "dom",
                payload: probe,
                evidence: `User input flows to ${sink.sink}: ${sink.pattern}`,
                parameter: param.name,
                context: "javascript",
                confidence,
                verificationStatus,
                verificationDetails,
                contextInfo,
              };

              const isDuplicate = this.foundVulnerabilities.some(
                v => v.parameter === param.name && v.type === "dom"
              );

              if (!isDuplicate) {
                this.foundVulnerabilities.push(result);
                await this.reportVulnerability(result, url);
              }
            }
          }
        }
      }
    }
  }

  private detectDomSinks(body: string): DOMSink[] {
    const foundSinks: DOMSink[] = [];

    for (const sink of this.domSinks) {
      if (sink.pattern.test(body)) {
        foundSinks.push(sink);
      }
    }

    return foundSinks;
  }

  private containsDangerousSinkWithInput(context: string, probe: string): boolean {
    const dangerousPatterns = [
      new RegExp(`eval\\s*\\([^)]*${probe}`, "i"),
      new RegExp(`innerHTML\\s*=\\s*[^;]*${probe}`, "i"),
      new RegExp(`outerHTML\\s*=\\s*[^;]*${probe}`, "i"),
      new RegExp(`document\\.write\\s*\\([^)]*${probe}`, "i"),
    ];

    return dangerousPatterns.some(pattern => pattern.test(context));
  }

  private async testStoredXSS(form: FormData): Promise<void> {
    const formUrl = form.action;
    
    for (const input of form.inputs) {
      if (input.type && !["text", "textarea", "email", "search", "url", "tel"].includes(input.type)) {
        continue;
      }

      await this.onLog("info", `Testing stored XSS in form field '${input.name}' at ${formUrl}`);

      const uniqueMarker = `xssstored${randomString(8)}`;
      const testPayload = `<script>alert('${uniqueMarker}')</script>`;

      const formData: Record<string, string> = {};
      for (const inp of form.inputs) {
        formData[inp.name] = inp.name === input.name ? testPayload : (inp.value || "test");
      }

      await this.trackAndPace();
      const submitResponse = await this.request(formUrl, {
        method: form.method as "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
        data: form.method === "POST" ? formData : undefined,
      });

      if (submitResponse.error) continue;

      await sleep(500);

      const persistenceVerification = await this.verifyStoredXSSPersistence(
        formUrl,
        testPayload,
        uniqueMarker
      );

      if (persistenceVerification.persisted) {
        const contextInfo = this.contextRiskMap["html-body"];
        const confidence = persistenceVerification.confirmedLoads >= 2 ? 98 : 90;
        const verificationStatus: VerificationStatus = persistenceVerification.isExecutable ? "confirmed" : "potential";
        
        const verificationDetails = this.buildStoredXSSVerificationDetails(
          testPayload,
          persistenceVerification,
          verificationStatus,
          confidence
        );

        const result: XSSResult = {
          vulnerable: true,
          type: "stored",
          payload: testPayload,
          evidence: `Stored XSS: ${persistenceVerification.evidence}`,
          parameter: input.name,
          context: "html-body",
          confidence,
          verificationStatus,
          verificationDetails,
          contextInfo,
        };

        const isDuplicate = this.foundVulnerabilities.some(
          v => v.parameter === input.name && v.type === "stored"
        );

        if (!isDuplicate) {
          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result, formUrl);
        }
      }
    }
  }

  private async verifyStoredXSSPersistence(
    url: string,
    payload: string,
    uniqueMarker: string
  ): Promise<{
    persisted: boolean;
    isExecutable: boolean;
    confirmedLoads: number;
    evidence: string;
    isEncoded: boolean;
  }> {
    let confirmedLoads = 0;
    let isExecutable = false;
    let evidence = "";
    let isEncoded = false;

    for (let i = 0; i < 3; i++) {
      await this.trackAndPace();
      
      const refetchResponse = await this.request(url);
      if (refetchResponse.error) continue;

      if (refetchResponse.body.includes(uniqueMarker)) {
        confirmedLoads++;
        
        const execCheck = this.isPayloadExecutable(refetchResponse.body, payload);
        if (execCheck.isExecutable) {
          isExecutable = true;
          evidence = execCheck.evidence;
        }
        isEncoded = execCheck.isEncoded;
      }
    }

    return {
      persisted: confirmedLoads > 0,
      isExecutable,
      confirmedLoads,
      evidence: evidence || `Payload persisted across ${confirmedLoads} page loads`,
      isEncoded,
    };
  }

  private buildStoredXSSVerificationDetails(
    payload: string,
    verification: { persisted: boolean; isExecutable: boolean; confirmedLoads: number; isEncoded: boolean },
    status: VerificationStatus,
    confidence: number
  ): string {
    const payloadSnippet = payload.length > 40 ? payload.substring(0, 40) + "..." : payload;
    
    if (status === "confirmed") {
      return `Stored XSS confirmed: payload ${payloadSnippet} persisted and verified across ${verification.confirmedLoads} page load(s). Payload executes unencoded in HTML context. This is a persistent attack affecting all users who view this content.`;
    }
    
    const reasons: string[] = [];
    if (verification.isEncoded) {
      reasons.push("payload is encoded on output");
    }
    if (!verification.isExecutable) {
      reasons.push("execution not directly observable");
    }
    if (verification.confirmedLoads < 2) {
      reasons.push(`only verified in ${verification.confirmedLoads} page load(s)`);
    }
    
    return `Stored XSS potential: payload ${payloadSnippet} persists in storage (${verification.confirmedLoads} load(s) verified). ${reasons.join(", ")}. Manual verification recommended.`;
  }

  private async reportVulnerability(result: XSSResult, url: string): Promise<void> {
    const statusLabel = result.verificationStatus === "confirmed" ? "CONFIRMED" : "POTENTIAL";
    await this.onLog("warn", `XSS found (${result.type}) [${statusLabel}] in parameter '${result.parameter}' - confidence: ${result.confidence}%`);

    await this.onVuln({
      type: `Cross-Site Scripting (${result.type})`,
      severity: "High",
      url,
      parameter: result.parameter,
      payload: result.payload,
      evidence: `[${result.context}] ${result.evidence}`,
      description: this.getDescription(result.type),
      remediation: this.getRemediation(result.type),
      verificationStatus: result.verificationStatus,
      confidence: result.confidence,
      verificationDetails: result.verificationDetails,
    });
  }

  private getDescription(type: string): string {
    switch (type) {
      case "reflected":
        return "Reflected XSS was detected. User input is echoed back in the response without proper sanitization, allowing attackers to inject malicious scripts that execute in victims' browsers.";
      case "dom":
        return "DOM-based XSS was detected. Client-side JavaScript processes user input unsafely, allowing attackers to manipulate the DOM and execute arbitrary JavaScript.";
      case "stored":
        return "Stored XSS was detected. Malicious input is stored on the server and served to other users, allowing persistent attacks against all visitors.";
      default:
        return "Cross-Site Scripting vulnerability detected. Attackers may be able to steal session cookies, redirect users, or perform actions on their behalf.";
    }
  }

  private getRemediation(type: string): string {
    const baseRemediation = "Implement proper output encoding based on the context (HTML, JavaScript, URL, CSS). Use Content Security Policy (CSP) headers. Validate and sanitize all user inputs.";
    
    switch (type) {
      case "reflected":
        return `${baseRemediation} Never reflect user input directly in responses without proper encoding.`;
      case "dom":
        return `${baseRemediation} Avoid using dangerous DOM manipulation methods like eval(), innerHTML, and document.write(). Use textContent instead. Implement input validation before processing in client-side JavaScript.`;
      case "stored":
        return `${baseRemediation} Sanitize and validate all user inputs on the server-side before storing. Never trust stored data when rendering - always encode output. Use parameterized storage and retrieval.`;
      default:
        return baseRemediation;
    }
  }
}
