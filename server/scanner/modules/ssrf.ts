import { SSRF_PAYLOADS } from "../payloads";
import { makeRequest, extractParameters, injectPayload, sleep, randomString } from "../utils";
import { InsertVulnerability } from "@shared/schema";
import { DefenseAwareness, EncodingStrategy } from "../defense-awareness";

interface SSRFResult {
  vulnerable: boolean;
  type: "internal" | "cloud-metadata" | "protocol" | "port-scan";
  payload: string;
  evidence: string;
  parameter: string;
  confidence: "high" | "medium" | "low";
}

interface ResponseBaseline {
  status: number;
  contentLength: number;
  responseTime: number;
  headers: Record<string, string>;
  body: string;
  serverSignature?: string;
}

interface MetadataPattern {
  provider: string;
  patterns: Array<{
    name: string;
    regex: RegExp;
    critical: boolean;
  }>;
}

export class SSRFModule {
  private targetUrl: string;
  private foundVulnerabilities: SSRFResult[] = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;
  private metadataPatterns: MetadataPattern[];
  private baselineResponses: Map<string, ResponseBaseline> = new Map();
  private skippedParams: Set<string> = new Set();

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
    this.metadataPatterns = this.initializeMetadataPatterns();
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
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  private initializeMetadataPatterns(): MetadataPattern[] {
    return [
      {
        provider: "AWS",
        patterns: [
          { name: "ami-id", regex: /ami-[a-z0-9]{8,17}/i, critical: false },
          { name: "instance-id", regex: /i-[a-z0-9]{8,17}/i, critical: true },
          { name: "security-credentials", regex: /"AccessKeyId"|"SecretAccessKey"|security-credentials/i, critical: true },
          { name: "iam-credentials", regex: /iam\/security-credentials\/|"Code"\s*:\s*"Success"/i, critical: true },
          { name: "aws-hostname", regex: /ec2[a-z0-9\-]*\.amazonaws\.com|ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/i, critical: false },
        ],
      },
      {
        provider: "GCP",
        patterns: [
          { name: "project-id", regex: /"project_id"\s*:\s*"[^"]+"/i, critical: true },
          { name: "service-account", regex: /service-accounts\/|"service_account"|"client_email"/i, critical: true },
          { name: "gcp-oauth", regex: /"access_token"|"token_type"\s*:\s*"Bearer"/i, critical: true },
        ],
      },
      {
        provider: "Azure",
        patterns: [
          { name: "subscription-id", regex: /subscriptionId["\s:]+[a-f0-9\-]{36}|\/subscriptions\/[a-f0-9\-]{36}/i, critical: true },
          { name: "vm-id", regex: /vmId["\s:]+[a-f0-9\-]+|"id"\s*:\s*"\/subscriptions/i, critical: true },
          { name: "managed-identity", regex: /principalId|"type"\s*:\s*"SystemAssigned"/i, critical: true },
          { name: "azure-tokens", regex: /"access_token"|"token_type"\s*:\s*"Bearer"|x-ms-request-id/i, critical: true },
        ],
      },
    ];
  }

  async scan(urlsToTest: string[]): Promise<SSRFResult[]> {
    await this.onLog("info", "Starting SSRF scan module...");
    
    for (const url of urlsToTest) {
      const params = extractParameters(url);
      
      if (params.length === 0) {
        const testUrls = [
          `${url}?url=http://example.com`,
          `${url}?redirect=http://example.com`,
          `${url}?src=http://example.com`,
          `${url}?target=http://example.com`,
        ];
        
        for (const testUrl of testUrls) {
          await this.testUrl(testUrl);
        }
      } else {
        await this.testUrl(url);
      }
    }

    return this.foundVulnerabilities;
  }

  private async testUrl(url: string): Promise<void> {
    const params = extractParameters(url);
    
    const urlParams = params.filter(p => 
      /url|uri|link|src|href|redirect|site|dest|target|path|fetch|callback|data|image|file|load/i.test(p.name)
    );

    const paramsToTest = urlParams.length > 0 ? urlParams : params;
    
    for (const param of paramsToTest) {
      if (this.skippedParams.has(param.name)) {
        continue;
      }

      await this.onLog("info", `Testing parameter '${param.name}' for SSRF...`);
      
      await this.trackAndPace();
      const baselineResponse = await this.request(url);
      if (baselineResponse.error) continue;

      const baseline: ResponseBaseline = {
        status: baselineResponse.status,
        contentLength: baselineResponse.contentLength,
        responseTime: baselineResponse.responseTime,
        headers: baselineResponse.headers,
        body: baselineResponse.body,
        serverSignature: baselineResponse.headers["server"],
      };

      this.baselineResponses.set(param.name, baseline);

      const shouldSkip = await this.performControlTest(url, param.name, baseline);
      if (shouldSkip) {
        await this.onLog("info", `Skipping SSRF tests for '${param.name}' - site appears to reflect URL inputs in error messages`);
        this.skippedParams.add(param.name);
        continue;
      }

      await this.testInternalNetwork(url, param.name, baseline);
      await this.testCloudMetadata(url, param.name, baseline);
      await this.testProtocolHandlers(url, param.name, baseline);
    }
  }

  private async performControlTest(url: string, paramName: string, baseline: ResponseBaseline): Promise<boolean> {
    const controlPayloads = [
      `http://${randomString(12)}.invalid/`,
      `http://${randomString(10)}.nonexistent.test/path`,
      `https://${randomString(8)}.fakeTLD12345/`,
    ];

    let differentResponses = 0;
    
    for (const payload of controlPayloads) {
      await this.trackAndPace();
      const testUrl = injectPayload(url, paramName, payload);
      const response = await this.request(testUrl, { timeout: 5000 });
      
      if (response.error) continue;

      const bodyDiffers = response.body !== baseline.body;
      const sizeDiff = Math.abs(response.contentLength - baseline.contentLength);
      
      if (bodyDiffers && sizeDiff > 20 && response.body.includes(payload.substring(7, 20))) {
        differentResponses++;
      } else if (bodyDiffers && sizeDiff > 50) {
        differentResponses++;
      }
      
      await sleep(50);
    }

    return differentResponses >= 2;
  }

  private async testInternalNetwork(url: string, paramName: string, baseline: ResponseBaseline): Promise<void> {
    const internalPayloads = SSRF_PAYLOADS.internal.slice(0, 4);
    
    for (const payload of internalPayloads) {
      await this.trackAndPace();
      const testUrl = injectPayload(url, paramName, payload);
      const response = await this.request(testUrl, { timeout: 5000 });

      if (response.error) continue;

      const internalIndicators = [
        { pattern: ">root:x:0:0:", confidence: "high" as const },
        { pattern: "daemon:x:1:1:", confidence: "high" as const },
        { pattern: "Redis server", confidence: "high" as const },
        { pattern: "Elasticsearch", confidence: "high" as const },
        { pattern: "MongoDB server", confidence: "high" as const },
        { pattern: "[mysqld]", confidence: "high" as const },
        { pattern: "PostgreSQL", confidence: "high" as const },
      ];

      for (const indicator of internalIndicators) {
        if (response.body.includes(indicator.pattern) && !baseline.body.includes(indicator.pattern)) {
          const result: SSRFResult = {
            vulnerable: true,
            type: "internal",
            payload,
            evidence: `Internal service signature detected: ${indicator.pattern}`,
            parameter: paramName,
            confidence: indicator.confidence,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result, url);
          return;
        }
      }

      const serverHeader = response.headers["server"]?.toLowerCase() || "";
      const baselineServerHeader = baseline.serverSignature?.toLowerCase() || "";
      
      if (serverHeader !== baselineServerHeader && this.isDefiniteInternalService(serverHeader, response.body)) {
        const result: SSRFResult = {
          vulnerable: true,
          type: "internal",
          payload,
          evidence: `Internal server detected: ${serverHeader}`,
          parameter: paramName,
          confidence: "high",
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      await sleep(50);
    }
  }

  private isDefiniteInternalService(serverHeader: string, body: string): boolean {
    const definiteInternalSignatures = [
      { header: "redis", bodyPattern: /redis|WRONGTYPE|ERR unknown command/i },
      { header: "elasticsearch", bodyPattern: /elasticsearch|"cluster_name"|"tagline"\s*:\s*"You Know, for Search"/i },
      { header: "mongodb", bodyPattern: /mongodb|"ismaster"|"maxWireVersion"/i },
      { header: "memcached", bodyPattern: /memcached|STAT pid|VERSION \d+\.\d+/i },
      { header: "jenkins", bodyPattern: /jenkins|"_class"\s*:\s*"hudson/i },
    ];
    
    for (const sig of definiteInternalSignatures) {
      if (serverHeader.includes(sig.header) && sig.bodyPattern.test(body)) {
        return true;
      }
    }
    
    return false;
  }

  private async testCloudMetadata(url: string, paramName: string, baseline: ResponseBaseline): Promise<void> {
    const metadataPayloads = SSRF_PAYLOADS.cloudMetadata.slice(0, 5);
    
    for (const payload of metadataPayloads) {
      await this.trackAndPace();
      const encodedPayload = this.getEncodedPayload(payload);
      const testUrl = injectPayload(url, paramName, encodedPayload);
      
      const headers: Record<string, string> = {};
      if (payload.includes("metadata.google.internal")) {
        headers["Metadata-Flavor"] = "Google";
      }

      const response = await this.request(testUrl, { timeout: 5000, headers });

      if (response.error) continue;

      if (response.status !== 200 || response.contentLength === 0) {
        continue;
      }

      const provider = this.getCloudProvider(payload);
      const jsonData = this.tryParseJson(response.body);

      let foundMetadataEvidence = false;
      let evidenceDescription = "";

      // Check if response is just reflecting the URL (false positive indicator)
      const payloadReflected = response.body.includes(payload) || 
                               response.body.includes("169.254.169.254") ||
                               response.body.includes("security-credentials") && response.body.includes("meta-data");
      
      // If payload is reflected and response is HTML (likely an error page), skip
      if (payloadReflected && (response.body.includes("<html") || response.body.includes("<!DOCTYPE"))) {
        continue;
      }

      for (const pattern of this.metadataPatterns) {
        if (pattern.provider !== provider) continue;

        for (const p of pattern.patterns) {
          if (!p.critical) continue;
          
          const matches = p.regex.test(response.body) || (jsonData && this.containsPattern(jsonData, p.regex));

          if (matches && !p.regex.test(baseline.body)) {
            // Additional check: the pattern should match ACTUAL metadata content, not just reflected URL
            // For "security-credentials" pattern, require actual credential-like content
            if (p.name === "security-credentials" || p.name === "iam-credentials") {
              // Must have actual AWS credential content, not just URL reflection
              const hasRealCredentials = 
                (response.body.includes('"AccessKeyId"') && response.body.includes('"SecretAccessKey"')) ||
                (response.body.includes('"Code"') && response.body.includes('"Success"'));
              if (!hasRealCredentials) {
                continue; // Skip this pattern, it's just URL reflection
              }
            }
            
            foundMetadataEvidence = true;
            evidenceDescription = `${pattern.provider} - ${p.name}`;
            break;
          }
        }
        if (foundMetadataEvidence) break;
      }

      if (!foundMetadataEvidence && jsonData) {
        const sensitiveKeys = this.checkJsonForSensitiveKeys(jsonData);
        const baselineJson = this.tryParseJson(baseline.body);
        const baselineSensitiveKeys = baselineJson ? this.checkJsonForSensitiveKeys(baselineJson) : [];
        
        const newSensitiveKeys = sensitiveKeys.filter(k => !baselineSensitiveKeys.includes(k));
        
        if (newSensitiveKeys.length >= 2) {
          foundMetadataEvidence = true;
          evidenceDescription = `Cloud metadata keys: ${newSensitiveKeys.slice(0, 3).join(", ")}`;
        }
      }

      if (foundMetadataEvidence) {
        const result: SSRFResult = {
          vulnerable: true,
          type: "cloud-metadata",
          payload,
          evidence: `Cloud metadata detected: ${evidenceDescription}`,
          parameter: paramName,
          confidence: "high",
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      await sleep(50);
    }
  }

  private getCloudProvider(payload: string): string {
    if (payload.includes("169.254.169.254")) {
      if (payload.includes("metadata.google")) return "GCP";
      if (payload.includes("metadata/instance")) return "Azure";
      return "AWS";
    }
    if (payload.includes("metadata.google")) return "GCP";
    if (payload.includes("kubernetes")) return "Kubernetes";
    return "Unknown";
  }

  private tryParseJson(body: string): Record<string, unknown> | null {
    try {
      return JSON.parse(body);
    } catch {
      return null;
    }
  }

  private containsPattern(obj: unknown, pattern: RegExp): boolean {
    const str = JSON.stringify(obj);
    return pattern.test(str);
  }

  private checkJsonForSensitiveKeys(obj: unknown, visited = new Set<unknown>()): string[] {
    if (visited.has(obj)) return [];
    visited.add(obj);

    const sensitiveKeys = [
      "access_token", "accessToken",
      "secret", "secret_key", "secretKey",
      "api_key", "apiKey",
      "password", "passwd",
      "credential", "credentials",
      "private_key", "privateKey",
      "client_secret", "clientSecret",
    ];

    const found: string[] = [];

    if (typeof obj === "object" && obj !== null) {
      for (const key in obj) {
        if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
          found.push(key);
        }

        const value = (obj as Record<string, unknown>)[key];
        if (typeof value === "object" && value !== null && !visited.has(value)) {
          found.push(...this.checkJsonForSensitiveKeys(value, visited));
        }
      }
    }

    return Array.from(new Set(found));
  }

  private async testProtocolHandlers(url: string, paramName: string, baseline: ResponseBaseline): Promise<void> {
    const protocolPayloads = SSRF_PAYLOADS.protocols.slice(0, 3);
    
    for (const payload of protocolPayloads) {
      await this.trackAndPace();
      const encodedPayload = this.getEncodedPayload(payload);
      const testUrl = injectPayload(url, paramName, encodedPayload);
      const response = await this.request(testUrl, { timeout: 5000 });

      if (response.error) continue;

      if (payload.startsWith("file://")) {
        const fileIndicators = [
          { pattern: "root:x:0:0:", confidence: "high" as const },
          { pattern: "daemon:x:1:1:", confidence: "high" as const },
          { pattern: "bin:x:2:2:", confidence: "high" as const },
          { pattern: "[fonts]", confidence: "high" as const },
          { pattern: "[extensions]", confidence: "high" as const },
          { pattern: "; for 16-bit app support", confidence: "high" as const },
        ];

        for (const indicator of fileIndicators) {
          if (response.body.includes(indicator.pattern) && 
              !baseline.body.includes(indicator.pattern) && 
              response.body.length > 50) {
            const result: SSRFResult = {
              vulnerable: true,
              type: "protocol",
              payload,
              evidence: `File disclosure via file://: ${indicator.pattern}`,
              parameter: paramName,
              confidence: indicator.confidence,
            };

            this.foundVulnerabilities.push(result);
            await this.reportVulnerability(result, url);
            return;
          }
        }
      }

      if (payload.startsWith("dict://") || payload.startsWith("gopher://")) {
        const protocolIndicators = [
          { pattern: "-ERR", protocol: "Redis" },
          { pattern: "220 ", protocol: "SMTP/FTP" },
          { pattern: "+OK", protocol: "POP3" },
        ];
        
        for (const indicator of protocolIndicators) {
          if (response.body.includes(indicator.pattern) && !baseline.body.includes(indicator.pattern)) {
            const result: SSRFResult = {
              vulnerable: true,
              type: "protocol",
              payload,
              evidence: `Protocol handler enabled - ${indicator.protocol} response: ${indicator.pattern}`,
              parameter: paramName,
              confidence: "high",
            };

            this.foundVulnerabilities.push(result);
            await this.reportVulnerability(result, url);
            return;
          }
        }
      }

      await sleep(50);
    }
  }

  private async reportVulnerability(result: SSRFResult, url: string): Promise<void> {
    const verificationStatus = result.confidence === "high" ? "confirmed" : "potential";
    const confidenceScore = result.confidence === "high" ? 95 : 
                            result.confidence === "medium" ? 70 : 55;
    
    await this.onLog("warn", `SSRF found (${result.type}) in parameter '${result.parameter}' - ${verificationStatus.toUpperCase()} (${confidenceScore}%)`);

    const severityMap: Record<string, string> = {
      "internal": "High",
      "cloud-metadata": "Critical",
      "protocol": "High",
      "port-scan": "Medium",
    };

    const verificationDetails = this.getVerificationDetails(result, verificationStatus);

    await this.onVuln({
      type: `Server-Side Request Forgery (${result.type})`,
      severity: severityMap[result.type] || "High",
      verificationStatus,
      confidence: confidenceScore,
      url,
      parameter: result.parameter,
      payload: result.payload,
      evidence: result.evidence,
      verificationDetails,
      description: this.getDescription(result.type),
      remediation: "Validate and sanitize all URL inputs. Use allowlists for permitted domains. Block access to internal IP ranges (127.0.0.1, 10.x.x.x, 192.168.x.x, etc.). Disable unnecessary URL schemes. Use a web application firewall (WAF).",
    });
  }

  private getVerificationDetails(result: SSRFResult, status: string): string {
    if (status === "confirmed") {
      switch (result.type) {
        case "cloud-metadata":
          return `CONFIRMED: Server-side access verified through cloud metadata content that could only be obtained via actual IMDS endpoint access. Evidence: ${result.evidence}`;
        case "internal":
          return `CONFIRMED: Internal service access verified through unique service signatures/responses that couldn't be faked client-side. Evidence: ${result.evidence}`;
        case "protocol":
          return `CONFIRMED: Protocol handler access verified through service-specific response patterns. Evidence: ${result.evidence}`;
        default:
          return `CONFIRMED: Server-side request verified with definitive proof. Evidence: ${result.evidence}`;
      }
    } else {
      return `POTENTIAL: Behavioral indicators suggest possible SSRF but no definitive server-side proof obtained. The parameter accepts URL-like input and shows differential response behavior, but actual server-side access couldn't be conclusively verified.`;
    }
  }

  private getDescription(type: string): string {
    switch (type) {
      case "internal":
        return "SSRF allowing internal network access was detected. An attacker can make the server send requests to internal services, potentially accessing sensitive systems not exposed to the internet.";
      case "cloud-metadata":
        return "SSRF accessing cloud metadata endpoints was detected. This is critical as it may expose cloud credentials, API keys, and sensitive instance information that can lead to full cloud account compromise.";
      case "protocol":
        return "SSRF with protocol handler abuse was detected. An attacker can use protocols like file://, dict://, or gopher:// to read local files or interact with internal services.";
      case "port-scan":
        return "SSRF can be used for port scanning internal services. An attacker can enumerate open ports and services on internal networks.";
      default:
        return "Server-Side Request Forgery vulnerability detected. An attacker can make the server perform requests to arbitrary destinations.";
    }
  }
}
