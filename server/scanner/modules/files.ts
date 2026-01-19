import { SENSITIVE_FILES } from "../payloads";
import { makeRequest, buildUrl, sleep, hashString, randomString } from "../utils";
import { InsertVulnerability } from "@shared/schema";

interface FileResult {
  path: string;
  status: number;
  size: number;
  type: string;
  evidence: string;
  severity: string;
}

interface Baseline404Response {
  body: string;
  bodyHash: string;
  size: number;
  status: number;
}

export class SensitiveFilesModule {
  private targetUrl: string;
  private foundFiles: FileResult[] = [];
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;
  private checkedPaths: Set<string> = new Set();
  private baseline404: Baseline404Response | null = null;

  private abortSignal?: AbortSignal;

  constructor(
    targetUrl: string,
    onLog: (level: string, message: string) => Promise<void>,
    onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>,
    abortSignal?: AbortSignal
  ) {
    this.targetUrl = targetUrl.endsWith("/") ? targetUrl.slice(0, -1) : targetUrl;
    this.onLog = onLog;
    this.onVuln = onVuln;
    this.abortSignal = abortSignal;
  }

  private async request(url: string, options: Parameters<typeof makeRequest>[1] = {}): Promise<ReturnType<typeof makeRequest>> {
    return makeRequest(url, { ...options, signal: this.abortSignal });
  }

  private async establishBaseline404(): Promise<void> {
    // Request multiple random fake files to establish baseline 404 response
    const fakeFiles = [
      `/${randomString(12)}_nonexistent_${randomString(8)}.txt`,
      `/${randomString(10)}_fake_file_${randomString(6)}.html`,
      `/${randomString(14)}_does_not_exist_${randomString(5)}.php`,
    ];

    const responses: Baseline404Response[] = [];

    for (const fakePath of fakeFiles) {
      const url = `${this.targetUrl}${fakePath}`;
      const response = await this.request(url, { timeout: 5000 });
      
      if (!response.error) {
        responses.push({
          body: response.body,
          bodyHash: hashString(response.body),
          size: response.contentLength,
          status: response.status,
        });
      }
      await sleep(50);
    }

    if (responses.length >= 2) {
      // Use the most common response as baseline
      const hashCounts = new Map<string, number>();
      for (const r of responses) {
        hashCounts.set(r.bodyHash, (hashCounts.get(r.bodyHash) || 0) + 1);
      }
      
      let maxCount = 0;
      let baselineHash = "";
      const hashCountEntries = Array.from(hashCounts.entries());
      for (let i = 0; i < hashCountEntries.length; i++) {
        const [hash, count] = hashCountEntries[i];
        if (count > maxCount) {
          maxCount = count;
          baselineHash = hash;
        }
      }
      
      this.baseline404 = responses.find(r => r.bodyHash === baselineHash) || responses[0];
      await this.onLog("info", `Established baseline 404 response: ${this.baseline404.size} bytes, status ${this.baseline404.status}`);
    }
  }

  private isSimilarToBaseline(response: any): boolean {
    if (!this.baseline404) return false;
    
    const responseHash = hashString(response.body);
    
    // Same content hash = definitely same response
    if (responseHash === this.baseline404.bodyHash) {
      return true;
    }
    
    // Similar size (within 20%) = likely same error page
    const sizeDiff = Math.abs(response.contentLength - this.baseline404.size);
    const sizeRatio = this.baseline404.size > 0 ? sizeDiff / this.baseline404.size : 0;
    if (sizeRatio < 0.2) {
      return true;
    }
    
    return false;
  }

  private hasErrorPageIndicators(body: string): boolean {
    const lowerBody = body.toLowerCase();
    const errorIndicators = [
      "page not found",
      "404 not found",
      "file not found",
      "not found",
      "does not exist",
      "resource not found",
      "the page you requested",
      "could not be found",
      "error occurred",
      "server error",
      "access denied",
      "forbidden",
      "unauthorized",
      "runtime error",
      "application error",
      "asp.net",
      "iis",
      "error page",
      "this page cannot be displayed",
      "requested url was not found",
      "http error",
    ];
    
    for (const indicator of errorIndicators) {
      if (lowerBody.includes(indicator)) {
        return true;
      }
    }
    
    return false;
  }

  async scan(): Promise<FileResult[]> {
    await this.onLog("info", "Starting sensitive file discovery...");
    
    // Establish baseline 404 response using random fake files
    await this.establishBaseline404();

    // Build list of all files to check
    const allFiles: string[] = [];

    // Add all files from categories
    Object.values(SENSITIVE_FILES).forEach(files => {
      files.forEach(file => {
        if (!file.includes("*")) { // Skip wildcards
          allFiles.push(file);
        }
      });
    });

    // Add common extensions for config files
    const extensions = [".bak", ".old", ".backup", "~", ".swp", ".save", ".orig", ".copy"];
    const baseFiles = ["config", "database", "settings", "wp-config", ".env"];
    baseFiles.forEach(base => {
      extensions.forEach(ext => {
        allFiles.push(`${base}${ext}`);
      });
    });

    // Deduplicate
    const uniqueFiles = Array.from(new Set(allFiles));
    
    await this.onLog("info", `Checking ${uniqueFiles.length} potential sensitive files...`);

    // Check files in batches
    const batchSize = 10;
    for (let i = 0; i < uniqueFiles.length; i += batchSize) {
      const batch = uniqueFiles.slice(i, i + batchSize);
      await Promise.all(batch.map(file => this.checkFile(file)));
      await sleep(100); // Rate limiting between batches
    }

    return this.foundFiles;
  }

  private async checkFile(path: string): Promise<void> {
    // Normalize path
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    
    if (this.checkedPaths.has(normalizedPath)) return;
    this.checkedPaths.add(normalizedPath);

    const url = `${this.targetUrl}${normalizedPath}`;
    const response = await this.request(url, { timeout: 5000 });

    if (response.error || response.status === 404 || response.status === 403) {
      return;
    }

    // Check against baseline 404 - if similar, it's a false positive
    if (this.isSimilarToBaseline(response)) {
      return;
    }

    // Check for error page indicators in response
    if (this.hasErrorPageIndicators(response.body)) {
      return;
    }

    // Check if it's actually the file we're looking for (not a custom 404)
    if (!this.isValidResponse(response, path)) {
      return;
    }

    const result = this.analyzeFile(path, response);
    if (result) {
      this.foundFiles.push(result);
      await this.reportVulnerability(result, url);
    }
  }

  private isValidResponse(response: any, path: string): boolean {
    const body = response.body.toLowerCase();

    // Skip if response is too small to be meaningful
    if (response.contentLength < 10) {
      return false;
    }

    // Skip if it's an HTML page for non-HTML file types
    if (
      (path.endsWith(".env") || path.endsWith(".sql") || path.endsWith(".json") || path.endsWith(".yml")) &&
      body.includes("<!doctype html")
    ) {
      return false;
    }

    return true;
  }

  private analyzeFile(path: string, response: any): FileResult | null {
    const body = response.body;
    const lowerPath = path.toLowerCase();

    // Git files
    if (lowerPath.includes(".git/")) {
      if (body.includes("ref:") || body.includes("gitdir:")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Git Repository",
          evidence: "Git repository files accessible",
          severity: "High",
        };
      }
    }

    // Environment files
    if (lowerPath.includes(".env")) {
      // Check for typical env file patterns
      if (
        body.includes("=") &&
        (body.includes("DB_") || body.includes("API_") || body.includes("SECRET") || 
         body.includes("PASSWORD") || body.includes("KEY=") || body.includes("TOKEN"))
      ) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Environment File",
          evidence: "Environment variables exposed (may contain secrets)",
          severity: "Critical",
        };
      }
    }

    // SQL/Database dumps
    if (lowerPath.includes(".sql") || lowerPath.includes("dump") || lowerPath.includes("backup")) {
      if (
        body.includes("CREATE TABLE") ||
        body.includes("INSERT INTO") ||
        body.includes("DROP TABLE") ||
        body.includes("-- MySQL dump")
      ) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Database Dump",
          evidence: "SQL database dump accessible",
          severity: "Critical",
        };
      }
    }

    // WordPress config
    if (lowerPath.includes("wp-config")) {
      if (body.includes("DB_PASSWORD") || body.includes("DB_USER") || body.includes("table_prefix")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "WordPress Configuration",
          evidence: "WordPress configuration file exposed",
          severity: "Critical",
        };
      }
    }

    // PHP info
    if (lowerPath.includes("phpinfo")) {
      if (body.includes("PHP Version") || body.includes("phpinfo()")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "PHP Info",
          evidence: "PHP configuration information exposed",
          severity: "Medium",
        };
      }
    }

    // htaccess/htpasswd
    if (lowerPath.includes(".htaccess") || lowerPath.includes(".htpasswd")) {
      if (body.includes("RewriteRule") || body.includes("AuthType") || body.includes("$")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Apache Configuration",
          evidence: lowerPath.includes("passwd") ? "Password file accessible" : "Server configuration accessible",
          severity: lowerPath.includes("passwd") ? "Critical" : "Medium",
        };
      }
    }

    // Package manager files
    if (lowerPath.includes("package.json") || lowerPath.includes("composer.json")) {
      if (body.includes("dependencies") || body.includes("require")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Package Configuration",
          evidence: "Package manager file accessible (reveals dependencies)",
          severity: "Low",
        };
      }
    }

    // Logs
    if (lowerPath.includes(".log") || lowerPath.includes("error_log")) {
      if (body.includes("[error]") || body.includes("PHP") || body.includes("Exception")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Log File",
          evidence: "Application logs accessible",
          severity: "Medium",
        };
      }
    }

    // Backup files
    if (lowerPath.includes(".bak") || lowerPath.includes(".backup") || lowerPath.includes(".old")) {
      return {
        path,
        status: response.status,
        size: response.contentLength,
        type: "Backup File",
        evidence: "Backup file accessible",
        severity: "Medium",
      };
    }

    // Generic configuration files
    if (lowerPath.includes("config") && (lowerPath.includes(".php") || lowerPath.includes(".inc"))) {
      if (body.includes("<?php") || body.includes("password") || body.includes("database")) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "Configuration File",
          evidence: "PHP configuration file accessible",
          severity: "High",
        };
      }
    }

    // YAML/YML files
    if (lowerPath.includes(".yml") || lowerPath.includes(".yaml")) {
      if (body.includes(":") && (body.includes("password") || body.includes("secret") || body.includes("key"))) {
        return {
          path,
          status: response.status,
          size: response.contentLength,
          type: "YAML Configuration",
          evidence: "YAML configuration file accessible",
          severity: "High",
        };
      }
    }

    // If we got a 200 response for a known sensitive path, report it
    if (response.status === 200 && response.contentLength > 50) {
      const sensitivePatterns = [
        { pattern: ".git", type: "Git", severity: "High" },
        { pattern: ".svn", type: "SVN", severity: "High" },
        { pattern: ".env", type: "Environment", severity: "Critical" },
        { pattern: "config", type: "Configuration", severity: "Medium" },
        { pattern: "backup", type: "Backup", severity: "Medium" },
        { pattern: "dump", type: "Database", severity: "High" },
        { pattern: "secret", type: "Secret", severity: "Critical" },
      ];

      for (const { pattern, type, severity } of sensitivePatterns) {
        if (lowerPath.includes(pattern)) {
          return {
            path,
            status: response.status,
            size: response.contentLength,
            type: `${type} File`,
            evidence: `Potentially sensitive file accessible (${response.contentLength} bytes)`,
            severity,
          };
        }
      }
    }

    return null;
  }

  private async reportVulnerability(result: FileResult, url: string): Promise<void> {
    await this.onLog("warn", `Sensitive file found: ${result.path} (${result.type})`);

    await this.onVuln({
      type: "Sensitive File Disclosure",
      severity: result.severity,
      url,
      path: result.path,
      description: `${result.type} file is publicly accessible. ${result.evidence}`,
      remediation: "Restrict access to sensitive files using web server configuration. Move sensitive files outside the web root. Use .htaccess or nginx configuration to deny access to dotfiles and backup files. Review file permissions and remove unnecessary files from production.",
      evidence: `File size: ${result.size} bytes, HTTP status: ${result.status}`,
    });
  }
}
