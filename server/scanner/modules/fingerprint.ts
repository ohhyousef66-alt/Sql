import { TECHNOLOGY_SIGNATURES, CVE_DATABASE } from "../payloads";
import { makeRequest, buildUrl } from "../utils";
import { InsertVulnerability } from "@shared/schema";

interface Technology {
  name: string;
  version?: string;
  confidence: "high" | "medium" | "low";
  category: "cms" | "framework" | "server" | "language" | "library";
}

interface FingerprintResult {
  technologies: Technology[];
  cves: Array<{ id: string; description: string; severity: string }>;
  headers: Record<string, string>;
}

export class FingerprintModule {
  private targetUrl: string;
  private onLog: (level: string, message: string) => Promise<void>;
  private onVuln: (vuln: Omit<InsertVulnerability, "scanId">) => Promise<void>;

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

  async scan(): Promise<FingerprintResult> {
    await this.onLog("info", "Starting technology fingerprinting...");

    const result: FingerprintResult = {
      technologies: [],
      cves: [],
      headers: {},
    };

    // Fetch main page
    const mainPage = await this.request(this.targetUrl);
    if (mainPage.error) {
      await this.onLog("error", "Failed to fetch main page for fingerprinting");
      return result;
    }

    result.headers = mainPage.headers;

    // Analyze headers
    await this.analyzeHeaders(mainPage.headers, result);

    // Analyze content
    await this.analyzeContent(mainPage.body, result);

    // Check technology-specific paths
    await this.checkSpecificPaths(result);

    // Extract version information
    await this.extractVersions(result);

    // Get relevant CVEs
    this.lookupCVEs(result);

    // Report findings
    await this.reportFindings(result);

    return result;
  }

  private async analyzeHeaders(headers: Record<string, string>, result: FingerprintResult): Promise<void> {
    const headerLower = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
    );

    // Server header
    if (headerLower["server"]) {
      const server = headerLower["server"];
      
      if (server.includes("nginx")) {
        const version = server.match(/nginx\/([\d.]+)/)?.[1];
        result.technologies.push({
          name: "nginx",
          version,
          confidence: "high",
          category: "server",
        });
      }
      
      if (server.includes("Apache")) {
        const version = server.match(/Apache\/([\d.]+)/)?.[1];
        result.technologies.push({
          name: "apache",
          version,
          confidence: "high",
          category: "server",
        });
      }
      
      if (server.includes("Microsoft-IIS")) {
        const version = server.match(/IIS\/([\d.]+)/)?.[1];
        result.technologies.push({
          name: "iis",
          version,
          confidence: "high",
          category: "server",
        });
      }
    }

    // X-Powered-By header
    if (headerLower["x-powered-by"]) {
      const poweredBy = headerLower["x-powered-by"];
      
      if (poweredBy.includes("PHP")) {
        const version = poweredBy.match(/PHP\/([\d.]+)/)?.[1];
        result.technologies.push({
          name: "php",
          version,
          confidence: "high",
          category: "language",
        });
      }
      
      if (poweredBy.includes("ASP.NET")) {
        result.technologies.push({
          name: "aspnet",
          confidence: "high",
          category: "framework",
        });
      }
      
      if (poweredBy.includes("Express")) {
        result.technologies.push({
          name: "express",
          confidence: "high",
          category: "framework",
        });
      }
    }

    // X-AspNet-Version
    if (headerLower["x-aspnet-version"]) {
      result.technologies.push({
        name: "aspnet",
        version: headerLower["x-aspnet-version"],
        confidence: "high",
        category: "framework",
      });
    }

    // Session cookies
    if (headerLower["set-cookie"]) {
      const cookie = headerLower["set-cookie"];
      
      if (cookie.includes("PHPSESSID")) {
        if (!result.technologies.some(t => t.name === "php")) {
          result.technologies.push({
            name: "php",
            confidence: "high",
            category: "language",
          });
        }
      }
      
      if (cookie.includes("JSESSIONID")) {
        result.technologies.push({
          name: "java",
          confidence: "high",
          category: "language",
        });
      }
      
      if (cookie.includes("ASP.NET_SessionId")) {
        if (!result.technologies.some(t => t.name === "aspnet")) {
          result.technologies.push({
            name: "aspnet",
            confidence: "high",
            category: "framework",
          });
        }
      }
      
      if (cookie.includes("laravel_session")) {
        result.technologies.push({
          name: "laravel",
          confidence: "high",
          category: "framework",
        });
      }
      
      if (cookie.includes("django") || cookie.includes("csrftoken")) {
        result.technologies.push({
          name: "django",
          confidence: "medium",
          category: "framework",
        });
      }
    }

    // X-Generator
    if (headerLower["x-generator"]) {
      const generator = headerLower["x-generator"];
      
      if (generator.includes("Drupal")) {
        const version = generator.match(/Drupal\s*([\d.]+)/)?.[1];
        result.technologies.push({
          name: "drupal",
          version,
          confidence: "high",
          category: "cms",
        });
      }
    }

    // Report exposed headers
    const sensitiveHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-generator"];
    for (const header of sensitiveHeaders) {
      if (headerLower[header]) {
        await this.onVuln({
          type: "Information Disclosure",
          severity: "Info",
          url: this.targetUrl,
          description: `Server header '${header}' reveals technology information: ${headerLower[header]}`,
          remediation: "Configure the server to suppress version information in headers. For nginx: server_tokens off; For Apache: ServerTokens Prod; ServerSignature Off",
          evidence: `${header}: ${headerLower[header]}`,
        });
      }
    }
  }

  private async analyzeContent(body: string, result: FingerprintResult): Promise<void> {
    const lowerBody = body.toLowerCase();

    // WordPress detection
    if (
      lowerBody.includes("wp-content") ||
      lowerBody.includes("wp-includes") ||
      lowerBody.includes("/wp-json/")
    ) {
      // Try to get version from meta generator
      const versionMatch = body.match(/content="WordPress\s*([\d.]+)"/i);
      result.technologies.push({
        name: "wordpress",
        version: versionMatch?.[1],
        confidence: "high",
        category: "cms",
      });
    }

    // Joomla detection
    if (
      lowerBody.includes("/media/jui/") ||
      lowerBody.includes("joomla!") ||
      body.includes("com_content")
    ) {
      result.technologies.push({
        name: "joomla",
        confidence: "high",
        category: "cms",
      });
    }

    // Drupal detection
    if (
      lowerBody.includes("drupal") ||
      lowerBody.includes("/sites/default/") ||
      lowerBody.includes("/misc/drupal.js")
    ) {
      result.technologies.push({
        name: "drupal",
        confidence: "high",
        category: "cms",
      });
    }

    // Magento detection
    if (
      lowerBody.includes("mage.") ||
      lowerBody.includes("/skin/frontend/") ||
      lowerBody.includes("magento")
    ) {
      result.technologies.push({
        name: "magento",
        confidence: "high",
        category: "cms",
      });
    }

    // Shopify detection
    if (lowerBody.includes("shopify") || lowerBody.includes("cdn.shopify.com")) {
      result.technologies.push({
        name: "shopify",
        confidence: "high",
        category: "cms",
      });
    }

    // React detection
    if (
      lowerBody.includes("react") ||
      lowerBody.includes("__react") ||
      body.includes("reactDOM")
    ) {
      result.technologies.push({
        name: "react",
        confidence: "medium",
        category: "library",
      });
    }

    // Angular detection
    if (lowerBody.includes("ng-version") || lowerBody.includes("angular")) {
      const versionMatch = body.match(/ng-version="([\d.]+)"/);
      result.technologies.push({
        name: "angular",
        version: versionMatch?.[1],
        confidence: "high",
        category: "library",
      });
    }

    // Vue.js detection
    if (lowerBody.includes("vue.js") || lowerBody.includes("__vue__")) {
      result.technologies.push({
        name: "vuejs",
        confidence: "medium",
        category: "library",
      });
    }

    // jQuery detection
    if (lowerBody.includes("jquery")) {
      const versionMatch = body.match(/jquery[.-]?([\d.]+)/i);
      result.technologies.push({
        name: "jquery",
        version: versionMatch?.[1],
        confidence: "high",
        category: "library",
      });
    }

    // Bootstrap detection
    if (lowerBody.includes("bootstrap")) {
      const versionMatch = body.match(/bootstrap[.-]?([\d.]+)/i);
      result.technologies.push({
        name: "bootstrap",
        version: versionMatch?.[1],
        confidence: "medium",
        category: "library",
      });
    }

    // Generator meta tag
    const generatorMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
    if (generatorMatch) {
      await this.onVuln({
        type: "Information Disclosure",
        severity: "Info",
        url: this.targetUrl,
        description: `Generator meta tag reveals: ${generatorMatch[1]}`,
        remediation: "Remove the generator meta tag from your HTML templates.",
        evidence: generatorMatch[1],
      });
    }
  }

  private async checkSpecificPaths(result: FingerprintResult): Promise<void> {
    // Skip CMS detection if ASP.NET is already detected (can't be both WordPress and ASP.NET)
    const hasAspNet = result.technologies.some(t => t.name === "aspnet" || t.name === "iis");
    
    // WordPress specific - require WordPress-specific content, not just 200 status
    if (!hasAspNet) {
      const wpPaths = ["/wp-login.php", "/wp-admin/"];
      for (const path of wpPaths) {
        const response = await this.request(`${this.targetUrl}${path}`);
        // Must have 200 status AND contain WordPress-specific content
        if (response.status === 200 && 
            (response.body.includes("wp-login") || 
             response.body.includes("WordPress") ||
             response.body.includes("wp-includes"))) {
          if (!result.technologies.some(t => t.name === "wordpress")) {
            result.technologies.push({
              name: "wordpress",
              confidence: "high",
              category: "cms",
            });
          }
          break;
        }
      }
    }

    // Joomla specific
    const joomlaPaths = ["/administrator/", "/administrator/index.php"];
    for (const path of joomlaPaths) {
      const response = await this.request(`${this.targetUrl}${path}`);
      if (response.status === 200 && response.body.includes("Joomla")) {
        if (!result.technologies.some(t => t.name === "joomla")) {
          result.technologies.push({
            name: "joomla",
            confidence: "high",
            category: "cms",
          });
        }
        break;
      }
    }

    // Drupal specific
    const drupalPaths = ["/CHANGELOG.txt", "/core/CHANGELOG.txt"];
    for (const path of drupalPaths) {
      const response = await this.request(`${this.targetUrl}${path}`);
      if (response.status === 200 && response.body.includes("Drupal")) {
        const versionMatch = response.body.match(/Drupal\s*([\d.]+)/);
        if (!result.technologies.some(t => t.name === "drupal")) {
          result.technologies.push({
            name: "drupal",
            version: versionMatch?.[1],
            confidence: "high",
            category: "cms",
          });
        }
        break;
      }
    }
  }

  private async extractVersions(result: FingerprintResult): Promise<void> {
    // Try to get more specific versions where possible
    for (const tech of result.technologies) {
      if (!tech.version && tech.name === "wordpress") {
        // Try to get WP version from feed
        const feedResponse = await this.request(`${this.targetUrl}/feed/`);
        if (feedResponse.status === 200) {
          const versionMatch = feedResponse.body.match(/generator>https:\/\/wordpress.org\/\?v=([\d.]+)</);
          if (versionMatch) {
            tech.version = versionMatch[1];
          }
        }
      }
    }
  }

  private lookupCVEs(result: FingerprintResult): void {
    // Skip PHP/WordPress/Joomla/Drupal CVEs when ASP.NET is detected (incompatible technologies)
    const hasAspNet = result.technologies.some(t => t.name === "aspnet" || t.name === "iis");
    const phpOnlyTech = ["wordpress", "joomla", "drupal", "magento", "php", "laravel"];
    
    for (const tech of result.technologies) {
      // Skip PHP-based technology CVEs if ASP.NET is detected
      if (hasAspNet && phpOnlyTech.includes(tech.name.toLowerCase())) {
        continue;
      }
      
      const cves = CVE_DATABASE[tech.name];
      if (cves) {
        result.cves.push(...cves);
      }
    }
  }

  private async reportFindings(result: FingerprintResult): Promise<void> {
    // Report detected technologies
    if (result.technologies.length > 0) {
      const techList = result.technologies
        .map(t => `${t.name}${t.version ? ` ${t.version}` : ""}`)
        .join(", ");
      
      await this.onLog("info", `Detected technologies: ${techList}`);
    }

    // Report CVEs
    for (const cve of result.cves) {
      await this.onVuln({
        type: "Known Vulnerability (CVE)",
        severity: cve.severity,
        url: this.targetUrl,
        description: `${cve.id}: ${cve.description}`,
        remediation: "Update the affected software to the latest patched version. Check vendor security advisories for specific remediation steps.",
        evidence: cve.id,
      });
    }
  }
}
