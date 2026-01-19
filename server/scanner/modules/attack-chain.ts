import { Vulnerability } from "@shared/schema";

export interface AttackChainLink {
  vulnId: number;
  vulnType: string;
  severity: string;
  description: string;
  order: number;
}

export interface AttackChain {
  id: string;
  name: string;
  description: string;
  links: AttackChainLink[];
  overallSeverity: "Critical" | "High" | "Medium";
  exploitability: "Easy" | "Moderate" | "Complex";
  impact: string;
  attackFlow: string;
}

interface ChainRule {
  name: string;
  requires: string[];
  optionalEnhancers: string[];
  severity: "Critical" | "High" | "Medium";
  exploitability: "Easy" | "Moderate" | "Complex";
  impact: string;
  flowTemplate: string;
  description: string;
}

const CHAIN_RULES: ChainRule[] = [
  {
    name: "Credential Theft Chain",
    requires: ["SQL Injection"],
    optionalEnhancers: ["Information Disclosure", "Error"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Full database access and credential theft",
    flowTemplate: "SQL Injection vulnerability allows database queries → Extract user credentials from database → Use credentials to access accounts directly",
    description: "An attacker can leverage SQL injection to directly query and extract user credentials, password hashes, or session tokens from the database. Combined with information disclosure, the attacker gains additional context about the database structure."
  },
  {
    name: "Account Takeover Chain",
    requires: ["XSS"],
    optionalEnhancers: ["Session", "Cookie", "CSRF"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Complete user account compromise",
    flowTemplate: "XSS vulnerability executes malicious JavaScript → Steal session cookies or tokens → Hijack authenticated user sessions → Full account takeover",
    description: "Cross-site scripting allows attackers to inject malicious JavaScript that can steal session cookies, authentication tokens, or perform actions on behalf of the victim user, leading to complete account compromise."
  },
  {
    name: "Internal Network Access Chain",
    requires: ["SSRF"],
    optionalEnhancers: ["Information Disclosure", "Cloud Metadata"],
    severity: "Critical",
    exploitability: "Moderate",
    impact: "Access to internal services and lateral movement capability",
    flowTemplate: "SSRF vulnerability accesses internal endpoints → Scan internal network services → Access cloud metadata endpoints → Retrieve AWS/GCP/Azure credentials → Lateral movement to other cloud resources",
    description: "Server-side request forgery allows attackers to make requests from the server, accessing internal network resources, cloud metadata services, and potentially obtaining cloud provider credentials for lateral movement."
  },
  {
    name: "Source Code Credential Discovery Chain",
    requires: ["LFI"],
    optionalEnhancers: ["Path Traversal", "Information Disclosure", "Directory"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Source code exposure and embedded credential theft",
    flowTemplate: "LFI vulnerability reads local files → Access configuration files → Extract database credentials, API keys → Access backend systems with stolen credentials",
    description: "Local file inclusion allows reading arbitrary files from the server, enabling attackers to access configuration files containing database credentials, API keys, and other secrets that can be used to compromise additional systems."
  },
  {
    name: "Data Exfiltration Chain",
    requires: ["SQL Injection", "Information Disclosure"],
    optionalEnhancers: ["Error", "Debug"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Complete database dump and sensitive data exposure",
    flowTemplate: "Information disclosure reveals database structure → SQL injection extracts data systematically → Complete database exfiltration including PII, credentials, and business data",
    description: "Combining information disclosure with SQL injection allows attackers to understand the database schema and extract data more efficiently, leading to complete data breaches."
  },
  {
    name: "Privilege Escalation Chain",
    requires: ["IDOR"],
    optionalEnhancers: ["Information Disclosure", "Authentication", "Authorization"],
    severity: "High",
    exploitability: "Easy",
    impact: "Access to other users' data and administrative functions",
    flowTemplate: "Information leak reveals user IDs or patterns → IDOR vulnerability allows accessing other users' resources → Escalate to admin accounts if discoverable → Full privilege escalation",
    description: "Insecure direct object references combined with information disclosure allow attackers to enumerate and access resources belonging to other users, potentially escalating to administrative privileges."
  },
  {
    name: "Stored Attack Chain",
    requires: ["Stored XSS"],
    optionalEnhancers: ["Authentication", "Admin"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Persistent attack affecting all users viewing compromised content",
    flowTemplate: "Stored XSS payload persists in application → Every user viewing content executes malicious script → Mass session theft → Potential admin account compromise",
    description: "Stored XSS creates a persistent attack vector that executes for every user who views the affected content, enabling mass credential theft and potential administrative access."
  },
  {
    name: "Authentication Bypass Chain",
    requires: ["Authentication Bypass"],
    optionalEnhancers: ["SQL Injection", "Session", "IDOR"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Complete authentication system compromise",
    flowTemplate: "Authentication bypass vulnerability discovered → Access protected resources without valid credentials → Access admin panels or sensitive data → Full system compromise",
    description: "Authentication bypass vulnerabilities allow attackers to access protected resources without valid credentials, potentially leading to admin access and complete system compromise."
  },
  {
    name: "Remote Code Execution Chain",
    requires: ["Command Injection"],
    optionalEnhancers: ["LFI", "File Upload", "SSRF"],
    severity: "Critical",
    exploitability: "Easy",
    impact: "Complete server compromise with arbitrary code execution",
    flowTemplate: "Command injection executes OS commands → Establish reverse shell → Pivot through internal network → Complete infrastructure compromise",
    description: "Command injection allows execution of arbitrary operating system commands, enabling attackers to take complete control of the server, access files, and pivot to other systems."
  },
  {
    name: "File Upload Attack Chain",
    requires: ["File Upload"],
    optionalEnhancers: ["LFI", "Path Traversal"],
    severity: "Critical",
    exploitability: "Moderate",
    impact: "Web shell upload and server takeover",
    flowTemplate: "File upload vulnerability allows malicious file → Upload web shell or backdoor → Execute arbitrary commands on server → Persistent server access",
    description: "Unrestricted file upload vulnerabilities allow attackers to upload malicious files such as web shells, providing persistent backdoor access to the server."
  },
  {
    name: "Session Manipulation Chain",
    requires: ["Session"],
    optionalEnhancers: ["XSS", "Cookie", "Authentication"],
    severity: "High",
    exploitability: "Moderate",
    impact: "Session hijacking and user impersonation",
    flowTemplate: "Session vulnerability discovered → Steal or predict session tokens → Hijack active user sessions → Impersonate legitimate users",
    description: "Session vulnerabilities allow attackers to steal, predict, or manipulate session tokens to hijack authenticated sessions and impersonate legitimate users."
  },
  {
    name: "Information Reconnaissance Chain",
    requires: ["Information Disclosure"],
    optionalEnhancers: ["Error", "Debug", "Directory"],
    severity: "Medium",
    exploitability: "Easy",
    impact: "Detailed reconnaissance enabling targeted attacks",
    flowTemplate: "Information disclosure reveals system details → Identify software versions and configurations → Research known vulnerabilities → Plan targeted exploitation",
    description: "Information disclosure provides attackers with valuable reconnaissance data about the target system, enabling them to identify and exploit known vulnerabilities in specific software versions."
  },
  {
    name: "CSRF Account Manipulation Chain",
    requires: ["CSRF"],
    optionalEnhancers: ["XSS", "Session"],
    severity: "High",
    exploitability: "Moderate",
    impact: "Unauthorized state changes on behalf of users",
    flowTemplate: "CSRF vulnerability allows forged requests → Trick users into executing malicious actions → Change passwords, email addresses, or transfer funds → Account takeover",
    description: "Cross-site request forgery allows attackers to trick authenticated users into performing unwanted actions, potentially leading to account compromise or unauthorized transactions."
  },
  {
    name: "API Exploitation Chain",
    requires: ["API"],
    optionalEnhancers: ["Authentication", "IDOR", "Rate Limiting"],
    severity: "High",
    exploitability: "Moderate",
    impact: "API abuse and unauthorized data access",
    flowTemplate: "API vulnerability discovered → Bypass authentication or rate limits → Access unauthorized endpoints → Extract sensitive data via API",
    description: "API vulnerabilities allow attackers to bypass security controls, access unauthorized endpoints, and extract or manipulate data through the application's API interfaces."
  },
  {
    name: "Path Traversal Data Access Chain",
    requires: ["Path Traversal"],
    optionalEnhancers: ["LFI", "Information Disclosure"],
    severity: "High",
    exploitability: "Easy",
    impact: "Unauthorized file system access",
    flowTemplate: "Path traversal allows escaping web root → Access system files (passwd, shadow, configs) → Extract credentials and sensitive data → Expand access to other systems",
    description: "Path traversal vulnerabilities allow attackers to escape the web root and access arbitrary files on the server, potentially exposing credentials and sensitive configuration data."
  }
];

const VULNERABILITY_TYPE_PATTERNS: Record<string, string[]> = {
  "SQL Injection": ["sql injection", "sqli", "database injection", "blind sql", "union-based", "time-based", "error-based", "boolean-based", "stacked queries"],
  "XSS": ["xss", "cross-site scripting", "cross site scripting", "script injection"],
  "Stored XSS": ["stored xss", "persistent xss", "stored cross-site"],
  "SSRF": ["ssrf", "server-side request forgery", "server side request forgery"],
  "LFI": ["lfi", "local file inclusion", "file inclusion", "file access", "arbitrary file read"],
  "IDOR": ["idor", "insecure direct object reference", "direct object reference", "bola", "broken object level authorization", "access control", "authorization bypass"],
  "Path Traversal": ["path traversal", "directory traversal", "dot dot slash", "../", "..\\"],
  "Command Injection": ["command injection", "os command injection", "rce", "remote code execution", "shell injection"],
  "File Upload": ["file upload", "unrestricted upload", "arbitrary file upload", "malicious file"],
  "Authentication Bypass": ["authentication bypass", "auth bypass", "login bypass", "broken authentication"],
  "Session": ["session", "session fixation", "session hijacking", "session management", "session token"],
  "Cookie": ["cookie", "insecure cookie", "cookie security", "httponly", "secure flag"],
  "CSRF": ["csrf", "cross-site request forgery", "cross site request forgery", "xsrf"],
  "Information Disclosure": ["information disclosure", "info leak", "information leak", "sensitive data exposure", "disclosure", "data exposure", "verbose error", "stack trace exposure"],
  "Error": ["error", "error message", "stack trace", "debug information", "exception"],
  "Debug": ["debug", "debugging", "debug mode", "development mode"],
  "Directory": ["directory listing", "directory browsing", "index of"],
  "Authentication": ["authentication", "auth", "login", "password", "credential"],
  "Authorization": ["authorization", "access control", "permission", "privilege"],
  "Admin": ["admin", "administrator", "administrative", "admin panel"],
  "API": ["api", "rest api", "graphql", "endpoint", "api key"],
  "Rate Limiting": ["rate limit", "rate limiting", "throttling", "brute force"],
  "Cloud Metadata": ["cloud metadata", "aws metadata", "imds", "instance metadata", "169.254.169.254"]
};

const TYPE_PREFIX_MAPPINGS: Record<string, string[]> = {
  "SQL Injection": ["SQL Injection", "SQLi"],
  "Cross-Site Scripting": ["XSS", "Cross-Site Scripting"],
  "Server-Side Request Forgery": ["SSRF"],
  "Local File Inclusion": ["LFI", "File Access"],
  "Insecure Direct Object Reference": ["IDOR", "Access Control"],
  "Command Injection": ["Command Injection", "RCE"],
  "Path Traversal": ["Path Traversal", "LFI"],
  "Information Disclosure": ["Information Disclosure", "Info Leak"],
  "Authentication Bypass": ["Authentication Bypass", "Authentication"],
  "Session Fixation": ["Session"],
  "Session Hijacking": ["Session"],
  "CSRF": ["CSRF"],
  "File Upload": ["File Upload"],
  "Stored XSS": ["Stored XSS", "XSS"],
  "Reflected XSS": ["XSS"],
  "DOM XSS": ["XSS"],
};

function normalizeVulnType(vulnType: string): string[] {
  const normalized: Set<string> = new Set();
  const lowerType = vulnType.toLowerCase();
  
  for (const [prefix, categories] of Object.entries(TYPE_PREFIX_MAPPINGS)) {
    if (lowerType.startsWith(prefix.toLowerCase())) {
      for (const cat of categories) {
        normalized.add(cat);
      }
    }
  }
  
  for (const [category, patterns] of Object.entries(VULNERABILITY_TYPE_PATTERNS)) {
    for (const pattern of patterns) {
      if (lowerType.includes(pattern.toLowerCase())) {
        normalized.add(category);
        break;
      }
    }
  }
  
  if (lowerType.includes("sql injection")) {
    normalized.add("SQL Injection");
  }
  if (lowerType.includes("cross-site scripting") || lowerType.includes("xss")) {
    normalized.add("XSS");
    if (lowerType.includes("stored")) {
      normalized.add("Stored XSS");
    }
  }
  if (lowerType.includes("ssrf") || lowerType.includes("server-side request")) {
    normalized.add("SSRF");
  }
  if (lowerType.includes("local file") || lowerType.includes("lfi")) {
    normalized.add("LFI");
  }
  if (lowerType.includes("idor") || lowerType.includes("direct object")) {
    normalized.add("IDOR");
  }
  if (lowerType.includes("information") && (lowerType.includes("disclosure") || lowerType.includes("leak"))) {
    normalized.add("Information Disclosure");
  }
  if (lowerType.includes("command injection") || lowerType.includes("os command")) {
    normalized.add("Command Injection");
  }
  if (lowerType.includes("path traversal") || lowerType.includes("directory traversal")) {
    normalized.add("Path Traversal");
  }
  if (lowerType.includes("session")) {
    normalized.add("Session");
  }
  if (lowerType.includes("authentication")) {
    normalized.add("Authentication");
    if (lowerType.includes("bypass")) {
      normalized.add("Authentication Bypass");
    }
  }
  if (lowerType.includes("csrf") || lowerType.includes("cross-site request forgery")) {
    normalized.add("CSRF");
  }
  if (lowerType.includes("file upload")) {
    normalized.add("File Upload");
  }
  
  return normalized.size > 0 ? Array.from(normalized) : [vulnType];
}

function matchesRequirement(vulnCategories: string[], requirement: string): boolean {
  const reqLower = requirement.toLowerCase().trim();
  
  for (const category of vulnCategories) {
    const catLower = category.toLowerCase().trim();
    
    if (catLower === reqLower) {
      return true;
    }
    
    if (catLower.includes(reqLower) || reqLower.includes(catLower)) {
      return true;
    }
    
    const reqNormalized = reqLower.replace(/[^a-z0-9]/g, '');
    const catNormalized = catLower.replace(/[^a-z0-9]/g, '');
    if (reqNormalized === catNormalized) {
      return true;
    }
    
    const abbreviationMap: Record<string, string[]> = {
      "sqli": ["sql injection", "sqlinjection"],
      "sql injection": ["sqli"],
      "xss": ["cross-site scripting", "crosssitescripting"],
      "cross-site scripting": ["xss"],
      "ssrf": ["server-side request forgery", "serversiderequestforgery"],
      "server-side request forgery": ["ssrf"],
      "lfi": ["local file inclusion", "localfileinclusion"],
      "local file inclusion": ["lfi"],
      "idor": ["insecure direct object reference", "insecuredirectobjectreference"],
      "csrf": ["cross-site request forgery", "crosssiterequestforgery"],
      "rce": ["remote code execution", "command injection"]
    };
    
    const reqAbbrevs = abbreviationMap[reqLower] || [];
    const catAbbrevs = abbreviationMap[catLower] || [];
    
    if (reqAbbrevs.some(abbr => abbr === catLower || catLower.includes(abbr))) {
      return true;
    }
    if (catAbbrevs.some(abbr => abbr === reqLower || reqLower.includes(abbr))) {
      return true;
    }
  }
  
  return false;
}

function generateChainId(rule: ChainRule, vulnIds: number[]): string {
  const idPart = vulnIds.sort().join("-");
  const namePart = rule.name.toLowerCase().replace(/\s+/g, "-");
  return `chain-${namePart}-${idPart}`;
}

function calculateExploitability(links: AttackChainLink[]): "Easy" | "Moderate" | "Complex" {
  const criticalOrHigh = links.filter(l => l.severity === "Critical" || l.severity === "High").length;
  const confirmed = links.filter(l => l.description.toLowerCase().includes("confirmed")).length;
  
  if (links.length <= 2 && criticalOrHigh >= 1 && confirmed >= 1) {
    return "Easy";
  } else if (links.length <= 3) {
    return "Moderate";
  }
  return "Complex";
}

function calculateOverallSeverity(
  ruleSeverity: "Critical" | "High" | "Medium",
  links: AttackChainLink[]
): "Critical" | "High" | "Medium" {
  const hasCritical = links.some(l => l.severity === "Critical");
  const highCount = links.filter(l => l.severity === "High").length;
  
  if (hasCritical || (highCount >= 2 && ruleSeverity === "High")) {
    return "Critical";
  }
  
  if (highCount >= 1 || ruleSeverity === "High") {
    return "High";
  }
  
  return ruleSeverity;
}

function generateAttackFlowDescription(rule: ChainRule, vulns: Vulnerability[]): string {
  const steps: string[] = [];
  
  steps.push(`**Attack Chain: ${rule.name}**\n`);
  steps.push(`**Overall Impact:** ${rule.impact}\n`);
  steps.push(`\n**Step-by-Step Attack Flow:**\n`);
  
  vulns.forEach((vuln, index) => {
    const stepNum = index + 1;
    const location = vuln.parameter ? `parameter '${vuln.parameter}'` : vuln.path || vuln.url;
    steps.push(`${stepNum}. **${vuln.type}** at ${location}`);
    if (vuln.description) {
      const shortDesc = vuln.description.split('.')[0];
      steps.push(`   - ${shortDesc}`);
    }
  });
  
  steps.push(`\n**Exploitation Path:**`);
  steps.push(rule.flowTemplate);
  
  steps.push(`\n**Why These Combine Into Higher Risk:**`);
  steps.push(rule.description);
  
  return steps.join("\n");
}

function buildChainLinks(vulns: Vulnerability[]): AttackChainLink[] {
  return vulns.map((vuln, index) => ({
    vulnId: vuln.id,
    vulnType: vuln.type,
    severity: vuln.severity,
    description: vuln.description || `${vuln.type} vulnerability detected`,
    order: index + 1
  }));
}

function findMatchingVulnerabilities(
  vulnerabilities: Vulnerability[],
  rule: ChainRule
): Vulnerability[] {
  const matched: Vulnerability[] = [];
  const usedIds = new Set<number>();
  
  for (const requirement of rule.requires) {
    for (const vuln of vulnerabilities) {
      if (usedIds.has(vuln.id)) continue;
      
      const categories = normalizeVulnType(vuln.type);
      if (matchesRequirement(categories, requirement)) {
        matched.push(vuln);
        usedIds.add(vuln.id);
        break;
      }
    }
  }
  
  if (matched.length < rule.requires.length) {
    return [];
  }
  
  for (const enhancer of rule.optionalEnhancers) {
    for (const vuln of vulnerabilities) {
      if (usedIds.has(vuln.id)) continue;
      
      const categories = normalizeVulnType(vuln.type);
      if (matchesRequirement(categories, enhancer)) {
        matched.push(vuln);
        usedIds.add(vuln.id);
        break;
      }
    }
  }
  
  matched.sort((a, b) => {
    const severityOrder: Record<string, number> = {
      "Critical": 1,
      "High": 2,
      "Medium": 3,
      "Low": 4,
      "Info": 5
    };
    return (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
  });
  
  return matched;
}

export function analyzeAttackChains(vulnerabilities: Vulnerability[]): AttackChain[] {
  const chains: AttackChain[] = [];
  const usedVulnIds = new Set<number>();
  
  if (vulnerabilities.length === 0) {
    return chains;
  }
  
  const sortedRules = [...CHAIN_RULES].sort((a, b) => {
    const severityOrder = { "Critical": 1, "High": 2, "Medium": 3 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
  
  for (const rule of sortedRules) {
    const availableVulns = vulnerabilities.filter(v => !usedVulnIds.has(v.id));
    const matchedVulns = findMatchingVulnerabilities(availableVulns, rule);
    
    if (matchedVulns.length > 0) {
      const links = buildChainLinks(matchedVulns);
      const vulnIds = matchedVulns.map(v => v.id);
      
      const chain: AttackChain = {
        id: generateChainId(rule, vulnIds),
        name: rule.name,
        description: rule.description,
        links,
        overallSeverity: calculateOverallSeverity(rule.severity, links),
        exploitability: rule.exploitability,
        impact: rule.impact,
        attackFlow: generateAttackFlowDescription(rule, matchedVulns)
      };
      
      chains.push(chain);
      
      for (const id of vulnIds) {
        usedVulnIds.add(id);
      }
    }
  }
  
  chains.sort((a, b) => {
    const severityOrder = { "Critical": 1, "High": 2, "Medium": 3 };
    const exploitOrder = { "Easy": 1, "Moderate": 2, "Complex": 3 };
    
    const sevDiff = severityOrder[a.overallSeverity] - severityOrder[b.overallSeverity];
    if (sevDiff !== 0) return sevDiff;
    
    return exploitOrder[a.exploitability] - exploitOrder[b.exploitability];
  });
  
  return chains;
}

export function generateChainReport(chains: AttackChain[]): string {
  if (chains.length === 0) {
    return "No attack chains detected.";
  }
  
  const sections: string[] = [];
  
  sections.push("# Attack Chain Analysis Report\n");
  sections.push(`**Total Chains Detected:** ${chains.length}\n`);
  
  const criticalCount = chains.filter(c => c.overallSeverity === "Critical").length;
  const highCount = chains.filter(c => c.overallSeverity === "High").length;
  const mediumCount = chains.filter(c => c.overallSeverity === "Medium").length;
  
  sections.push("## Summary");
  sections.push(`- Critical Chains: ${criticalCount}`);
  sections.push(`- High Severity Chains: ${highCount}`);
  sections.push(`- Medium Severity Chains: ${mediumCount}\n`);
  
  sections.push("## Remediation Priority");
  sections.push("Address chains in order of severity and exploitability:\n");
  
  chains.forEach((chain, index) => {
    sections.push(`${index + 1}. **${chain.name}** [${chain.overallSeverity}/${chain.exploitability}]`);
    sections.push(`   - Impact: ${chain.impact}`);
    sections.push(`   - Vulnerabilities involved: ${chain.links.length}`);
  });
  
  sections.push("\n---\n");
  sections.push("## Detailed Chain Analysis\n");
  
  for (const chain of chains) {
    sections.push(`### ${chain.name}`);
    sections.push(`**Severity:** ${chain.overallSeverity} | **Exploitability:** ${chain.exploitability}\n`);
    sections.push(chain.attackFlow);
    sections.push("\n**Vulnerabilities in this chain:**");
    
    for (const link of chain.links) {
      sections.push(`- [${link.order}] ${link.vulnType} (${link.severity})`);
    }
    
    sections.push("\n---\n");
  }
  
  return sections.join("\n");
}

export function getChainSummary(chains: AttackChain[]): {
  totalChains: number;
  criticalChains: number;
  highChains: number;
  mediumChains: number;
  easyToExploit: number;
  highestRiskChain: AttackChain | null;
} {
  return {
    totalChains: chains.length,
    criticalChains: chains.filter(c => c.overallSeverity === "Critical").length,
    highChains: chains.filter(c => c.overallSeverity === "High").length,
    mediumChains: chains.filter(c => c.overallSeverity === "Medium").length,
    easyToExploit: chains.filter(c => c.exploitability === "Easy").length,
    highestRiskChain: chains.length > 0 ? chains[0] : null
  };
}

export function getRemediationPriority(chains: AttackChain[]): Array<{
  vulnId: number;
  vulnType: string;
  priority: number;
  reason: string;
}> {
  const priorityMap = new Map<number, { priority: number; reason: string; vulnType: string }>();
  
  chains.forEach((chain, chainIndex) => {
    const chainPriority = chainIndex + 1;
    const severityMultiplier = chain.overallSeverity === "Critical" ? 1 : 
                               chain.overallSeverity === "High" ? 2 : 3;
    
    chain.links.forEach((link, linkIndex) => {
      const basePriority = (chainPriority * 10) + (linkIndex * severityMultiplier);
      const existing = priorityMap.get(link.vulnId);
      
      if (!existing || basePriority < existing.priority) {
        priorityMap.set(link.vulnId, {
          priority: basePriority,
          reason: `Part of "${chain.name}" (${chain.overallSeverity} severity, ${chain.exploitability} exploitability)`,
          vulnType: link.vulnType
        });
      }
    });
  });
  
  const result = Array.from(priorityMap.entries()).map(([vulnId, data]) => ({
    vulnId,
    vulnType: data.vulnType,
    priority: data.priority,
    reason: data.reason
  }));
  
  result.sort((a, b) => a.priority - b.priority);
  
  return result;
}
