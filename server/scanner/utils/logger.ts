export interface DebugLogContext {
  url?: string;
  parameter?: string;
  payload?: string;
  response?: {
    status?: number;
    contentType?: string;
    length?: number;
  };
  decision?: string;
  reason?: string;
  error?: string;
  stack?: string;
  [key: string]: any;
}

export interface DebugLogEntry {
  timestamp: Date;
  level: "debug" | "info" | "warn" | "error";
  module: string;
  message: string;
  context?: DebugLogContext;
}

export type LogCallback = (level: string, message: string) => Promise<void>;

export class ScannerLogger {
  private scanId: number;
  private onLog: LogCallback;
  private debugLogs: DebugLogEntry[] = [];
  private debugEnabled: boolean;

  constructor(scanId: number, onLog: LogCallback, debugEnabled: boolean = true) {
    this.scanId = scanId;
    this.onLog = onLog;
    this.debugEnabled = debugEnabled;
  }

  private addDebugLog(entry: DebugLogEntry): void {
    this.debugLogs.push(entry);
    if (this.debugLogs.length > 10000) {
      this.debugLogs = this.debugLogs.slice(-5000);
    }
  }

  async debug(module: string, message: string, context?: DebugLogContext): Promise<void> {
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "debug",
      module,
      message,
      context,
    };
    this.addDebugLog(entry);
    if (this.debugEnabled) {
      const contextStr = context ? ` | ${this.formatContext(context)}` : "";
      console.log(`[DEBUG][${module}] ${message}${contextStr}`);
    }
  }

  async info(module: string, message: string, context?: DebugLogContext): Promise<void> {
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "info",
      module,
      message,
      context,
    };
    this.addDebugLog(entry);
    await this.onLog("info", `[${module}] ${message}`);
  }

  async warn(module: string, message: string, error?: Error, context?: DebugLogContext): Promise<void> {
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "warn",
      module,
      message,
      context: {
        ...context,
        error: error?.message,
        stack: error?.stack,
      },
    };
    this.addDebugLog(entry);
    const errorStr = error ? `: ${error.message}` : "";
    await this.onLog("warn", `[${module}] ${message}${errorStr}`);
  }

  async error(module: string, message: string, error: Error, context?: DebugLogContext): Promise<void> {
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "error",
      module,
      message,
      context: {
        ...context,
        error: error.message,
        stack: error.stack,
      },
    };
    this.addDebugLog(entry);
    await this.onLog("error", `[${module}] ${message}: ${error.message}`);
  }

  logFindingDecision(
    module: string,
    decision: "vulnerable" | "not_vulnerable" | "skipped" | "inconclusive",
    reason: string,
    context: DebugLogContext
  ): void {
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "debug",
      module,
      message: `Finding decision: ${decision}`,
      context: {
        ...context,
        decision,
        reason,
      },
    };
    this.addDebugLog(entry);
    if (this.debugEnabled) {
      console.log(`[FINDING][${module}] ${decision}: ${reason}`);
    }
  }

  logPayloadTest(
    module: string,
    action: "testing" | "skipped",
    payload: string,
    reason: string,
    context?: DebugLogContext
  ): void {
    const truncatedPayload = payload.length > 100 ? payload.substring(0, 100) + "..." : payload;
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "debug",
      module,
      message: `Payload ${action}: ${truncatedPayload}`,
      context: {
        ...context,
        payload,
        reason,
      },
    };
    this.addDebugLog(entry);
    if (this.debugEnabled) {
      console.log(`[PAYLOAD][${module}] ${action}: ${truncatedPayload} | Reason: ${reason}`);
    }
  }

  logResponseAnalysis(
    module: string,
    url: string,
    response: { status?: number; contentType?: string; length?: number; error?: string },
    analysis: string
  ): void {
    const entry: DebugLogEntry = {
      timestamp: new Date(),
      level: "debug",
      module,
      message: `Response analysis: ${analysis}`,
      context: {
        url,
        response,
      },
    };
    this.addDebugLog(entry);
    if (this.debugEnabled) {
      console.log(`[RESPONSE][${module}] ${url} - Status: ${response.status}, Length: ${response.length} | ${analysis}`);
    }
  }

  getDebugLogs(): DebugLogEntry[] {
    return [...this.debugLogs];
  }

  getLogsByLevel(level: DebugLogEntry["level"]): DebugLogEntry[] {
    return this.debugLogs.filter(log => log.level === level);
  }

  getLogsByModule(module: string): DebugLogEntry[] {
    return this.debugLogs.filter(log => log.module === module);
  }

  getRecentLogs(count: number = 100): DebugLogEntry[] {
    return this.debugLogs.slice(-count);
  }

  clearLogs(): void {
    this.debugLogs = [];
  }

  private formatContext(context: DebugLogContext): string {
    const parts: string[] = [];
    if (context.url) parts.push(`url=${context.url}`);
    if (context.parameter) parts.push(`param=${context.parameter}`);
    if (context.payload) {
      const truncated = context.payload.length > 50 ? context.payload.substring(0, 50) + "..." : context.payload;
      parts.push(`payload=${truncated}`);
    }
    if (context.response) {
      parts.push(`status=${context.response.status}`);
    }
    if (context.decision) parts.push(`decision=${context.decision}`);
    if (context.reason) parts.push(`reason=${context.reason}`);
    if (context.error) parts.push(`error=${context.error}`);
    return parts.join(", ");
  }
}
