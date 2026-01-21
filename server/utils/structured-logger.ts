import fs from "fs";
import path from "path";

/**
 * مستويات اللوغينغ - من الأقل أهمية للأعلى
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4,
}

/**
 * واجهة رسالة لوغ منظمة
 */
export interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  levelName: string;
  module: string;
  message: string;
  context?: Record<string, any>;
  scanId?: number;
  traceId?: string;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

/**
 * Logger منظم ومحسّن للأداء
 * - يدعم مستويات لوغينغ متعددة
 * - يحفظ اللوغات في ملف و Console
 * - يدعم Trace ID للتتبع
 * - يدعم Context إضافي
 */
export class StructuredLogger {
  private minLevel: LogLevel;
  private logFilePath: string | null;
  private consoleEnabled: boolean;
  private fileEnabled: boolean;

  constructor(options: {
    minLevel?: LogLevel;
    logFilePath?: string;
    consoleEnabled?: boolean;
    fileEnabled?: boolean;
  } = {}) {
    this.minLevel = options.minLevel ?? (process.env.NODE_ENV === 'production' ? LogLevel.INFO : LogLevel.DEBUG);
    this.logFilePath = options.logFilePath ?? null;
    this.consoleEnabled = options.consoleEnabled ?? true;
    this.fileEnabled = options.fileEnabled ?? false;

    if (this.fileEnabled && this.logFilePath) {
      // Create logs directory if doesn't exist
      const logDir = path.dirname(this.logFilePath);
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
    }
  }

  /**
   * تعيين الحد الأدنى لمستوى اللوغ
   */
  setMinLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  /**
   * تعيين مسار ملف اللوغ
   */
  setLogFilePath(filePath: string): void {
    this.logFilePath = filePath;
    this.fileEnabled = true;
    
    const logDir = path.dirname(filePath);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  /**
   * تسجيل رسالة DEBUG
   */
  debug(message: string, context?: Record<string, any>, module: string = "App"): void {
    this.log(LogLevel.DEBUG, message, module, context);
  }

  /**
   * تسجيل رسالة INFO
   */
  info(message: string, context?: Record<string, any>, module: string = "App"): void {
    this.log(LogLevel.INFO, message, module, context);
  }

  /**
   * تسجيل رسالة WARN
   */
  warn(message: string, context?: Record<string, any>, module: string = "App"): void {
    this.log(LogLevel.WARN, message, module, context);
  }

  /**
   * تسجيل رسالة ERROR
   */
  error(message: string, error?: Error, context?: Record<string, any>, module: string = "App"): void {
    const entry: Partial<LogEntry> = { ...context };
    
    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };
    }
    
    this.log(LogLevel.ERROR, message, module, entry as Record<string, any>);
  }

  /**
   * تسجيل رسالة CRITICAL
   */
  critical(message: string, error?: Error, context?: Record<string, any>, module: string = "App"): void {
    const entry: Partial<LogEntry> = { ...context };
    
    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };
    }
    
    this.log(LogLevel.CRITICAL, message, module, entry as Record<string, any>);
  }

  /**
   * الدالة الأساسية للتسجيل
   */
  private log(
    level: LogLevel,
    message: string,
    module: string,
    context?: Record<string, any>
  ): void {
    // Skip if below minimum level
    if (level < this.minLevel) return;

    const entry: LogEntry = {
      timestamp: new Date(),
      level,
      levelName: LogLevel[level],
      module,
      message,
      context,
      scanId: context?.scanId,
      traceId: context?.traceId,
    };

    // Console output with color
    if (this.consoleEnabled) {
      this.logToConsole(entry);
    }

    // File output (async, non-blocking)
    if (this.fileEnabled && this.logFilePath) {
      this.logToFile(entry);
    }
  }

  /**
   * طباعة اللوغ في Console بألوان
   */
  private logToConsole(entry: LogEntry): void {
    const colorMap: Record<LogLevel, string> = {
      [LogLevel.DEBUG]: '\x1b[36m', // Cyan
      [LogLevel.INFO]: '\x1b[32m',  // Green
      [LogLevel.WARN]: '\x1b[33m',  // Yellow
      [LogLevel.ERROR]: '\x1b[31m', // Red
      [LogLevel.CRITICAL]: '\x1b[35m', // Magenta
    };

    const reset = '\x1b[0m';
    const color = colorMap[entry.level];
    
    const timestamp = entry.timestamp.toISOString();
    const levelPadded = entry.levelName.padEnd(8);
    const modulePadded = `[${entry.module}]`.padEnd(12);
    
    let logLine = `${color}${timestamp} ${levelPadded}${reset} ${modulePadded} ${entry.message}`;
    
    if (entry.scanId) {
      logLine += ` ${color}[Scan:${entry.scanId}]${reset}`;
    }
    
    if (entry.traceId) {
      logLine += ` ${color}[Trace:${entry.traceId}]${reset}`;
    }
    
    console.log(logLine);
    
    // Print context if exists
    if (entry.context && Object.keys(entry.context).length > 0) {
      console.log(`  Context:`, entry.context);
    }
    
    // Print error if exists
    if (entry.error) {
      console.error(`  Error: ${entry.error.name}: ${entry.error.message}`);
      if (entry.error.stack) {
        console.error(`  Stack:\n${entry.error.stack}`);
      }
    }
  }

  /**
   * حفظ اللوغ في ملف (non-blocking)
   */
  private logToFile(entry: LogEntry): void {
    if (!this.logFilePath) return;

    const logObject = {
      timestamp: entry.timestamp.toISOString(),
      level: entry.levelName,
      module: entry.module,
      message: entry.message,
      ...(entry.scanId && { scanId: entry.scanId }),
      ...(entry.traceId && { traceId: entry.traceId }),
      ...(entry.context && { context: entry.context }),
      ...(entry.error && { error: entry.error }),
    };

    const logLine = JSON.stringify(logObject) + '\n';

    // Append asynchronously (non-blocking)
    fs.appendFile(this.logFilePath, logLine, (err) => {
      if (err) {
        console.error(`Failed to write log to file: ${err.message}`);
      }
    });
  }

  /**
   * إنشاء logger فرعي بـ module name محدد
   */
  createChild(module: string): LoggerChild {
    return new LoggerChild(this, module);
  }

  /**
   * تنظيف اللوغات القديمة (اختياري)
   */
  async cleanOldLogs(daysToKeep: number = 7): Promise<void> {
    if (!this.logFilePath || !this.fileEnabled) return;

    const logDir = path.dirname(this.logFilePath);
    const files = fs.readdirSync(logDir);
    const now = Date.now();
    const maxAge = daysToKeep * 24 * 60 * 60 * 1000;

    for (const file of files) {
      const filePath = path.join(logDir, file);
      const stats = fs.statSync(filePath);
      
      if (now - stats.mtimeMs > maxAge) {
        fs.unlinkSync(filePath);
        this.info(`Deleted old log file: ${file}`, undefined, "Logger");
      }
    }
  }
}

/**
 * Logger فرعي مع module name ثابت
 */
export class LoggerChild {
  constructor(
    private parent: StructuredLogger,
    private module: string
  ) {}

  debug(message: string, context?: Record<string, any>): void {
    this.parent.debug(message, context, this.module);
  }

  info(message: string, context?: Record<string, any>): void {
    this.parent.info(message, context, this.module);
  }

  warn(message: string, context?: Record<string, any>): void {
    this.parent.warn(message, context, this.module);
  }

  error(message: string, error?: Error, context?: Record<string, any>): void {
    this.parent.error(message, error, context, this.module);
  }

  critical(message: string, error?: Error, context?: Record<string, any>): void {
    this.parent.critical(message, error, context, this.module);
  }
}

/**
 * Global logger instance
 */
export const globalLogger = new StructuredLogger({
  minLevel: process.env.NODE_ENV === 'production' ? LogLevel.INFO : LogLevel.DEBUG,
  consoleEnabled: true,
  fileEnabled: process.env.LOG_TO_FILE === 'true',
  logFilePath: process.env.LOG_FILE_PATH || './logs/app.log',
});

/**
 * دالة مساعدة لإنشاء trace ID
 */
export function generateTraceId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Middleware لإضافة trace ID للطلبات
 */
export function traceMiddleware(req: any, res: any, next: any): void {
  req.traceId = generateTraceId();
  res.setHeader('X-Trace-ID', req.traceId);
  next();
}
