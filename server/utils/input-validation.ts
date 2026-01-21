import { z } from "zod";

/**
 * Input Validation Middleware & Utilities
 * - التحقق من صحة المدخلات قبل المعالجة
 * - منع SQL Injection, XSS, Path Traversal
 * - Sanitization للبيانات
 */

/**
 * Validation Errors
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public value: any,
    public code: string = 'VALIDATION_ERROR'
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * URL Validation
 */
export function validateUrl(url: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Check if empty
  if (!url || url.trim().length === 0) {
    errors.push('URL cannot be empty');
    return { valid: false, errors };
  }
  
  // Check length
  if (url.length > 2048) {
    errors.push('URL is too long (max 2048 characters)');
  }
  
  // Try parsing
  try {
    const parsed = new URL(url);
    
    // Check protocol
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      errors.push(`Invalid protocol: ${parsed.protocol}. Only HTTP and HTTPS are allowed.`);
    }
    
    // Check for suspicious patterns
    if (url.includes('<script') || url.includes('javascript:')) {
      errors.push('URL contains suspicious patterns');
    }
    
    // Check hostname
    if (!parsed.hostname || parsed.hostname.length === 0) {
      errors.push('URL must have a valid hostname');
    }
    
    // Prevent localhost/internal IPs in production
    if (process.env.NODE_ENV === 'production') {
      const dangerousHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
      const isPrivate = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(parsed.hostname);
      
      if (dangerousHosts.includes(parsed.hostname) || isPrivate) {
        errors.push('Cannot scan internal/private addresses in production');
      }
    }
    
  } catch (err) {
    errors.push(`Invalid URL format: ${(err as Error).message}`);
  }
  
  return { valid: errors.length === 0, errors };
}

/**
 * Thread Count Validation
 */
export function validateThreads(threads: number | undefined): { valid: boolean; errors: string[]; value: number } {
  const errors: string[] = [];
  const defaultThreads = 10;
  
  if (threads === undefined || threads === null) {
    return { valid: true, errors: [], value: defaultThreads };
  }
  
  if (typeof threads !== 'number' || isNaN(threads)) {
    errors.push('Threads must be a valid number');
    return { valid: false, errors, value: defaultThreads };
  }
  
  if (threads < 1) {
    errors.push('Threads must be at least 1');
  }
  
  if (threads > 100) {
    errors.push('Threads cannot exceed 100');
  }
  
  if (!Number.isInteger(threads)) {
    errors.push('Threads must be an integer');
  }
  
  return { 
    valid: errors.length === 0, 
    errors, 
    value: errors.length === 0 ? threads : defaultThreads 
  };
}

/**
 * Scan Mode Validation
 */
export function validateScanMode(mode: string): { valid: boolean; errors: string[] } {
  const validModes = ['sqli', 'xss', 'xxe', 'ssrf', 'lfi', 'rfi', 'full'];
  const errors: string[] = [];
  
  if (!mode || mode.trim().length === 0) {
    errors.push('Scan mode cannot be empty');
    return { valid: false, errors };
  }
  
  if (!validModes.includes(mode.toLowerCase())) {
    errors.push(`Invalid scan mode: ${mode}. Valid modes: ${validModes.join(', ')}`);
  }
  
  return { valid: errors.length === 0, errors };
}

/**
 * Scan Request Validation (Complete)
 */
export interface ScanRequest {
  targetUrl: string;
  scanMode?: string;
  threads?: number;
  depth?: number;
  timeout?: number;
}

export function validateScanRequest(data: any): { valid: boolean; errors: string[]; validated?: ScanRequest } {
  const errors: string[] = [];
  
  // Validate URL
  const urlValidation = validateUrl(data.targetUrl);
  if (!urlValidation.valid) {
    errors.push(...urlValidation.errors);
  }
  
  // Validate threads
  const threadsValidation = validateThreads(data.threads);
  if (!threadsValidation.valid) {
    errors.push(...threadsValidation.errors);
  }
  
  // Validate scan mode
  if (data.scanMode) {
    const modeValidation = validateScanMode(data.scanMode);
    if (!modeValidation.valid) {
      errors.push(...modeValidation.errors);
    }
  }
  
  // Validate depth (optional)
  if (data.depth !== undefined) {
    if (typeof data.depth !== 'number' || data.depth < 0 || data.depth > 10) {
      errors.push('Depth must be between 0 and 10');
    }
  }
  
  // Validate timeout (optional)
  if (data.timeout !== undefined) {
    if (typeof data.timeout !== 'number' || data.timeout < 1000 || data.timeout > 3600000) {
      errors.push('Timeout must be between 1 second and 1 hour');
    }
  }
  
  if (errors.length === 0) {
    return {
      valid: true,
      errors: [],
      validated: {
        targetUrl: data.targetUrl,
        scanMode: data.scanMode || 'sqli',
        threads: threadsValidation.value,
        depth: data.depth,
        timeout: data.timeout,
      },
    };
  }
  
  return { valid: false, errors };
}

/**
 * Batch Scan Validation
 */
export function validateBatchScan(data: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!data.targetUrls || !Array.isArray(data.targetUrls)) {
    errors.push('targetUrls must be an array');
    return { valid: false, errors };
  }
  
  if (data.targetUrls.length === 0) {
    errors.push('targetUrls cannot be empty');
    return { valid: false, errors };
  }
  
  if (data.targetUrls.length > 100) {
    errors.push('Cannot scan more than 100 URLs in batch');
  }
  
  // Validate each URL
  data.targetUrls.forEach((url: any, index: number) => {
    const validation = validateUrl(url);
    if (!validation.valid) {
      errors.push(`URL at index ${index}: ${validation.errors.join(', ')}`);
    }
  });
  
  // Validate threads
  if (data.threads !== undefined) {
    const threadsValidation = validateThreads(data.threads);
    if (!threadsValidation.valid) {
      errors.push(...threadsValidation.errors);
    }
  }
  
  return { valid: errors.length === 0, errors };
}

/**
 * File Upload Validation
 */
export function validateFileUpload(data: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Validate filename
  if (!data.filename || typeof data.filename !== 'string') {
    errors.push('Filename is required and must be a string');
  } else {
    // Check for path traversal
    if (data.filename.includes('..') || data.filename.includes('/') || data.filename.includes('\\')) {
      errors.push('Filename contains invalid characters');
    }
    
    // Check extension
    const allowedExtensions = ['.txt', '.csv'];
    const hasValidExtension = allowedExtensions.some(ext => data.filename.toLowerCase().endsWith(ext));
    if (!hasValidExtension) {
      errors.push(`File must have one of these extensions: ${allowedExtensions.join(', ')}`);
    }
  }
  
  // Validate content
  if (!data.content || typeof data.content !== 'string') {
    errors.push('Content is required and must be a string');
  } else {
    // Check size (max 10MB)
    const maxSize = 10 * 1024 * 1024;
    if (data.content.length > maxSize) {
      errors.push(`File content too large (max ${maxSize / 1024 / 1024}MB)`);
    }
    
    // Check if content is empty
    if (data.content.trim().length === 0) {
      errors.push('File content cannot be empty');
    }
  }
  
  return { valid: errors.length === 0, errors };
}

/**
 * Sanitize String (remove dangerous characters)
 */
export function sanitizeString(input: string): string {
  return input
    .replace(/[<>]/g, '') // Remove < and >
    .replace(/['"]/g, '') // Remove quotes
    .replace(/[\\]/g, '') // Remove backslashes
    .trim();
}

/**
 * Sanitize HTML (prevent XSS)
 */
export function sanitizeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Validate and sanitize integer
 */
export function validateInteger(
  value: any,
  fieldName: string,
  options: { min?: number; max?: number; required?: boolean } = {}
): number {
  const { min, max, required = false } = options;
  
  // Check if required
  if (required && (value === undefined || value === null)) {
    throw new ValidationError(`${fieldName} is required`, fieldName, value, 'REQUIRED');
  }
  
  // If not required and empty, return default
  if (value === undefined || value === null) {
    return min || 0;
  }
  
  // Parse to number
  const num = typeof value === 'string' ? parseInt(value, 10) : value;
  
  // Check if valid number
  if (typeof num !== 'number' || isNaN(num) || !Number.isInteger(num)) {
    throw new ValidationError(
      `${fieldName} must be a valid integer`,
      fieldName,
      value,
      'INVALID_TYPE'
    );
  }
  
  // Check min
  if (min !== undefined && num < min) {
    throw new ValidationError(
      `${fieldName} must be at least ${min}`,
      fieldName,
      value,
      'MIN_VALUE'
    );
  }
  
  // Check max
  if (max !== undefined && num > max) {
    throw new ValidationError(
      `${fieldName} must be at most ${max}`,
      fieldName,
      value,
      'MAX_VALUE'
    );
  }
  
  return num;
}

/**
 * Express Middleware للتحقق من الطلبات
 */
export function validateScanRequestMiddleware(req: any, res: any, next: any): void {
  const validation = validateScanRequest(req.body);
  
  if (!validation.valid) {
    return res.status(400).json({
      message: 'Validation failed',
      errors: validation.errors,
    });
  }
  
  // Replace body with validated data
  req.body = validation.validated;
  next();
}

/**
 * Zod Schemas (alternative to manual validation)
 */
export const scanRequestSchema = z.object({
  targetUrl: z.string().url().max(2048),
  scanMode: z.enum(['sqli', 'xss', 'xxe', 'ssrf', 'lfi', 'rfi', 'full']).optional().default('sqli'),
  threads: z.number().int().min(1).max(100).optional().default(10),
  depth: z.number().int().min(0).max(10).optional(),
  timeout: z.number().int().min(1000).max(3600000).optional(),
});

export const batchScanRequestSchema = z.object({
  targetUrls: z.array(z.string().url().max(2048)).min(1).max(100),
  scanMode: z.enum(['sqli', 'xss', 'xxe', 'ssrf', 'lfi', 'rfi', 'full']).optional().default('sqli'),
  threads: z.number().int().min(1).max(100).optional().default(10),
});

export const fileUploadSchema = z.object({
  filename: z.string().min(1).max(255).refine(
    (name) => !name.includes('..') && !name.includes('/') && !name.includes('\\'),
    { message: 'Filename contains invalid characters' }
  ),
  content: z.string().min(1).max(10 * 1024 * 1024), // 10MB max
});

/**
 * مثال استخدام:
 * 
 * // Manual validation
 * const validation = validateScanRequest(req.body);
 * if (!validation.valid) {
 *   return res.status(400).json({ errors: validation.errors });
 * }
 * 
 * // With Zod
 * const validated = scanRequestSchema.parse(req.body);
 * 
 * // As middleware
 * app.post('/api/scans', validateScanRequestMiddleware, async (req, res) => {
 *   // req.body is now validated and sanitized
 * });
 */
