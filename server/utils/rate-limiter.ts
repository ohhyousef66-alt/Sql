import { Request, Response, NextFunction } from "express";

/**
 * Rate Limiting Middleware
 * - يحد من عدد الطلبات لكل IP
 * - يمنع DOS attacks
 * - يدعم مستويات مختلفة للحدود
 */

interface RateLimitEntry {
  count: number;
  firstRequest: number;
  resetTime: number;
}

interface RateLimitOptions {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Maximum requests per window
  message?: string;
  statusCode?: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: Request) => string;
  handler?: (req: Request, res: Response) => void;
  onLimitReached?: (req: Request) => void;
}

/**
 * In-memory Rate Limiter
 */
class RateLimiter {
  private store: Map<string, RateLimitEntry> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Clean up expired entries every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.resetTime) {
        this.store.delete(key);
      }
    }
  }

  check(key: string, windowMs: number, maxRequests: number): { allowed: boolean; remaining: number; resetTime: number } {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now > entry.resetTime) {
      // New window
      const newEntry: RateLimitEntry = {
        count: 1,
        firstRequest: now,
        resetTime: now + windowMs,
      };
      this.store.set(key, newEntry);

      return {
        allowed: true,
        remaining: maxRequests - 1,
        resetTime: newEntry.resetTime,
      };
    }

    // Existing window
    if (entry.count < maxRequests) {
      entry.count++;
      return {
        allowed: true,
        remaining: maxRequests - entry.count,
        resetTime: entry.resetTime,
      };
    }

    // Limit exceeded
    return {
      allowed: false,
      remaining: 0,
      resetTime: entry.resetTime,
    };
  }

  reset(key: string): void {
    this.store.delete(key);
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}

// Global rate limiter instance
const globalLimiter = new RateLimiter();

/**
 * Default key generator (by IP)
 */
function defaultKeyGenerator(req: Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

/**
 * Create Rate Limit Middleware
 */
export function createRateLimit(options: RateLimitOptions) {
  const {
    windowMs,
    maxRequests,
    message = 'Too many requests, please try again later',
    statusCode = 429,
    skipSuccessfulRequests = false,
    skipFailedRequests = false,
    keyGenerator = defaultKeyGenerator,
    handler,
    onLimitReached,
  } = options;

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = keyGenerator(req);
    const result = globalLimiter.check(key, windowMs, maxRequests);

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', maxRequests.toString());
    res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
    res.setHeader('X-RateLimit-Reset', new Date(result.resetTime).toISOString());

    if (!result.allowed) {
      // Rate limit exceeded
      res.setHeader('Retry-After', Math.ceil((result.resetTime - Date.now()) / 1000).toString());

      if (onLimitReached) {
        onLimitReached(req);
      }

      if (handler) {
        handler(req, res);
        return;
      }

      res.status(statusCode).json({
        message,
        retryAfter: Math.ceil((result.resetTime - Date.now()) / 1000),
      });
      return;
    }

    // Track response to potentially skip counting
    if (skipSuccessfulRequests || skipFailedRequests) {
      const originalSend = res.send.bind(res);
      res.send = function (body: any) {
        const statusCode = res.statusCode;
        const isSuccessful = statusCode >= 200 && statusCode < 400;
        const isFailed = statusCode >= 400;

        if ((skipSuccessfulRequests && isSuccessful) || (skipFailedRequests && isFailed)) {
          // Decrement count
          globalLimiter.reset(key);
          globalLimiter.check(key, windowMs, maxRequests); // Re-initialize with count-1
        }

        return originalSend(body);
      };
    }

    next();
  };
}

/**
 * Predefined Rate Limiters
 */

// General API rate limit: 100 requests per 15 minutes
export const apiRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 100,
  message: 'Too many API requests, please try again later',
});

// Scan creation rate limit: 10 scans per 15 minutes per IP
export const scanCreationRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  message: 'Too many scan requests, please try again later',
  skipSuccessfulRequests: false,
});

// Batch scan rate limit: 3 batch scans per hour per IP
export const batchScanRateLimit = createRateLimit({
  windowMs: 60 * 60 * 1000,
  maxRequests: 3,
  message: 'Too many batch scan requests, please try again later',
});

// File upload rate limit: 5 uploads per 10 minutes per IP
export const fileUploadRateLimit = createRateLimit({
  windowMs: 10 * 60 * 1000,
  maxRequests: 5,
  message: 'Too many file uploads, please try again later',
});

// Authentication rate limit: 20 login attempts per 5 minutes
export const authRateLimit = createRateLimit({
  windowMs: 5 * 60 * 1000,
  maxRequests: 20,
  message: 'Too many authentication attempts, please try again later',
  skipSuccessfulRequests: true, // Don't count successful logins
});

// Aggressive rate limit for sensitive endpoints: 5 requests per minute
export const strictRateLimit = createRateLimit({
  windowMs: 60 * 1000,
  maxRequests: 5,
  message: 'Rate limit exceeded for this endpoint',
});

/**
 * Rate limit by User ID (for authenticated users)
 */
export const createUserRateLimit = (options: Omit<RateLimitOptions, 'keyGenerator'>) => {
  return createRateLimit({
    ...options,
    keyGenerator: (req: Request) => {
      // Get user ID from req.user (set by auth middleware)
      const userId = (req as any).user?.id;
      return userId ? `user:${userId}` : `ip:${req.ip || 'unknown'}`;
    },
  });
};

/**
 * Rate limit by Scan Target (prevent hammering same target)
 */
export const createTargetRateLimit = (options: Omit<RateLimitOptions, 'keyGenerator'>) => {
  return createRateLimit({
    ...options,
    keyGenerator: (req: Request) => {
      const targetUrl = req.body?.targetUrl;
      if (targetUrl) {
        try {
          const url = new URL(targetUrl);
          return `target:${url.hostname}`;
        } catch {
          return `target:invalid`;
        }
      }
      return `ip:${req.ip || 'unknown'}`;
    },
  });
};

/**
 * Per-target scan rate limit: 3 scans per target per 10 minutes
 */
export const perTargetScanLimit = createTargetRateLimit({
  windowMs: 10 * 60 * 1000,
  maxRequests: 3,
  message: 'Too many scans for this target, please wait before trying again',
});

/**
 * Cleanup function (call on server shutdown)
 */
export function cleanupRateLimiter(): void {
  globalLimiter.destroy();
}

/**
 * مثال استخدام:
 * 
 * import { scanCreationRateLimit, batchScanRateLimit } from './rate-limiter';
 * 
 * // Apply to specific route
 * app.post('/api/scans', scanCreationRateLimit, async (req, res) => {
 *   // Create scan
 * });
 * 
 * // Apply globally
 * app.use('/api', apiRateLimit);
 * 
 * // Custom rate limit
 * app.post('/api/custom', createRateLimit({
 *   windowMs: 60000,
 *   maxRequests: 10,
 *   message: 'Custom rate limit'
 * }));
 */
