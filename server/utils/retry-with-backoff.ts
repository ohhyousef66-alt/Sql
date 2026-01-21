/**
 * Retry Logic مع Exponential Backoff
 * - يعيد المحاولة تلقائياً عند الفشل
 * - يزيد وقت الانتظار بشكل أسي
 * - يدعم Jitter لتجنب Thundering Herd
 */

export interface RetryOptions {
  maxRetries?: number;
  baseDelay?: number;
  maxDelay?: number;
  exponentialBase?: number;
  jitter?: boolean;
  onRetry?: (attempt: number, error: Error) => void | Promise<void>;
  shouldRetry?: (error: Error) => boolean;
}

/**
 * Sleep function
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * حساب وقت الانتظار مع Exponential Backoff
 */
function calculateDelay(
  attempt: number,
  baseDelay: number,
  maxDelay: number,
  exponentialBase: number,
  jitter: boolean
): number {
  // Exponential backoff: baseDelay * (exponentialBase ^ attempt)
  let delay = baseDelay * Math.pow(exponentialBase, attempt);
  
  // Cap at maxDelay
  delay = Math.min(delay, maxDelay);
  
  // Add jitter (randomize ±25%)
  if (jitter) {
    const jitterAmount = delay * 0.25;
    delay = delay - jitterAmount + (Math.random() * jitterAmount * 2);
  }
  
  return Math.floor(delay);
}

/**
 * تنفيذ دالة مع Retry Logic و Exponential Backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 30000,
    exponentialBase = 2,
    jitter = true,
    onRetry,
    shouldRetry = () => true,
  } = options;

  let lastError: Error = new Error('Unknown error');
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      // Check if we should retry this error
      if (!shouldRetry(lastError)) {
        throw lastError;
      }
      
      // Last attempt - throw error
      if (attempt === maxRetries) {
        throw lastError;
      }
      
      // Calculate delay
      const delay = calculateDelay(attempt, baseDelay, maxDelay, exponentialBase, jitter);
      
      // Call onRetry callback if provided
      if (onRetry) {
        await onRetry(attempt + 1, lastError);
      }
      
      // Wait before retrying
      await sleep(delay);
    }
  }
  
  throw lastError;
}

/**
 * Retry مع تسجيل تلقائي
 */
export async function retryWithLogging<T>(
  fn: () => Promise<T>,
  operationName: string,
  logger?: { info: (msg: string) => void; warn: (msg: string) => void },
  options: RetryOptions = {}
): Promise<T> {
  return retryWithBackoff(fn, {
    ...options,
    onRetry: async (attempt, error) => {
      if (logger) {
        logger.warn(`${operationName} failed (attempt ${attempt}), retrying... Error: ${error.message}`);
      }
      if (options.onRetry) {
        await options.onRetry(attempt, error);
      }
    },
  });
}

/**
 * Retry فقط على أخطاء الشبكة
 */
export async function retryOnNetworkError<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  return retryWithBackoff(fn, {
    ...options,
    shouldRetry: (error) => {
      // Retry on network errors
      const networkErrors = ['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'ENETUNREACH', 'EAI_AGAIN'];
      const errorCode = (error as any).code;
      const isNetworkError = networkErrors.includes(errorCode);
      
      // Also retry on HTTP 5xx errors
      const isServerError = (error as any).status >= 500 && (error as any).status < 600;
      
      return isNetworkError || isServerError;
    },
  });
}

/**
 * Retry مع Circuit Breaker بسيط
 */
export class CircuitBreaker<T> {
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private state: 'closed' | 'open' | 'half-open' = 'closed';

  constructor(
    private fn: () => Promise<T>,
    private options: {
      failureThreshold?: number;
      successThreshold?: number;
      timeout?: number;
      resetTimeout?: number;
    } = {}
  ) {
    this.options = {
      failureThreshold: 5,
      successThreshold: 2,
      timeout: 30000,
      resetTimeout: 60000,
      ...options,
    };
  }

  async execute(): Promise<T> {
    // Check if circuit should transition from open to half-open
    if (this.state === 'open') {
      const timeSinceLastFailure = Date.now() - this.lastFailureTime;
      if (timeSinceLastFailure >= this.options.resetTimeout!) {
        this.state = 'half-open';
        this.failureCount = 0;
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      // Execute with timeout
      const result = await Promise.race([
        this.fn(),
        new Promise<T>((_, reject) => 
          setTimeout(() => reject(new Error('Circuit breaker timeout')), this.options.timeout)
        ),
      ]);

      // Success - update state
      this.onSuccess();
      return result;
    } catch (error) {
      // Failure - update state
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    
    if (this.state === 'half-open') {
      this.successCount++;
      if (this.successCount >= this.options.successThreshold!) {
        this.state = 'closed';
        this.successCount = 0;
      }
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    this.successCount = 0;
    
    if (this.failureCount >= this.options.failureThreshold!) {
      this.state = 'open';
    }
  }

  getState(): 'closed' | 'open' | 'half-open' {
    return this.state;
  }

  reset(): void {
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }
}

/**
 * مثال استخدام:
 * 
 * // Simple retry
 * const data = await retryWithBackoff(
 *   () => fetchDataFromAPI(),
 *   { maxRetries: 3, baseDelay: 1000 }
 * );
 * 
 * // Network errors only
 * const response = await retryOnNetworkError(
 *   () => makeHttpRequest(),
 *   { maxRetries: 5 }
 * );
 * 
 * // Circuit breaker
 * const breaker = new CircuitBreaker(() => callExternalService());
 * const result = await breaker.execute();
 */
