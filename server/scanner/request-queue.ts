/**
 * Request Queue Manager - Prevents async deadlocks and manages concurrent requests
 * Part of the comprehensive scanner improvements
 */

interface QueuedRequest {
  id: string;
  execute: () => Promise<any>;
  timeout: number;
  retries: number;
  priority: number;
  timestamp: number;
}

export class RequestQueueManager {
  private queue: QueuedRequest[] = [];
  private executing: Map<string, Promise<any>> = new Map();
  private maxConcurrent: number = 10;
  private failedRequests: Set<string> = new Set();
  private completedRequests: Set<string> = new Set();

  constructor(maxConcurrent: number = 10) {
    this.maxConcurrent = maxConcurrent;
  }

  async enqueue(
    id: string,
    execute: () => Promise<any>,
    timeout: number = 30000,
    priority: number = 0,
    retries: number = 2
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const request: QueuedRequest = {
        id,
        execute: async () => {
          try {
            // Add timeout protection wrapper
            return await Promise.race([
              execute(),
              new Promise<never>((_, rej) => 
                setTimeout(() => rej(new Error(`Request ${id} timeout after ${timeout}ms`)), timeout)
              )
            ]);
          } catch (error) {
            if (retries > 0 && !this.failedRequests.has(id)) {
              // Retry with exponential backoff
              await new Promise(r => setTimeout(r, Math.min(1000, 100 * (3 - retries))));
              this.failedRequests.delete(id);
              return this.enqueue(id, execute, timeout, priority, retries - 1);
            }
            this.failedRequests.add(id);
            throw error;
          }
        },
        timeout,
        retries,
        priority,
        timestamp: Date.now(),
      };

      this.queue.push(request);
      this.queue.sort((a, b) => b.priority - a.priority || a.timestamp - b.timestamp);
      
      this.processQueue().catch(reject);
      
      // Return the promise for this specific request
      const executePromise = Promise.resolve()
        .then(async () => {
          while (!this.executing.has(id) && this.queue.find(r => r.id === id)) {
            await new Promise(r => setTimeout(r, 10));
          }
          const result = await this.executing.get(id);
          this.completedRequests.add(id);
          return result;
        })
        .catch(error => {
          this.completedRequests.add(id);
          throw error;
        });

      resolve(executePromise);
    });
  }

  private async processQueue(): Promise<void> {
    while (this.executing.size < this.maxConcurrent && this.queue.length > 0) {
      const request = this.queue.shift();
      if (!request) break;

      const promise = Promise.resolve()
        .then(() => request.execute())
        .catch(error => {
          console.error(`[RequestQueue] Error executing ${request.id}:`, error.message);
          throw error;
        })
        .finally(() => {
          this.executing.delete(request.id);
          // Continue processing remaining items
          this.processQueue().catch(e => console.error('[RequestQueue] Processing error:', e));
        });

      this.executing.set(request.id, promise);
    }
  }

  getStats() {
    return {
      queueLength: this.queue.length,
      executing: this.executing.size,
      completed: this.completedRequests.size,
      failed: this.failedRequests.size,
    };
  }

  async waitAll(): Promise<void> {
    while (this.queue.length > 0 || this.executing.size > 0) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  clear(): void {
    this.queue = [];
    this.executing.clear();
    this.failedRequests.clear();
    this.completedRequests.clear();
  }
}

export const createRequestQueueManager = (maxConcurrent?: number) => 
  new RequestQueueManager(maxConcurrent);
