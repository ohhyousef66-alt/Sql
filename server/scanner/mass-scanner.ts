import { storage } from "../storage";
import { VulnerabilityScanner } from "./index";

/**
 * Mass Scanner - Uses existing VulnerabilityScanner
 * Just runs multiple scans in parallel
 */

interface MassScanTarget {
  url: string;
  id: number;
}

interface MassScanResult {
  targetId: number;
  url: string;
  scanId: number;
  status: "scanning" | "completed" | "error";
  vulnerabilitiesFound: number;
  error?: string;
}

export class MassScanner {
  private concurrency: number;
  private threads: number;
  private results: Map<number, MassScanResult> = new Map();
  private queue: MassScanTarget[] = [];
  private activeScans = 0;
  private stopped = false;

  constructor(concurrency: number = 50, threads: number = 10) {
    this.concurrency = concurrency;
    this.threads = threads;
  }

  /**
   * Scan batch of URLs using existing VulnerabilityScanner
   */
  async scanBatch(
    targets: MassScanTarget[],
    onProgress?: (completed: number, total: number, current?: MassScanResult) => void
  ): Promise<MassScanResult[]> {
    this.queue = [...targets];
    this.results.clear();
    this.stopped = false;

    const total = targets.length;
    let completed = 0;

    console.log(`[Mass Scanner] Starting ${total} scans with ${this.concurrency} concurrent, ${this.threads} threads each`);

    const workers: Promise<void>[] = [];

    for (let i = 0; i < this.concurrency; i++) {
      workers.push(
        (async () => {
          while (this.queue.length > 0 && !this.stopped) {
            const target = this.queue.shift();
            if (!target) break;

            this.activeScans++;
            const result = await this.scanSingleTarget(target);
            this.results.set(target.id, result);
            this.activeScans--;
            
            completed++;
            if (onProgress) {
              onProgress(completed, total, result);
            }
          }
        })()
      );
    }

    await Promise.all(workers);
    
    return Array.from(this.results.values());
  }

  /**
   * Scan single target using VulnerabilityScanner + Auto-verify with dump
   */
  private async scanSingleTarget(target: MassScanTarget): Promise<MassScanResult> {
    try {
      console.log(`[Mass Scanner] Scanning ${target.url}`);

      // Create scan in database
      const scan = await storage.createScan({
        targetUrl: target.url,
        scanType: "sqli",
        threads: this.threads,
        startTime: new Date(),
      });

      const result: MassScanResult = {
        targetId: target.id,
        url: target.url,
        scanId: scan.id,
        status: "scanning",
        vulnerabilitiesFound: 0,
      };

      // Run VulnerabilityScanner (FULL QUALITY - same as normal scan)
      const scanner = new VulnerabilityScanner(
        scan.id,
        target.url,
        "sqli",
        this.threads
      );

      scanner.run().catch((err) => {
        console.error(`[Mass Scanner] Scan ${scan.id} error:`, err);
      });

      // Poll with progress updates
      let attempts = 0;
      const maxAttempts = 1800; // 30 minutes - HIGH QUALITY SCAN
      
      while (attempts < maxAttempts) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        
        const updatedScan = await storage.getScan(scan.id);
        if (!updatedScan) break;

        if (updatedScan.status === "completed" || updatedScan.status === "failed") {
          const vulns = await storage.getVulnerabilities(scan.id);
          result.vulnerabilitiesFound = vulns.length;

          if (vulns.length > 0) {
            console.log(`[Mass Scanner] ✅ ${target.url} - ${vulns.length} vulns - Verifying dump...`);
            
            // AUTO-VERIFY with dump
            const { DataDumpingEngine } = await import("./data-dumping-engine");
            try {
              const engine = new DataDumpingEngine(vulns[0].id, vulns[0].url, vulns[0].parameter);
              const dbInfo = await engine.getCurrentDatabaseInfo();
              
              if (dbInfo && dbInfo.database) {
                result.status = "vulnerable"; // SUCCESS!
                console.log(`[Mass Scanner] 🎯 SUCCESS: ${target.url} - DB: ${dbInfo.database}`);
              } else {
                result.status = "completed";
              }
            } catch (e) {
              result.status = "completed"; // Vuln found but dump failed
            }
          } else {
            result.status = "clean";
            console.log(`[Mass Scanner] ❌ ${target.url} - clean`);
          }
          
          break;
        }
        
        attempts++;
      }

      if (attempts >= maxAttempts) {
        result.status = "error";
        result.error = "Timeout";
      }

      return result;

    } catch (error: any) {
      console.error(`[Mass Scanner] Error scanning ${target.url}:`, error);
      return {
        targetId: target.id,
        url: target.url,
        scanId: -1,
        status: "error",
        vulnerabilitiesFound: 0,
        error: error.message,
      };
    }
  }

  stop(): void {
    this.stopped = true;
  }

  getResults(): Map<number, MassScanResult> {
    return this.results;
  }

  getStats() {
    const results = Array.from(this.results.values());
    const vulnerable = results.filter(r => r.vulnerabilitiesFound > 0).length;
    const completed = results.filter(r => r.status === "completed").length;
    const errors = results.filter(r => r.status === "error").length;

    return {
      total: results.length,
      completed,
      vulnerable,
      clean: completed - vulnerable,
      errors,
      scanning: this.activeScans,
      queued: this.queue.length,
    };
  }
}
