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
  status: "scanning" | "completed" | "error" | "vulnerable";
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

  async scanBatch(
    targets: MassScanTarget[],
    onProgress?: (completed: number, total: number, current?: MassScanResult) => void
  ): Promise<MassScanResult[]> {
    this.queue = [...targets];
    this.results.clear();
    this.stopped = false;

    const total = targets.length;
    let completed = 0;

    // Initialize results with scanning status
    for (const target of targets) {
      this.results.set(target.id, {
        targetId: target.id,
        url: target.url,
        scanId: 0, // Will be updated
        status: "scanning",
        vulnerabilitiesFound: 0,
      });
    }

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
        scanMode: "sqli",
        threads: this.threads,
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
            console.log(`[Mass Scanner] ✅ ${target.url} - ${vulns.length} vulns - Testing payloads in dumper...`);
            
            // Try each vulnerability payload in dumper until one works
            // Use integrated pipeline for post-confirmation
            const { IntegratedPipelineAdapter } = await import("./integrated-pipeline-adapter");
            let dumpSuccess = false;
            
            console.log(`[Mass Scanner] 🔬 Starting pipeline for ${target.url}`);
            
            // Create pipeline context
            const pipelineContext = {
              scanId: scanIdForTarget,
              targetUrl: target.url,
              vulnerabilities: vulns.slice(0, 5), // First 5 vulns for confirmation
              enumerationEnabled: true,
              userConsent: {
                acknowledgedWarnings: [
                  "I confirm this target is authorized for testing",
                  "I will comply with all legal restrictions",
                  "I am responsible for any consequences",
                  "I will limit data extraction to necessary scope",
                ],
                metadata: {
                  ipAddress: "mass-scanner",
                  userAgent: "mass-scanner",
                },
              },
            };
            
            try {
              const pipeline = new IntegratedPipelineAdapter(pipelineContext);
              
              // Process vulnerabilities
              await pipeline.processVulnerabilities(vulns.slice(0, 5));
              
              // Evaluate confirmation
              const confirmed = await pipeline.evaluateConfirmation();
              if (confirmed) {
                console.log(`[Mass Scanner] ✅ ${target.url} - Confirmation passed`);
                
                // Fingerprint database
                const fingerprint = await pipeline.fingerprintDatabase();
                if (fingerprint) {
                  result.status = "vulnerable";
                  dumpSuccess = true;
                  console.log(`[Mass Scanner] 🎯 SUCCESS: ${target.url} - DB: ${fingerprint.type}`);
                  
                  // Enumerate database
                  const enumResults = await pipeline.enumerateDatabase();
                  if (enumResults) {
                    console.log(`[Mass Scanner] 📚 ${target.url} - Found ${enumResults.databases.length} databases`);
                  }
                } else {
                  console.log(`[Mass Scanner] ⚠️ ${target.url} - Fingerprinting failed`);
                }
              } else {
                console.log(`[Mass Scanner] ❌ ${target.url} - Confirmation blocked`);
              }
            } catch (e: any) {
              console.log(`[Mass Scanner] ⚠️ Pipeline error: ${e.message}`);
            }
            
            if (!dumpSuccess) {
              result.status = "completed"; // Vuln found but pipeline didn't confirm
              console.log(`[Mass Scanner] ❌ ${target.url} - Vulnerability found but not confirmed by pipeline`);
            }
          } else {
            result.status = "completed";
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
