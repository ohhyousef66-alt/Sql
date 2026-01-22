import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { api } from "@shared/routes";
import { z } from "zod";
import { VulnerabilityScanner } from "./scanner/index";
import { setupAuth, registerAuthRoutes } from "./replit_integrations/auth";
import PDFDocument from "pdfkit";
import { spawn } from "child_process";
import fs from "fs";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  // Scans
  app.get(api.scans.list.path, async (req, res) => {
    const scans = await storage.getScans();
    res.json(scans);
  });

  app.post(api.scans.create.path, async (req, res) => {
    try {
      const input = api.scans.create.input.parse(req.body);
      const scan = await storage.createScan(input);
      
      // Start scanning in background (async) - SQL injection only
      const threads = scan.threads ?? 10;
      const scanner = new VulnerabilityScanner(scan.id, scan.targetUrl, "sqli", threads);
      scanner.run(); // don't await, let it run

      res.status(201).json(scan);
    } catch (err) {
       if (err instanceof z.ZodError) {
          return res.status(400).json({ message: err.errors[0].message });
       }
       res.status(500).json({ message: "Internal Server Error" });
    }
  });

  // FIX #1: Session Persistence - Return full scan state with all metrics
  app.get(api.scans.get.path, async (req, res) => {
    try {
      const scanId = Number(req.params.id);
      const scan = await storage.getScan(scanId);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      
      // Include all necessary fields for session recovery
      res.json({
        ...scan,
        progressMetrics: scan.progressMetrics || {},
        resumable: scan.status === "scanning" || scan.status === "pending",
      });
    } catch (error) {
      console.error("Get scan error:", error);
      res.status(500).json({ message: "Failed to get scan" });
    }
  });

  app.get(api.scans.getVulnerabilities.path, async (req, res) => {
     const vulns = await storage.getVulnerabilities(Number(req.params.id));
     res.json(vulns);
  });

  app.get(api.scans.getLogs.path, async (req, res) => {
      const logs = await storage.getScanLogs(Number(req.params.id));
      res.json(logs);
  });

  app.get(api.scans.getTrafficLogs.path, async (req, res) => {
      const scanId = Number(req.params.id);
      const scan = await storage.getScan(scanId);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      
      const limit = req.query.limit ? Number(req.query.limit) : 1000;
      const logs = await storage.getTrafficLogs(scanId, limit);
      res.json(logs);
  });

  app.post(api.scans.cancel.path, async (req, res) => {
    try {
      const scanId = Number(req.params.id);
      const scan = await storage.getScan(scanId);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      
      if (scan.status === "scanning" || scan.status === "pending" || scan.status === "batch_parent") {
        // If this is a parent scan, cancel all children too
        if (scan.isParent) {
          const children = await storage.getChildScans(scanId);
          for (const child of children) {
            if (child.status === "scanning" || child.status === "pending") {
              await storage.cancelScan(child.id);
              VulnerabilityScanner.cancelScan(child.id);
            }
          }
        }
        
        const updatedScan = await storage.cancelScan(scanId);
        VulnerabilityScanner.cancelScan(scanId);
        res.json(updatedScan);
      } else {
        res.status(400).json({ message: "Scan cannot be cancelled in its current state" });
      }
    } catch (error) {
      res.status(500).json({ message: "Failed to cancel scan" });
    }
  });

  // ============================================
  // UNIFIED BATCH SCANNING - Same Engine, Just Queued
  // ============================================
  app.post(api.scans.batch.path, async (req, res) => {
    try {
      const input = api.scans.batch.input.parse(req.body);
      const { targetUrls, threads } = input;
      
      // Create parent scan for tracking
      const parentScan = await storage.createBatchParentScan(targetUrls, "sqli");
      const childScanIds: number[] = [];
      
      await storage.createScanLog({
        scanId: parentScan.id,
        level: "info",
        message: `🚀 Unified Batch Scan: Queuing ${targetUrls.length} targets through the SAME scanning engine`,
      });
      
      // Queue each URL through the UNIFIED scanner (same quality, no "lite" mode)
      for (const targetUrl of targetUrls) {
        const childScan = await storage.createChildScan(parentScan.id, targetUrl, "sqli");
        childScanIds.push(childScan.id);
        
        await storage.createScanLog({
          scanId: childScan.id,
          level: "info",
          message: `⚙️ [Quality Assurance] Using FULL scanning engine with ALL payloads - same depth as single URL scan`,
        });
        
        // Start child scan with the UNIFIED engine (identical to single scan)
        const scanner = new VulnerabilityScanner(
          childScan.id, 
          childScan.targetUrl, 
          "sqli",
          threads ?? 10
        );
        
        // Mark as scanning and run
        storage.updateScan(childScan.id, { status: "scanning", progress: 1 })
          .then(() => {
            return scanner.run(); // SAME engine as single scan - NO shortcuts
          })
          .catch(async (error) => {
            console.error(`Child scan ${childScan.id} failed:`, error);
            try {
              await storage.updateScan(childScan.id, {
                status: "failed",
                progress: 100,
                endTime: new Date()
              });
            } catch (e) {
              console.error(`Failed to update failed child scan ${childScan.id}:`, e);
            }
          })
          .finally(async () => {
            try {
              await storage.updateParentScanFromChildren(parentScan.id);
            } catch (e) {
              console.error(`Failed to update parent scan ${parentScan.id}:`, e);
            }
          });
      }
      
      res.status(201).json({
        parentScanId: parentScan.id,
        childScanIds,
      });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      console.error("Batch scan error:", err);
      res.status(500).json({ message: "Internal Server Error" });
    }
  });

  app.get(api.scans.getChildren.path, async (req, res) => {
    const parentId = Number(req.params.id);
    const parent = await storage.getScan(parentId);
    if (!parent) return res.status(404).json({ message: "Scan not found" });
    
    const children = await storage.getChildScans(parentId);
    res.json(children);
  });

  app.get(api.scans.getEnumerationResults.path, async (req, res) => {
    try {
      const scanId = Number(req.params.id);
      const scan = await storage.getScan(scanId);
      if (!scan) return res.status(404).json({ message: "Scan not found" });
      
      const results = await storage.getEnumerationResults(scanId);
      res.json(results);
    } catch (error) {
      console.error("Failed to get enumeration results:", error);
      res.status(500).json({ message: "Failed to get enumeration results" });
    }
  });
  
  app.get(api.scans.export.path, async (req, res) => {
    try {
      const scanId = Number(req.params.id);
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ message: "Scan not found" });
      }

      const vulnerabilities = await storage.getVulnerabilities(scanId);
      
      const doc = new PDFDocument({ margin: 50 });
      
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename=scan-report-${scanId}.pdf`);
      
      doc.pipe(res);

      // Title
      doc.fontSize(24).font("Helvetica-Bold").text("Web Vulnerability Scan Report", { align: "center" });
      doc.moveDown();

      // Scan Info
      doc.fontSize(12).font("Helvetica-Bold").text("Scan Details");
      doc.fontSize(10).font("Helvetica")
        .text(`Target URL: ${scan.targetUrl}`)
        .text(`Scan ID: ${scan.id}`)
        .text(`Status: ${scan.status}`)
        .text(`Started: ${scan.startTime ? new Date(scan.startTime).toLocaleString() : "N/A"}`)
        .text(`Completed: ${scan.endTime ? new Date(scan.endTime).toLocaleString() : "N/A"}`);
      doc.moveDown();

      // Summary
      const summary = scan.summary as Record<string, number> | null;
      doc.fontSize(12).font("Helvetica-Bold").text("Executive Summary");
      doc.fontSize(10).font("Helvetica");
      if (summary) {
        doc.text(`Critical: ${summary.critical || 0}`)
           .text(`High: ${summary.high || 0}`)
           .text(`Medium: ${summary.medium || 0}`)
           .text(`Low: ${summary.low || 0}`)
           .text(`Informational: ${summary.info || 0}`);
      } else {
        doc.text("No summary data available.");
      }
      doc.moveDown();

      // Vulnerabilities
      doc.fontSize(12).font("Helvetica-Bold").text("Vulnerability Findings");
      doc.moveDown(0.5);

      if (vulnerabilities.length === 0) {
        doc.fontSize(10).font("Helvetica").text("No vulnerabilities detected.");
      } else {
        vulnerabilities.forEach((vuln, index) => {
          if (doc.y > 700) {
            doc.addPage();
          }
          
          doc.fontSize(11).font("Helvetica-Bold")
             .text(`${index + 1}. ${vuln.type} [${vuln.severity.toUpperCase()}]`);
          
          doc.fontSize(9).font("Helvetica");
          if (vuln.path) doc.text(`Path: ${vuln.path}`);
          if (vuln.parameter) doc.text(`Parameter: ${vuln.parameter}`);
          if (vuln.payload) doc.text(`Payload: ${vuln.payload.substring(0, 100)}${vuln.payload.length > 100 ? "..." : ""}`);
          if (vuln.description) doc.text(`Description: ${vuln.description}`);
          if (vuln.remediation) {
            doc.font("Helvetica-Bold").text("Remediation: ", { continued: true })
               .font("Helvetica").text(vuln.remediation);
          }
          doc.moveDown(0.5);
        });
      }

      // Footer
      doc.moveDown(2);
      doc.fontSize(8).font("Helvetica").fillColor("gray")
         .text(`Generated on ${new Date().toLocaleString()} by Web Vulnerability Scanner`, { align: "center" });

      doc.end();
    } catch (error: any) {
      console.error("PDF export error:", error);
      res.status(500).json({ message: "Failed to generate report" });
    }
  });

  // ============================================
  // Python Scanner Integration API
  // ============================================
  
  app.post("/api/python-scan", async (req, res) => {
    try {
      const { targetUrl, threads = 10, types } = req.body;
      
      if (!targetUrl) {
        return res.status(400).json({ message: "Target URL is required" });
      }
      
      // Create a scan record
      const scan = await storage.createScan({
        targetUrl,
        scanMode: "sqli",
        threads,
      });
      await storage.updateScan(scan.id, { status: "scanning" });
      
      // Run Python scanner in background
      const args = [
        "scanner_cli/main.py",
        "-u", targetUrl,
        "-t", String(threads),
        "-o", `scanner_cli/results_${scan.id}`,
        "--json-only",
      ];
      
      if (types) {
        args.push("--types", types);
      }
      
      const pythonProcess = spawn("python3", args, {
        cwd: process.cwd(),
        stdio: ["ignore", "pipe", "pipe"],
      });
      
      let stdout = "";
      let stderr = "";
      
      pythonProcess.stdout.on("data", (data: Buffer) => {
        stdout += data.toString();
      });
      
      pythonProcess.stderr.on("data", (data: Buffer) => {
        stderr += data.toString();
      });
      
      pythonProcess.on("close", async (code: number) => {
        try {
          if (code === 0) {
            // Parse results and update scan
            const resultsPath = `scanner_cli/results_${scan.id}.json`;
            
            if (fs.existsSync(resultsPath)) {
              const results = JSON.parse(fs.readFileSync(resultsPath, "utf8"));
              
              // Save vulnerabilities to database
              for (const vuln of results.vulnerabilities || []) {
                const payloadType = vuln.payload_type || "unknown";
                await storage.createVulnerability({
                  scanId: scan.id,
                  type: payloadType,
                  severity: vuln.confidence >= 90 ? "critical" : vuln.confidence >= 70 ? "high" : "medium",
                  url: vuln.url,
                  path: vuln.url,
                  parameter: vuln.parameter,
                  payload: vuln.payload,
                  description: `SQL Injection (${payloadType.replace(/_/g, ' ')}) - ${vuln.database_type || 'unknown'} database`,
                  evidence: vuln.evidence,
                  confidence: vuln.confidence,
                  remediation: "Use parameterized queries or prepared statements",
                });
              }
              
              await storage.updateScan(scan.id, {
                status: "completed",
                progress: 100,
                endTime: new Date(),
                summary: {
                  critical: results.vulnerabilities?.filter((v: any) => v.confidence >= 90).length || 0,
                  high: results.vulnerabilities?.filter((v: any) => v.confidence >= 70 && v.confidence < 90).length || 0,
                  medium: results.vulnerabilities?.filter((v: any) => v.confidence < 70).length || 0,
                  low: 0,
                  info: 0,
                  confirmed: results.vulnerabilities?.length || 0,
                  potential: 0,
                },
                completionReason: `Python scanner completed: ${results.vulnerabilities?.length || 0} vulnerabilities found`,
              });
            } else {
              await storage.updateScan(scan.id, {
                status: "completed",
                progress: 100,
                endTime: new Date(),
                summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, confirmed: 0, potential: 0 },
                completionReason: "Python scanner completed: No vulnerabilities found",
              });
            }
          } else {
            await storage.updateScan(scan.id, {
              status: "failed",
              progress: 100,
              endTime: new Date(),
              completionReason: `Python scanner failed: ${stderr || "Unknown error"}`,
            });
          }
        } catch (updateError) {
          console.error("Failed to update scan after Python scanner:", updateError);
        }
      });
      
      res.status(201).json({ scanId: scan.id, message: "Python scan started" });
    } catch (error: any) {
      console.error("Python scan error:", error);
      res.status(500).json({ message: "Failed to start Python scan" });
    }
  });

  // ============================================
  // Batch Scan Status Monitor
  // ============================================
  
  app.post("/api/scans/:id/refresh-parent", async (req, res) => {
    try {
      const parentId = Number(req.params.id);
      const parent = await storage.getScan(parentId);
      
      if (!parent) {
        return res.status(404).json({ message: "Scan not found" });
      }
      
      if (!parent.isParent) {
        return res.status(400).json({ message: "Not a parent scan" });
      }
      
      const updated = await storage.updateParentScanFromChildren(parentId);
      res.json(updated);
    } catch (error: any) {
      console.error("Refresh parent scan error:", error);
      res.status(500).json({ message: "Failed to refresh parent scan" });
    }
  });

  // Retry failed child scans
  app.post("/api/scans/:id/retry-failed", async (req, res) => {
    try {
      const parentId = Number(req.params.id);
      const parent = await storage.getScan(parentId);
      
      if (!parent || !parent.isParent) {
        return res.status(404).json({ message: "Parent scan not found" });
      }
      
      const children = await storage.getChildScans(parentId);
      const failedChildren = children.filter(c => c.status === "failed");
      
      const retriedIds: number[] = [];
      
      for (const child of failedChildren) {
        // Reset child scan status
        await storage.updateScan(child.id, {
          status: "scanning",
          progress: 1,
          endTime: undefined,
          completionReason: undefined,
        });
        
        // Start new scanner
        const scanner = new VulnerabilityScanner(
          child.id,
          child.targetUrl,
          "sqli",
          child.threads ?? 10
        );
        
        scanner.run().catch(async (error) => {
          console.error(`Retry scan ${child.id} failed:`, error);
          await storage.updateScan(child.id, {
            status: "failed",
            progress: 100,
            endTime: new Date(),
            completionReason: `Retry failed: ${error.message}`,
          });
        }).finally(async () => {
          await storage.updateParentScanFromChildren(parentId);
        });
        
        retriedIds.push(child.id);
      }
      
      res.json({
        message: `Retried ${retriedIds.length} failed scans`,
        retriedIds,
      });
    } catch (error: any) {
      console.error("Retry failed scans error:", error);
      res.status(500).json({ message: "Failed to retry scans" });
    }
  });

  // Delete old scans
  app.delete("/api/scans/cleanup", async (req, res) => {
    try {
      const daysOld = Number(req.query.days) || 7;
      const threshold = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
      
      const allScans = await storage.getScans();
      const oldScans = allScans.filter(s => 
        s.startTime && new Date(s.startTime) < threshold &&
        (s.status === "completed" || s.status === "failed" || s.status === "cancelled")
      );
      
      let deletedCount = 0;
      for (const scan of oldScans) {
        await storage.deleteScan(scan.id);
        deletedCount++;
      }
      
      res.json({ message: `Deleted ${deletedCount} old scans`, deletedCount });
    } catch (error: any) {
      console.error("Cleanup scans error:", error);
      res.status(500).json({ message: "Failed to cleanup scans" });
    }
  });

  // ============================================================
  // MASS SCANNING - Uses VulnerabilityScanner for each target
  // ============================================================

  let activeMassScanner: any = null;
  let activeMassScanId: number | null = null; // Track current mass scan ID

  // Start mass scan
  app.post("/api/mass-scan/start", async (req, res) => {
    res.status(501).json({ message: "Mass scanning feature is not implemented" });
  });

  // Get mass scan progress
  app.get("/api/mass-scan/progress", async (req, res) => {
    res.status(501).json({ message: "Mass scanning feature is not implemented" });
  });

  // Get vulnerable targets from mass scan
  app.get("/api/mass-scan/vulnerable", async (req, res) => {
    res.status(501).json({ message: "Mass scanning feature is not implemented" });
  });

  // ============================================================
  // DATA DUMPING ENDPOINTS - SQLi Dumper Feature
  // ============================================================

  // Start database dump for a vulnerability
  app.post("/api/vulnerabilities/:id/dump/start", async (req, res) => {
    try {
      const vulnId = Number(req.params.id);
      const vuln = await storage.getVulnerability(vulnId);
      
      if (!vuln) {
        return res.status(404).json({ message: "Vulnerability not found" });
      }
      
      if (!vuln.parameter) {
        return res.status(400).json({ message: "No vulnerable parameter found" });
      }
      
      // Create dumping job
      const job = await storage.createDumpingJob({
        vulnerabilityId: vulnId,
        scanId: vuln.scanId,
        targetUrl: vuln.url,
        targetType: "database",
        targetId: 0,
        status: "pending",
        progress: 0,
      });
      
      // Start dumping in background
      const { DataDumpingEngine } = await import("./scanner/data-dumping-engine");
      const abortController = new AbortController();
      
      const engine = new DataDumpingEngine({
        targetUrl: vuln.url,
        vulnerableParameter: vuln.parameter,
        dbType: detectDbType(vuln.evidence || ""),
        technique: detectTechnique(vuln.type),
        injectionPoint: vuln.payload || "1",
        signal: abortController.signal,
        onProgress: async (progress, message) => {
          await storage.updateDumpingJob(job.id, { progress });
        },
        onLog: async (level, message) => {
          console.log(`[Dumping Job ${job.id}] ${level}: ${message}`);
        },
      });
      
      // Run dump
      engine.dumpAll().then(async (result) => {
        if (result.success) {
          // Save databases
          for (const db of result.databases) {
            await storage.createExtractedDatabase({
              vulnerabilityId: vulnId,
              scanId: vuln.scanId,
              targetUrl: vuln.url,
              databaseName: db.name,
              dbType: detectDbType(vuln.evidence || ""),
              extractionMethod: detectTechnique(vuln.type),
              status: "discovered",
              metadata: {
                version: db.version,
                user: db.user,
                currentDb: db.currentDb,
              },
            });
          }
          
          await storage.updateDumpingJob(job.id, {
            status: "completed",
            progress: 100,
            completedAt: new Date(),
          });
        } else {
          await storage.updateDumpingJob(job.id, {
            status: "failed",
            progress: 100,
            errorMessage: result.error,
            completedAt: new Date(),
          });
        }
      });
      
      res.json({ job, message: "Dumping job started" });
    } catch (error: any) {
      console.error("Start dump error:", error);
      res.status(500).json({ message: "Failed to start dump" });
    }
  });

  // Get extracted databases for a vulnerability
  app.get("/api/vulnerabilities/:id/databases", async (req, res) => {
    try {
      const vulnId = Number(req.params.id);
      const databases = await storage.getExtractedDatabases(vulnId);
      res.json(databases);
    } catch (error: any) {
      console.error("Get databases error:", error);
      res.status(500).json({ message: "Failed to get databases" });
    }
  });

  // Dump tables from a database - LINKED TO UNION/ERROR EXTRACTION ENGINES
  app.post("/api/databases/:id/dump-tables", async (req, res) => {
    try {
      const dbId = Number(req.params.id);
      const database = await storage.getExtractedDatabase(dbId);
      
      if (!database) {
        return res.status(404).json({ message: "Database not found" });
      }
      
      const vuln = await storage.getVulnerability(database.vulnerabilityId);
      if (!vuln || !vuln.parameter) {
        return res.status(400).json({ message: "Invalid vulnerability" });
      }
      
      // Create dumping job with status tracking
      const job = await storage.createDumpingJob({
        vulnerabilityId: database.vulnerabilityId,
        scanId: database.scanId,
        targetUrl: database.targetUrl,
        targetType: "table",
        targetId: dbId,
        status: "running",
        progress: 0,
      });
      
      await storage.updateDumpingJob(job.id, { startedAt: new Date() });
      
      // Start table enumeration using DataDumpingEngine
      const { DataDumpingEngine } = await import("./scanner/data-dumping-engine");
      const abortController = new AbortController();
      
      // Create engine with proper configuration
      const engine = new DataDumpingEngine({
        targetUrl: database.targetUrl,
        vulnerableParameter: vuln.parameter,
        dbType: database.dbType as any,
        technique: database.extractionMethod as any, // error-based or union-based
        injectionPoint: vuln.payload || "1",
        signal: abortController.signal,
        onProgress: async (progress, message) => {
          await storage.updateDumpingJob(job.id, { progress });
          console.log(`[Dump Tables Job ${job.id}] ${progress}% - ${message}`);
        },
        onLog: async (level, message) => {
          console.log(`[Dump Tables Job ${job.id}] [${level}] ${message}`);
        },
      });
      
      // Run enumeration in background
      engine.enumerateTables(database.databaseName)
        .then(async (tables) => {
          try {
            // Validate extracted tables
            if (!tables || tables.length === 0) {
              await storage.updateDumpingJob(job.id, {
                status: "completed",
                progress: 100,
                itemsTotal: 0,
                itemsExtracted: 0,
                completedAt: new Date(),
              });
              console.log(`[Dump Tables Job ${job.id}] No tables found`);
              return;
            }

            // Save tables to database
            let savedCount = 0;
            for (const table of tables) {
              try {
                await storage.createExtractedTable({
                  databaseId: dbId,
                  tableName: table.name,
                  rowCount: 0,
                  columnCount: 0,
                  status: "discovered",
                });
                savedCount++;
              } catch (err: any) {
                console.error(`[Dump Tables] Error saving table ${table.name}:`, err.message);
              }
            }
            
            // Update database record
            await storage.updateExtractedDatabase(dbId, {
              tableCount: savedCount,
              status: "discovered", // Mark as discovered, not completed
            });
            
            // Complete job
            await storage.updateDumpingJob(job.id, {
              status: "completed",
              progress: 100,
              itemsTotal: tables.length,
              itemsExtracted: savedCount,
              completedAt: new Date(),
            });
            
            console.log(`[Dump Tables Job ${job.id}] Completed: ${savedCount}/${tables.length} tables saved`);
          } catch (err: any) {
            console.error(`[Dump Tables] Error processing results:`, err);
            await storage.updateDumpingJob(job.id, {
              status: "failed",
              errorMessage: err.message,
              completedAt: new Date(),
            });
          }
        })
        .catch(async (error: any) => {
          console.error(`[Dump Tables Job ${job.id}] Enumeration error:`, error);
          await storage.updateDumpingJob(job.id, {
            status: "failed",
            errorMessage: error.message || "Enumeration failed",
            completedAt: new Date(),
          });
        });
      
      res.json({ 
        job, 
        message: "Table enumeration started using configured extraction engine",
        extractionTechnique: database.extractionMethod,
      });
    } catch (error: any) {
      console.error("Dump tables error:", error);
      res.status(500).json({ message: `Failed to dump tables: ${error.message}` });
    }
  });

  // Get tables for a database
  app.get("/api/databases/:id/tables", async (req, res) => {
    try {
      const dbId = Number(req.params.id);
      const tables = await storage.getExtractedTables(dbId);
      res.json(tables);
    } catch (error: any) {
      console.error("Get tables error:", error);
      res.status(500).json({ message: "Failed to get tables" });
    }
  });

  // Dump columns from a table
  app.post("/api/tables/:id/dump-columns", async (req, res) => {
    try {
      const tableId = Number(req.params.id);
      const table = await storage.getExtractedTable(tableId);
      
      if (!table) {
        return res.status(404).json({ message: "Table not found" });
      }
      
      const database = await storage.getExtractedDatabase(table.databaseId);
      if (!database) {
        return res.status(404).json({ message: "Database not found" });
      }
      
      const vuln = await storage.getVulnerability(database.vulnerabilityId);
      if (!vuln || !vuln.parameter) {
        return res.status(400).json({ message: "Invalid vulnerability" });
      }
      
      // Create dumping job
      const job = await storage.createDumpingJob({
        vulnerabilityId: database.vulnerabilityId,
        scanId: database.scanId,
        targetUrl: database.targetUrl,
        targetType: "column",
        targetId: tableId,
        status: "running",
        progress: 0,
      });
      
      // Start column enumeration
      const { DataDumpingEngine } = await import("./scanner/data-dumping-engine");
      const abortController = new AbortController();
      
      const engine = new DataDumpingEngine({
        targetUrl: database.targetUrl,
        vulnerableParameter: vuln.parameter,
        dbType: database.dbType as any,
        technique: database.extractionMethod as any,
        injectionPoint: vuln.payload || "1",
        signal: abortController.signal,
        onProgress: async (progress, message) => {
          await storage.updateDumpingJob(job.id, { progress });
        },
      });
      
      engine.enumerateColumns(database.databaseName, table.tableName).then(async (columns) => {
        // Save columns
        for (const col of columns) {
          await storage.createExtractedColumn({
            tableId,
            columnName: col.name,
            dataType: col.type,
            isNullable: col.isNullable,
            columnKey: col.key,
            columnDefault: col.default,
            extra: col.extra,
          });
        }
        
        await storage.updateExtractedTable(tableId, {
          columnCount: columns.length,
          status: "completed",
        });
        
        await storage.updateDumpingJob(job.id, {
          status: "completed",
          progress: 100,
          itemsTotal: columns.length,
          itemsExtracted: columns.length,
          completedAt: new Date(),
        });
      });
      
      res.json({ job, message: "Column dumping started" });
    } catch (error: any) {
      console.error("Dump columns error:", error);
      res.status(500).json({ message: "Failed to dump columns" });
    }
  });

  // Get columns for a table
  app.get("/api/tables/:id/columns", async (req, res) => {
    try {
      const tableId = Number(req.params.id);
      const columns = await storage.getExtractedColumns(tableId);
      res.json(columns);
    } catch (error: any) {
      console.error("Get columns error:", error);
      res.status(500).json({ message: "Failed to get columns" });
    }
  });

  // Dump data from a table - USES ERROR/UNION EXTRACTION WITH REGEX PARSING
  app.post("/api/tables/:id/dump-data", async (req, res) => {
    try {
      const tableId = Number(req.params.id);
      const limit = req.body.limit || 100;
      
      const table = await storage.getExtractedTable(tableId);
      if (!table) {
        return res.status(404).json({ message: "Table not found" });
      }
      
      const database = await storage.getExtractedDatabase(table.databaseId);
      if (!database) {
        return res.status(404).json({ message: "Database not found" });
      }
      
      const vuln = await storage.getVulnerability(database.vulnerabilityId);
      if (!vuln || !vuln.parameter) {
        return res.status(400).json({ message: "Invalid vulnerability" });
      }
      
      const columns = await storage.getExtractedColumns(tableId);
      const columnNames = columns.map(c => c.columnName);
      
      if (columnNames.length === 0) {
        return res.status(400).json({ message: "No columns found. Please dump columns first." });
      }
      
      // Create dumping job with Railway DATABASE_URL persistence
      const job = await storage.createDumpingJob({
        vulnerabilityId: database.vulnerabilityId,
        scanId: database.scanId,
        targetUrl: database.targetUrl,
        targetType: "table",
        targetId: tableId,
        status: "running",
        progress: 0,
        itemsTotal: limit,
      });
      
      await storage.updateDumpingJob(job.id, { startedAt: new Date() });
      
      // Start data extraction using Union/Error engines
      const { DataDumpingEngine } = await import("./scanner/data-dumping-engine");
      const abortController = new AbortController();
      
      // Engine configuration with proper extraction technique
      const engine = new DataDumpingEngine({
        targetUrl: database.targetUrl,
        vulnerableParameter: vuln.parameter,
        dbType: database.dbType as any,
        technique: database.extractionMethod as any, // error-based or union-based
        injectionPoint: vuln.payload || "1",
        signal: abortController.signal,
        onProgress: async (progress, message) => {
          await storage.updateDumpingJob(job.id, { progress });
          console.log(`[Dump Data Job ${job.id}] ${progress}% - ${message}`);
        },
        onLog: async (level, message) => {
          console.log(`[Dump Data Job ${job.id}] [${level}] ${message}`);
        },
      });
      
      // Extract data in background with DATABASE_URL persistence
      engine.extractTableData(database.databaseName, table.tableName, columnNames, limit)
        .then(async (rows) => {
          try {
            if (!rows || rows.length === 0) {
              await storage.updateDumpingJob(job.id, {
                status: "completed",
                progress: 100,
                itemsExtracted: 0,
                completedAt: new Date(),
              });
              console.log(`[Dump Data Job ${job.id}] No data extracted`);
              return;
            }

            // Save extracted rows to DATABASE_URL (via storage layer)
            let savedCount = 0;
            for (let i = 0; i < rows.length; i++) {
              try {
                await storage.createExtractedData({
                  tableId,
                  rowIndex: i,
                  rowData: rows[i],
                });
                savedCount++;
              } catch (err: any) {
                console.error(`[Dump Data] Error saving row ${i}:`, err.message);
              }
              
              // Update progress every 10 rows
              if ((i + 1) % 10 === 0) {
                await storage.updateDumpingJob(job.id, {
                  progress: Math.round(((i + 1) / rows.length) * 100),
                  itemsExtracted: savedCount,
                });
              }
            }
            
            // Update table metadata
            await storage.updateExtractedTable(tableId, {
              rowCount: savedCount,
              status: "completed",
            });
            
            // Complete job
            await storage.updateDumpingJob(job.id, {
              status: "completed",
              progress: 100,
              itemsExtracted: savedCount,
              completedAt: new Date(),
            });
            
            console.log(`[Dump Data Job ${job.id}] Completed: ${savedCount} rows saved to DATABASE_URL`);
          } catch (err: any) {
            console.error(`[Dump Data] Error processing/persisting results:`, err);
            await storage.updateDumpingJob(job.id, {
              status: "failed",
              errorMessage: `Data persistence error: ${err.message}`,
              completedAt: new Date(),
            });
          }
        })
        .catch(async (error: any) => {
          console.error(`[Dump Data Job ${job.id}] Extraction error:`, error);
          await storage.updateDumpingJob(job.id, {
            status: "failed",
            errorMessage: error.message || "Data extraction failed",
            completedAt: new Date(),
          });
        });
      
      res.json({ 
        job, 
        message: `Data extraction started for ${table.tableName} with ${database.extractionMethod} technique`,
        technique: database.extractionMethod,
        columns: columnNames.length,
        targetRows: limit,
      });
    } catch (error: any) {
      console.error("Dump data error:", error);
      res.status(500).json({ message: `Failed to dump data: ${error.message}` });
    }
  });

  // Get data from a table
  app.get("/api/tables/:id/data", async (req, res) => {
    try {
      const tableId = Number(req.params.id);
      const limit = req.query.limit ? Number(req.query.limit) : 100;
      const offset = req.query.offset ? Number(req.query.offset) : 0;
      
      const data = await storage.getExtractedData(tableId, limit, offset);
      const totalCount = await storage.getExtractedDataCount(tableId);
      
      res.json({ data, total: totalCount, limit, offset });
    } catch (error: any) {
      console.error("Get data error:", error);
      res.status(500).json({ message: "Failed to get data" });
    }
  });

  // Get dumping jobs for a vulnerability
  app.get("/api/vulnerabilities/:id/jobs", async (req, res) => {
    try {
      const vulnId = Number(req.params.id);
      const jobs = await storage.getDumpingJobs(vulnId);
      res.json(jobs);
    } catch (error: any) {
      console.error("Get jobs error:", error);
      res.status(500).json({ message: "Failed to get jobs" });
    }
  });

  // Cancel a dumping job
  app.post("/api/jobs/:id/cancel", async (req, res) => {
    try {
      const jobId = Number(req.params.id);
      const job = await storage.getDumpingJob(jobId);
      
      if (!job) {
        return res.status(404).json({ message: "Job not found" });
      }
      
      await storage.updateDumpingJob(jobId, {
        status: "failed",
        errorMessage: "Cancelled by user",
        completedAt: new Date(),
      });
      
      res.json({ message: "Job cancelled" });
    } catch (error: any) {
      console.error("Cancel job error:", error);
      res.status(500).json({ message: "Failed to cancel job" });
    }
  });

  // ========================================
  // DUMP PAGE ROUTES
  // ========================================

  /**
   * GET /api/dump/databases
   * Get all extracted databases (optionally filtered by scanId)
   */
  app.get("/api/dump/databases", async (req, res) => {
    try {
      const { scanId } = req.query;
      
      const databases = scanId 
        ? await storage.getExtractedDatabases(parseInt(scanId as string))
        : await storage.getExtractedDatabases();

      // Get tables for each database
      const result = await Promise.all(
        databases.map(async (db) => {
          const tables = await storage.getExtractedTables(db.id);
          
          // Get column count and row count for each table
          const tablesWithInfo = await Promise.all(
            tables.map(async (table) => {
              const columns = await storage.getExtractedColumns(table.id);
              
              // Estimate row count (get max from any column's data length)
              let rowCount = 0;
              for (const col of columns) {
                const data = await storage.getExtractedData(table.id);
                rowCount = Math.max(rowCount, data.length);
              }
              
              return {
                id: table.id,
                name: table.tableName,
                columnCount: columns.length,
                rowCount,
                columns: [], // Empty initially, loaded on demand
              };
            })
          );

          return {
            id: db.id,
            vulnerabilityId: db.vulnerabilityId,
            name: db.databaseName,
            tables: tablesWithInfo,
          };
        })
      );

      res.json(result);
    } catch (error) {
      console.error("Error getting databases:", error);
      res.status(500).json({ error: "Failed to get databases" });
    }
  });

  /**
   * GET /api/dump/databases/:dbId/tables/:tableName/data
   * Get all data for a specific table
   */
  app.get("/api/dump/databases/:dbId/tables/:tableName/data", async (req, res) => {
    try {
      const { dbId, tableName } = req.params;
      
      // Get table
      const tables = await storage.getExtractedTables(parseInt(dbId));
      const table = tables.find(t => t.tableName === tableName);
      
      if (!table) {
        return res.status(404).json({ error: "Table not found" });
      }

      // Get all columns with their data
      const columns = await storage.getExtractedColumns(table.id);
      
      const columnsWithData = await Promise.all(
        columns.map(async (col) => {
          const data = await storage.getExtractedData(table.id);
          return {
            id: col.id,
            name: col.columnName,
            type: col.dataType,
            data: data.map(d => d.rowData),
          };
        })
      );

      res.json({ columns: columnsWithData });
    } catch (error) {
      console.error("Error getting table data:", error);
      res.status(500).json({ error: "Failed to get table data" });
    }
  });

  return httpServer;
}

// Helper functions for dumping
function detectDbType(evidence: string): "mysql" | "postgresql" | "mssql" | "oracle" | "sqlite" {
  const e = evidence.toLowerCase();
  if (e.includes("mysql") || e.includes("mariadb")) return "mysql";
  if (e.includes("postgresql") || e.includes("postgres")) return "postgresql";
  if (e.includes("mssql") || e.includes("microsoft sql")) return "mssql";
  if (e.includes("oracle")) return "oracle";
  if (e.includes("sqlite")) return "sqlite";
  return "mysql"; // default
}

function detectTechnique(vulnType: string): "error-based" | "union-based" | "boolean-based" | "time-based" {
  const t = vulnType.toLowerCase();
  if (t.includes("error")) return "error-based";
  if (t.includes("union")) return "union-based";
  if (t.includes("boolean")) return "boolean-based";
  if (t.includes("time")) return "time-based";
  return "error-based"; // default
}
