import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { api } from "@shared/routes";
import { z } from "zod";
import { VulnerabilityScanner } from "./scanner/index";
import { StageExecutor } from "./scanner/stage-executor";
import { setupAuth, registerAuthRoutes } from "./replit_integrations/auth";
import PDFDocument from "pdfkit";
import { spawn } from "child_process";
import fs from "fs";

const activeStageExecutors = new Map<number, StageExecutor>();

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

  app.get(api.scans.get.path, async (req, res) => {
    const scan = await storage.getScan(Number(req.params.id));
    if (!scan) return res.status(404).json({ message: "Scan not found" });
    res.json(scan);
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

  app.post(api.scans.batch.path, async (req, res) => {
    try {
      const input = api.scans.batch.input.parse(req.body);
      const { targetUrls, threads } = input;
      
      const parentScan = await storage.createBatchParentScan(targetUrls, "sqli");
      const childScanIds: number[] = [];
      
      for (const targetUrl of targetUrls) {
        const childScan = await storage.createChildScan(parentScan.id, targetUrl, "sqli");
        childScanIds.push(childScan.id);
        
        // Start child scan - run() already registers in activeScans internally
        const scanner = new VulnerabilityScanner(
          childScan.id, 
          childScan.targetUrl, 
          "sqli",
          threads ?? 10
        );
        
        // Immediately mark child as scanning before run() starts
        storage.updateScan(childScan.id, { status: "scanning", progress: 1 })
          .then(() => {
            // Run scanner with proper error handling
            return scanner.run();
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
  
  // ============================================
  // Mass-Scan Management API Routes
  // ============================================

  // Helper: Validate URL format
  function isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url.trim());
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  // Upload file with URL list
  app.post(api.massScan.uploadFile.path, async (req, res) => {
    try {
      const input = api.massScan.uploadFile.input.parse(req.body);
      const { filename, content } = input;
      
      // Parse URLs from content (supports txt and csv)
      const lines = content.split(/[\r\n]+/).filter(line => line.trim());
      const validUrls: string[] = [];
      const errors: string[] = [];
      
      for (const line of lines) {
        const url = line.trim().split(',')[0].trim(); // First column for CSV
        if (!url || url.startsWith('#')) continue; // Skip empty and comments
        
        if (isValidUrl(url)) {
          validUrls.push(url);
        } else {
          errors.push(`Invalid URL: ${url.substring(0, 50)}${url.length > 50 ? '...' : ''}`);
        }
      }
      
      if (validUrls.length === 0) {
        return res.status(400).json({ message: "No valid URLs found in file" });
      }
      
      // Create file record
      const file = await storage.createUploadedFile({
        filename,
        totalUrls: validUrls.length + errors.length,
        validUrls: validUrls.length,
        invalidUrls: errors.length,
        currentStage: 0,
        status: "pending",
      });
      
      // Create staged targets for all valid URLs (bulk insert)
      const stagedTargetData = validUrls.map(url => ({
        fileId: file.id,
        url,
        currentStage: 0,
        status: "pending" as const,
        isAnomaly: false,
      }));
      
      await storage.createStagedTargets(stagedTargetData);
      
      res.status(201).json({
        file,
        validUrls: validUrls.length,
        invalidUrls: errors.length,
        errors: errors.slice(0, 10), // Return first 10 errors
      });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      console.error("File upload error:", err);
      res.status(500).json({ message: "Failed to upload file" });
    }
  });

  // Get all uploaded files
  app.get(api.massScan.getFiles.path, async (req, res) => {
    const files = await storage.getUploadedFiles();
    res.json(files);
  });

  // Get single file with targets and stage runs
  app.get(api.massScan.getFile.path, async (req, res) => {
    const fileId = Number(req.params.id);
    const file = await storage.getUploadedFile(fileId);
    if (!file) return res.status(404).json({ message: "File not found" });
    
    const targets = await storage.getStagedTargetsByFile(fileId);
    const runs = await storage.getStageRunsByFile(fileId);
    res.json({ file, targets, stageRuns: runs });
  });

  // Delete uploaded file and its targets
  app.delete(api.massScan.deleteFile.path, async (req, res) => {
    const fileId = Number(req.params.id);
    const file = await storage.getUploadedFile(fileId);
    if (!file) return res.status(404).json({ message: "File not found" });
    
    await storage.deleteUploadedFile(fileId);
    res.json({ success: true });
  });

  // Get stage runs for a file
  app.get(api.massScan.getStageRuns.path, async (req, res) => {
    const fileId = Number(req.params.id);
    const file = await storage.getUploadedFile(fileId);
    if (!file) return res.status(404).json({ message: "File not found" });
    
    const runs = await storage.getStageRunsByFile(fileId);
    res.json(runs);
  });

  // Get all flagged targets (anomalies)
  app.get(api.massScan.getFlaggedTargets.path, async (req, res) => {
    const fileId = req.query.fileId ? Number(req.query.fileId) : undefined;
    const flaggedTargets = await storage.getFlaggedTargets(fileId);
    res.json(flaggedTargets);
  });

  // Export targets as text file
  app.get(api.massScan.exportTargets.path, async (req, res) => {
    try {
      const fileId = Number(req.params.id);
      const file = await storage.getUploadedFile(fileId);
      if (!file) return res.status(404).json({ message: "File not found" });
      
      const stage = req.query.stage ? Number(req.query.stage) : undefined;
      const onlyFlagged = req.query.flagged === 'true';
      
      let targets;
      if (onlyFlagged) {
        targets = await storage.getFlaggedTargets(fileId);
      } else if (stage !== undefined) {
        targets = await storage.getStagedTargetsByFileAndStage(fileId, stage);
      } else {
        targets = await storage.getStagedTargetsByFile(fileId);
      }
      
      const content = targets.map(t => t.url).join('\n');
      
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename=${file.filename}-export.txt`);
      res.send(content);
    } catch (err) {
      console.error("Export error:", err);
      res.status(500).json({ message: "Failed to export targets" });
    }
  });

  // Promote targets to next stage
  app.post(api.massScan.promoteTargets.path, async (req, res) => {
    try {
      const fileId = Number(req.params.id);
      const file = await storage.getUploadedFile(fileId);
      if (!file) return res.status(404).json({ message: "File not found" });
      
      const input = api.massScan.promoteTargets.input.parse(req.body);
      const { targetIds, toStage } = input;
      
      let promotedCount = 0;
      for (const targetId of targetIds) {
        await storage.updateStagedTarget(targetId, { 
          currentStage: toStage - 1, // Ready for next stage
          status: "pending",
        });
        promotedCount++;
      }
      
      res.json({ promoted: promotedCount });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      res.status(500).json({ message: "Failed to promote targets" });
    }
  });

  // Run stage with StageExecutor
  app.post(api.massScan.runStage.path, async (req, res) => {
    try {
      const fileId = Number(req.params.id);
      const file = await storage.getUploadedFile(fileId);
      if (!file) return res.status(404).json({ message: "File not found" });
      
      const input = api.massScan.runStage.input.parse(req.body);
      const { stageNumber, threads, targetIds } = input;
      
      // Get targets ready for this stage
      const targets = await storage.getStagedTargetsByFile(fileId);
      let eligibleTargets = targets.filter(t => 
        t.currentStage === stageNumber - 1 && t.status === "pending"
      );
      
      // Filter by targetIds if provided (Issue 1 fix)
      if (targetIds && targetIds.length > 0) {
        const targetIdSet = new Set(targetIds);
        eligibleTargets = eligibleTargets.filter(t => targetIdSet.has(t.id));
        
        if (eligibleTargets.length === 0) {
          return res.status(400).json({ 
            message: "None of the specified targets are ready for this stage" 
          });
        }
      }
      
      if (eligibleTargets.length === 0) {
        return res.status(400).json({ message: "No targets ready for this stage" });
      }
      
      // Enable zeroSpeedMode for stages 4 and 5
      const zeroSpeedMode = stageNumber >= 4;
      
      // Create stage run record
      const stageRun = await storage.createStageRun({
        fileId,
        stageNumber,
        status: "pending",
        totalTargets: eligibleTargets.length,
        processedTargets: 0,
        flaggedTargets: 0,
        confirmedVulns: 0,
        threads,
        zeroSpeedMode,
      });
      
      // Update file status to processing (don't touch currentStage - only update on completion)
      await storage.updateUploadedFile(fileId, { 
        status: "processing" 
      });
      
      // Update stage run to running
      await storage.updateStageRun(stageRun.id, { 
        status: "running", 
        startedAt: new Date() 
      });
      
      // Create and run stage executor in background
      const executor = new StageExecutor();
      activeStageExecutors.set(stageRun.id, executor);
      
      const targetUrls = eligibleTargets.map(t => t.url);
      
      // Run asynchronously
      executor.executeStage(fileId, stageNumber, targetUrls, async (progress) => {
        // Update stage run progress
        await storage.updateStageRun(stageRun.id, {
          processedTargets: progress.processedTargets,
          flaggedTargets: progress.flaggedTargets,
          confirmedVulns: progress.confirmedVulns,
        });
      }).then(async (result) => {
        // Stage completed
        console.log(`[MassScan] Stage ${stageNumber} completed for file ${fileId}: ${result.processedCount} processed, ${result.flaggedCount} flagged`);
        
        await storage.updateStageRun(stageRun.id, {
          status: "completed",
          completedAt: new Date(),
          processedTargets: result.processedCount,
          flaggedTargets: result.flaggedCount,
          confirmedVulns: result.confirmedVulns,
        });
        
        // Get current file state and updated targets
        const currentFile = await storage.getUploadedFile(fileId);
        const updatedTargets = await storage.getStagedTargetsByFile(fileId);
        
        // Check if all targets have completed the final stage (stage 5)
        const allCompletedFinalStage = updatedTargets.every(t => 
          t.currentStage >= 5 || t.status === "flagged"
        );
        
        // Only update currentStage if we actually processed targets AND this stage is higher than current
        const shouldUpdateStage = result.processedCount > 0 && 
          (!currentFile || stageNumber > (currentFile.currentStage || 0));
        
        // Calculate statistics for logging (condensed)
        const targetsByStage = updatedTargets.reduce((acc, t) => {
          acc[t.currentStage] = (acc[t.currentStage] || 0) + 1;
          return acc;
        }, {} as Record<number, number>);
        console.log(`[MassScan] File ${fileId} targets by stage:`, JSON.stringify(targetsByStage));
        
        if (allCompletedFinalStage) {
          // All done - mark completed
          await storage.updateUploadedFile(fileId, { status: "completed", currentStage: 5 });
        } else if (currentFile?.status !== "completed") {
          // Stage finished - set to "pending" (ready for next stage) not "processing" (actively running)
          // Only update currentStage if we actually processed targets AND this is a new high-water mark
          const updates: { status?: string; currentStage?: number } = { status: "pending" };
          if (shouldUpdateStage) {
            updates.currentStage = stageNumber;
          }
          await storage.updateUploadedFile(fileId, updates);
        }
        
        activeStageExecutors.delete(stageRun.id);
      }).catch(async (error) => {
        console.error(`Stage ${stageNumber} failed:`, error);
        await storage.updateStageRun(stageRun.id, {
          status: "failed",
          completedAt: new Date(),
        });
        await storage.updateUploadedFile(fileId, { status: "failed" });
        activeStageExecutors.delete(stageRun.id);
      });
      
      res.status(201).json(stageRun);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      console.error("Stage run error:", err);
      res.status(500).json({ message: "Failed to start stage run" });
    }
  });

  // Stop stage run
  app.post(api.massScan.stopStage.path, async (req, res) => {
    try {
      const runId = Number(req.params.runId);
      const run = await storage.getStageRun(runId);
      if (!run) return res.status(404).json({ message: "Stage run not found" });
      
      // Guard: Only stop if the run is actually in progress (running or pending)
      if (run.status !== "running" && run.status !== "pending") {
        // Run already completed/failed/stopped - return current state without changes
        return res.json(run);
      }
      
      // Cancel the executor if it's running
      const executor = activeStageExecutors.get(runId);
      if (executor) {
        executor.cancel();
        activeStageExecutors.delete(runId);
      }
      
      const updatedRun = await storage.updateStageRun(runId, { 
        status: "stopped", 
        completedAt: new Date() 
      });
      
      // Only reset file status if it's currently "processing"
      const file = await storage.getUploadedFile(run.fileId);
      if (file && file.status === "processing") {
        await storage.updateUploadedFile(run.fileId, { status: "pending" });
        console.log(`[MassScan] Stage ${run.stageNumber} stopped for file ${run.fileId}`);
      }
      
      res.json(updatedRun);
    } catch (err) {
      res.status(500).json({ message: "Failed to stop stage run" });
    }
  });

  // ============================================
  // End Mass-Scan Management API Routes
  // ============================================

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
    try {
      const { targets, settings } = req.body;
      
      if (!targets || !Array.isArray(targets) || targets.length === 0) {
        return res.status(400).json({ message: "No targets provided" });
      }

      if (targets.length > 100000) {
        return res.status(400).json({ message: "Maximum 100,000 targets allowed" });
      }

      // Create parent scan for mass scan
      const parentScan = await storage.createScan({
        targetUrl: `mass-scan-${Date.now()}`,
        scanMode: "sqli",
        threads: settings?.threads || 10,
        batchMode: true,
      });
      
      activeMassScanId = parentScan.id;

      // Create child scans for each target
      const childScans: any[] = [];
      for (const url of targets) {
        const childScan = await storage.createScan({
          targetUrl: url.trim(),
          scanMode: "sqli",
          threads: settings?.threads || 10,
          parentId: parentScan.id,
        });
        childScans.push(childScan);
      }

      const { MassScanner } = await import("./scanner/mass-scanner");
      const concurrency = settings?.concurrency || 50;
      const scanner = new MassScanner(concurrency, settings?.threads || 10);
      activeMassScanner = scanner;

      const scanTargets = childScans.map((scan) => ({
        url: scan.targetUrl,
        id: scan.id,
      }));

      // Start scanning in background
      scanner.scanBatch(scanTargets).then(() => {
        console.log(`[Mass Scan] Complete`);
        storage.updateScan(parentScan.id, {
          status: "completed",
          progress: 100,
          endTime: new Date(),
        });
        activeMassScanner = null;
        activeMassScanId = null;
      });

      res.json({
        message: "Mass scan started",
        scanId: parentScan.id,
        totalTargets: targets.length,
        concurrency,
      });
    } catch (error: any) {
      console.error("Mass scan error:", error);
      res.status(500).json({ message: "Failed to start mass scan" });
    }
  });

  // Get mass scan progress
  app.get("/api/mass-scan/progress", async (req, res) => {
    try {
      // If no active scanner, check if we have saved state
      if (!activeMassScanner && activeMassScanId) {
        const parentScan = await storage.getScan(activeMassScanId);
        if (parentScan && parentScan.status === "completed") {
          const childScans = await storage.getChildScans(activeMassScanId);
          const vulnerable = childScans.filter(async (s) => {
            const vulns = await storage.getVulnerabilities(s.id);
            return vulns.length > 0;
          }).length;
          
          return res.json({
            running: false,
            total: childScans.length,
            completed: childScans.filter(s => s.status === "completed").length,
            scanning: 0,
            vulnerable,
            clean: childScans.length - vulnerable,
            errors: childScans.filter(s => s.status === "failed").length,
            progress: 100,
            scanId: activeMassScanId,
          });
        }
      }
      
      if (!activeMassScanner) {
        return res.json({
          running: false,
          total: 0,
          completed: 0,
          scanning: 0,
          vulnerable: 0,
          clean: 0,
          errors: 0,
          progress: 0,
        });
      }

      const stats = activeMassScanner.getStats();
      const percentComplete = stats.total > 0 
        ? Math.round(((stats.completed + stats.errors) / stats.total) * 100) 
        : 0;

      res.json({
        running: true,
        ...stats,
        progress: percentComplete,
        scanId: activeMassScanId,
      });
    } catch (error: any) {
      console.error("Progress error:", error);
      res.status(500).json({ message: "Failed to get progress" });
    }
  });

  // Get vulnerable targets from mass scan
  app.get("/api/mass-scan/vulnerable", async (req, res) => {
    try {
      // If we have active mass scan ID, get its child scans
      if (activeMassScanId) {
        const childScans = await storage.getChildScans(activeMassScanId);
        const vulnerableScans = [];

        for (const scan of childScans) {
          const vulns = await storage.getVulnerabilities(scan.id);
          if (vulns.length > 0 && vulns[0]) {
            vulnerableScans.push({
              scanId: scan.id,
              url: scan.targetUrl,
              vulnerability: {
                id: vulns[0].id,
                type: vulns[0].type,
                parameter: vulns[0].parameter,
                payload: vulns[0].payload,
              },
            });
          }
        }

        return res.json(vulnerableScans);
      }
      
      if (!activeMassScanner) {
        // Get recent completed scans with vulnerabilities
        const scans = await storage.getScans();
        const recentScans = scans.slice(0, 1000); // Last 1000 scans
        const vulnerableScans = [];

        for (const scan of recentScans) {
          if (scan.status === "completed" && scan.summary && scan.summary.confirmed > 0) {
            const vulns = await storage.getVulnerabilities(scan.id);
            if (vulns.length > 0) {
              vulnerableScans.push({
                scanId: scan.id,
                url: scan.targetUrl,
                vulnerability: {
                  id: vulns[0].id,
                  parameter: vulns[0].parameter,
                  payload: vulns[0].payload,
                  dbType: vulns[0].evidence?.includes("MySQL") ? "MySQL" : 
                          vulns[0].evidence?.includes("PostgreSQL") ? "PostgreSQL" : "Unknown",
                  technique: vulns[0].type,
                },
              });
            }
          }
        }

        return res.json(vulnerableScans);
      }

      // Get results from active scanner
      const vulnerable = activeMassScanner.getVulnerableTargets();
      const results = [];

      for (const result of vulnerable) {
        const vulns = await storage.getVulnerabilities(result.scanId);
        if (vulns.length > 0) {
          results.push({
            scanId: result.scanId,
            url: result.url,
            vulnerability: {
              id: vulns[0].id,
              parameter: vulns[0].parameter,
              payload: vulns[0].payload,
              dbType: vulns[0].evidence?.includes("MySQL") ? "MySQL" : 
                      vulns[0].evidence?.includes("PostgreSQL") ? "PostgreSQL" : "Unknown",
              technique: vulns[0].type,
            },
          });
        }
      }

      res.json(results);
    } catch (error: any) {
      console.error("Get vulnerable targets error:", error);
      res.status(500).json({ message: "Failed to get vulnerable targets" });
    }
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

  // Dump tables from a database
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
      
      // Create dumping job
      const job = await storage.createDumpingJob({
        vulnerabilityId: database.vulnerabilityId,
        scanId: database.scanId,
        targetUrl: database.targetUrl,
        targetType: "table",
        targetId: dbId,
        status: "running",
        progress: 0,
      });
      
      // Start table enumeration
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
      
      engine.enumerateTables(database.databaseName).then(async (tables) => {
        // Save tables
        for (const table of tables) {
          await storage.createExtractedTable({
            databaseId: dbId,
            tableName: table.name,
            status: "discovered",
          });
        }
        
        await storage.updateExtractedDatabase(dbId, {
          tableCount: tables.length,
          status: "completed",
        });
        
        await storage.updateDumpingJob(job.id, {
          status: "completed",
          progress: 100,
          itemsTotal: tables.length,
          itemsExtracted: tables.length,
          completedAt: new Date(),
        });
      });
      
      res.json({ job, message: "Table dumping started" });
    } catch (error: any) {
      console.error("Dump tables error:", error);
      res.status(500).json({ message: "Failed to dump tables" });
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

  // Dump data from a table
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
      
      // Create dumping job
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
      
      // Start data extraction
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
      
      engine.extractTableData(database.databaseName, table.tableName, columnNames, limit)
        .then(async (rows) => {
          // Save data
          for (let i = 0; i < rows.length; i++) {
            await storage.createExtractedData({
              tableId,
              rowIndex: i,
              rowData: rows[i],
            });
          }
          
          await storage.updateExtractedTable(tableId, {
            rowCount: rows.length,
            status: "completed",
          });
          
          await storage.updateDumpingJob(job.id, {
            status: "completed",
            progress: 100,
            itemsExtracted: rows.length,
            completedAt: new Date(),
          });
        });
      
      res.json({ job, message: "Data dumping started" });
    } catch (error: any) {
      console.error("Dump data error:", error);
      res.status(500).json({ message: "Failed to dump data" });
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
                const data = await storage.getExtractedData(col.id);
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
          const data = await storage.getExtractedData(col.tableId);
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
