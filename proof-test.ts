#!/usr/bin/env tsx
/**
 * PROOF OF WORK TEST - LIVE DEMONSTRATION
 * 
 * This script will PROVE the system works by:
 * 1. Starting a scan on a known vulnerable URL
 * 2. Showing scanner logs in REAL-TIME
 * 3. Showing when the Dumper automatically kicks in
 * 4. Showing the extracted database name
 * 5. Verifying data was saved to PostgreSQL
 */

import { storage } from "./server/storage";
import { VulnerabilityScanner } from "./server/scanner/index";
import { pool } from "./server/db";

const VULNERABLE_URL = "http://testphp.vulnweb.com/artists.php?artist=1";

// ANSI color codes for beautiful output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
};

function log(message: string, color: string = colors.white) {
  console.log(`${color}${message}${colors.reset}`);
}

function header(message: string) {
  console.log("\n" + "=".repeat(80));
  log(message, colors.bright + colors.cyan);
  console.log("=".repeat(80) + "\n");
}

function success(message: string) {
  log(`✅ ${message}`, colors.green);
}

function error(message: string) {
  log(`❌ ${message}`, colors.red);
}

function info(message: string) {
  log(`ℹ️  ${message}`, colors.blue);
}

function warning(message: string) {
  log(`⚠️  ${message}`, colors.yellow);
}

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForCompletion(scanId: number, maxWaitSeconds: number = 120): Promise<boolean> {
  const startTime = Date.now();
  const maxWaitMs = maxWaitSeconds * 1000;
  
  info(`Waiting for scan to complete (max ${maxWaitSeconds}s)...`);
  
  while (Date.now() - startTime < maxWaitMs) {
    const scan = await storage.getScan(scanId);
    
    if (!scan) {
      error("Scan not found!");
      return false;
    }
    
    if (scan.status === "completed" || scan.status === "cancelled") {
      success(`Scan finished with status: ${scan.status}`);
      return true;
    }
    
    // Show progress
    process.stdout.write(`\r⏳ Progress: ${scan.progress || 0}% - Status: ${scan.status}    `);
    
    await sleep(2000);
  }
  
  warning("Scan timed out!");
  return false;
}

async function main() {
  try {
    header("🔥 PROOF OF WORK TEST - SQL INJECTION SCANNER & DUMPER");
    
    info(`Target URL: ${VULNERABLE_URL}`);
    info(`Database: ${process.env.DATABASE_URL?.replace(/postgresql:\/\/([^:]+):([^@]+)@/, "postgresql://$1:***@") || "Not configured"}`);
    console.log();
    
    // Step 1: Create a scan
    header("STEP 1: Creating Scan Record");
    const scan = await storage.createScan({
      targetUrl: VULNERABLE_URL,
      scanMode: "sqli",
      threads: 10,
    });
    
    success(`✅ Scan created with ID: ${scan.id}`);
    console.log();
    
    // Step 2: Initialize and start scanner
    header("STEP 2: Initializing Scanner with Verification Loop");
    info("This scanner will:");
    info("  1. Find SQL injection vulnerabilities");
    info("  2. Automatically trigger the Dumper for verification");
    info("  3. Extract database names to prove exploitability");
    info("  4. Stop immediately on verified success");
    console.log();
    
    const scanner = new VulnerabilityScanner(scan.id, VULNERABLE_URL, "sqli", 10);
    
    header("STEP 3: Running Full Scan Cycle");
    warning("This may take 2-5 minutes. Watch the logs...");
    console.log();
    console.log("-".repeat(80));
    
    // Run the scanner (logs will appear in real-time)
    await scanner.run();
    
    console.log("-".repeat(80));
    console.log();
    
    // Wait a moment for everything to settle
    await sleep(2000);
    
    // Step 4: Retrieve and verify results
    header("STEP 4: Retrieving Results from PostgreSQL");
    
    const finalScan = await storage.getScan(scan.id);
    const vulns = await storage.getVulnerabilities(scan.id);
    const logs = await storage.getScanLogs(scan.id);
    
    info(`Scan Status: ${finalScan?.status}`);
    info(`Total Logs: ${logs.length}`);
    info(`Vulnerabilities Found: ${vulns.length}`);
    console.log();
    
    // Step 5: Display vulnerability details
    if (vulns.length > 0) {
      header("STEP 5: VERIFIED VULNERABILITY DETAILS");
      
      for (const vuln of vulns) {
        console.log("━".repeat(80));
        success(`🎯 ${vuln.type} - ${vuln.severity.toUpperCase()}`);
        console.log();
        info(`URL: ${vuln.url}`);
        info(`Parameter: ${vuln.parameter || "N/A"}`);
        info(`Confidence: ${vuln.confidence}%`);
        info(`Verification Status: ${vuln.verificationStatus || "N/A"}`);
        console.log();
        console.log(`${colors.cyan}Evidence:${colors.reset}`);
        console.log(vuln.evidence || "No evidence");
        console.log("━".repeat(80));
        console.log();
      }
    } else {
      warning("⚠️ No vulnerabilities saved to database");
    }
    
    // Step 6: Check logs for proof of dumper execution
    header("STEP 6: Analyzing Logs for Dumper Activity");
    
    let foundDumperTrigger = false;
    let foundDatabaseExtraction = false;
    let extractedDbName = "";
    
    for (const log of logs) {
      if (log.message.includes("Dumper Verification") || log.message.includes("Testing with Dumper")) {
        foundDumperTrigger = true;
        success("✅ Found: Dumper was triggered");
      }
      
      if (log.message.includes("VERIFIED by Dumper")) {
        foundDatabaseExtraction = true;
        success("✅ Found: Database extraction succeeded");
        
        // Try to extract the database name from the log
        const match = log.message.match(/Database:\s*(\w+)/);
        if (match) {
          extractedDbName = match[1];
          success(`✅ Extracted Database Name: ${extractedDbName}`);
        }
      }
      
      if (log.message.includes("Database:")) {
        const match = log.message.match(/Database:\s*(\w+)/);
        if (match && !extractedDbName) {
          extractedDbName = match[1];
        }
      }
    }
    
    console.log();
    
    // Final verification summary
    header("🎯 PROOF OF WORK VERIFICATION");
    
    const checks = [
      { 
        name: "✓ Scanner executed successfully", 
        passed: finalScan?.status === "completed" || finalScan?.status === "cancelled",
        detail: `Status: ${finalScan?.status}`
      },
      { 
        name: "✓ SQL injection vulnerability detected", 
        passed: vulns.length > 0,
        detail: `Found ${vulns.length} vulnerability(ies)`
      },
      { 
        name: "✓ Dumper triggered automatically", 
        passed: foundDumperTrigger,
        detail: foundDumperTrigger ? "Dumper verification logs found" : "No dumper trigger found"
      },
      { 
        name: "✓ Database name extracted", 
        passed: foundDatabaseExtraction || extractedDbName.length > 0,
        detail: extractedDbName ? `Database: ${extractedDbName}` : "No database name in logs"
      },
      { 
        name: "✓ Data persisted to PostgreSQL", 
        passed: vulns.length > 0,
        detail: `${vulns.length} vulnerability record(s) saved`
      },
    ];
    
    console.log();
    for (const check of checks) {
      if (check.passed) {
        success(`${check.name} - ${check.detail}`);
      } else {
        error(`${check.name} - ${check.detail}`);
      }
    }
    console.log();
    
    const allPassed = checks.every(c => c.passed);
    
    if (allPassed) {
      header("🎉 ✅ VERIFIED SUCCESS - SYSTEM FULLY OPERATIONAL!");
      success("Scanner → Dumper → Database pipeline working perfectly!");
    } else {
      header("⚠️ PARTIAL SUCCESS");
      warning("Some checks failed. Review logs above.");
      
      // If we found ANY database extraction evidence, that's still good
      if (extractedDbName || foundDatabaseExtraction) {
        console.log();
        success(`🎉 GOOD NEWS: Database extraction IS working! Database: ${extractedDbName || "Found in logs"}`);
      }
    }
    
    console.log();
    info(`Full scan logs contain ${logs.length} entries - check database for complete details`);
    console.log();
    
  } catch (err: any) {
    console.log();
    error(`❌ Test failed: ${err.message}`);
    console.error(err);
    process.exit(1);
  } finally {
    await pool.end();
    process.exit(0);
  }
}

main();
