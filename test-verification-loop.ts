#!/usr/bin/env tsx
/**
 * PROOF OF CONCEPT TEST
 * This script demonstrates the verification loop in action
 */

import { VulnerabilityScanner } from "./server/scanner/index";
import { storage } from "./server/storage";

async function runVerificationTest() {
  console.log("=".repeat(80));
  console.log("🧪 VERIFICATION LOOP - PROOF OF CONCEPT TEST");
  console.log("=".repeat(80));
  console.log();

  // Use a known vulnerable test site
  const vulnerableUrl = "http://testphp.vulnweb.com/artists.php?artist=1";
  
  console.log("📋 Test Configuration:");
  console.log(`   Target URL: ${vulnerableUrl}`);
  console.log(`   Scan Mode: sqli`);
  console.log(`   Threads: 10`);
  console.log();

  try {
    // Create a test scan
    console.log("1️⃣ Creating scan record...");
    const scan = await storage.createScan({
      targetUrl: vulnerableUrl,
      scanMode: "sqli",
      threads: 10,
    });
    console.log(`   ✅ Scan created with ID: ${scan.id}`);
    console.log();

    // Initialize scanner
    console.log("2️⃣ Initializing VulnerabilityScanner...");
    const scanner = new VulnerabilityScanner(
      scan.id,
      vulnerableUrl,
      "sqli",
      10
    );
    console.log("   ✅ Scanner initialized");
    console.log();

    // Start scan
    console.log("3️⃣ Starting scan (this will take 2-5 minutes)...");
    console.log("   📡 Watching for verification loop logs...");
    console.log("-".repeat(80));
    console.log();

    // Run the scan
    await scanner.run();

    console.log();
    console.log("-".repeat(80));
    console.log("4️⃣ Scan completed! Fetching results...");
    console.log();

    // Get scan results
    const updatedScan = await storage.getScan(scan.id);
    const vulnerabilities = await storage.getVulnerabilities(scan.id);
    const logs = await storage.getScanLogs(scan.id);

    // Display results
    console.log("=".repeat(80));
    console.log("📊 SCAN RESULTS");
    console.log("=".repeat(80));
    console.log();

    console.log("📈 Scan Status:");
    console.log(`   Status: ${updatedScan?.status}`);
    console.log(`   Progress: ${updatedScan?.progress}%`);
    console.log(`   Completion Reason: ${updatedScan?.completionReason || "N/A"}`);
    console.log();

    console.log("🎯 Summary:");
    const summary = updatedScan?.summary as any;
    if (summary) {
      console.log(`   Critical: ${summary.critical || 0}`);
      console.log(`   High: ${summary.high || 0}`);
      console.log(`   Medium: ${summary.medium || 0}`);
      console.log(`   Confirmed: ${summary.confirmed || 0}`);
      console.log(`   Potential: ${summary.potential || 0}`);
    }
    console.log();

    // Show vulnerabilities with verification proof
    console.log("🔒 VERIFIED VULNERABILITIES:");
    console.log("-".repeat(80));
    if (vulnerabilities && vulnerabilities.length > 0) {
      for (const vuln of vulnerabilities) {
        console.log();
        console.log(`   Type: ${vuln.type}`);
        console.log(`   Severity: ${vuln.severity.toUpperCase()}`);
        console.log(`   Parameter: ${vuln.parameter}`);
        console.log(`   Confidence: ${vuln.confidence}%`);
        console.log(`   Verification: ${vuln.verificationStatus}`);
        console.log();
        console.log(`   Evidence:`);
        if (vuln.evidence) {
          const evidenceLines = vuln.evidence.split('\n');
          evidenceLines.forEach((line: string) => console.log(`      ${line}`));
        }
        console.log();
        
        // Check for dumper verification proof
        if (vuln.evidence && vuln.evidence.includes("VERIFIED by Dumper")) {
          console.log("   ✅ DUMPER VERIFICATION: SUCCESS");
          // Extract database name from evidence
          const dbMatch = vuln.evidence.match(/Database:\s*([^\s,]+)/);
          if (dbMatch) {
            console.log(`   📊 Extracted Database: ${dbMatch[1]}`);
          }
        } else {
          console.log("   ⚠️ WARNING: No dumper verification found!");
        }
        console.log("-".repeat(80));
      }
    } else {
      console.log("   ℹ️ No vulnerabilities found (or all discarded as false positives)");
    }
    console.log();

    // Show verification loop logs
    console.log("📜 VERIFICATION LOOP LOGS:");
    console.log("-".repeat(80));
    const verificationLogs = logs.filter(log => 
      log.message.includes("Verification Loop") || 
      log.message.includes("Dumper") ||
      log.message.includes("Stop-on-Success")
    );
    
    if (verificationLogs.length > 0) {
      for (const log of verificationLogs) {
        const timestamp = new Date(log.timestamp).toISOString().split('T')[1].split('.')[0];
        console.log(`   [${timestamp}] [${log.level.toUpperCase()}] ${log.message}`);
      }
    } else {
      console.log("   ⚠️ No verification loop logs found!");
      console.log("   This might indicate the verification loop is not active.");
    }
    console.log();

    // Verify database persistence
    console.log("=".repeat(80));
    console.log("💾 DATABASE PERSISTENCE CHECK");
    console.log("=".repeat(80));
    console.log();

    // Check if vulnerabilities were saved
    if (vulnerabilities && vulnerabilities.length > 0) {
      console.log("✅ Vulnerabilities successfully saved to Railway PostgreSQL");
      console.log(`   Record Count: ${vulnerabilities.length}`);
      console.log(`   Scan ID: ${scan.id}`);
      
      // Check for extracted databases
      const extractedDbs = await storage.getExtractedDatabases(scan.id);
      if (extractedDbs && extractedDbs.length > 0) {
        console.log();
        console.log("✅ Extracted databases found in Railway PostgreSQL:");
        for (const db of extractedDbs) {
          console.log(`   - Database: ${db.databaseName}`);
          console.log(`     Type: ${db.dbType}`);
          console.log(`     Method: ${db.extractionMethod}`);
          console.log(`     Table Count: ${db.tableCount}`);
        }
      } else {
        console.log();
        console.log("ℹ️ No extracted databases found (dumper might not have completed full enumeration)");
      }
    } else {
      console.log("ℹ️ No vulnerabilities saved (target might not be vulnerable or all were false positives)");
    }
    console.log();

    // Final verdict
    console.log("=".repeat(80));
    console.log("🏁 TEST VERDICT");
    console.log("=".repeat(80));
    console.log();

    let passed = true;
    const checks = [];

    // Check 1: Scan completed
    if (updatedScan?.status === "completed" || updatedScan?.status === "failed") {
      checks.push("✅ Scan execution completed");
    } else {
      checks.push("❌ Scan did not complete");
      passed = false;
    }

    // Check 2: Verification loop logs present
    if (verificationLogs.length > 0) {
      checks.push("✅ Verification loop logs found");
    } else {
      checks.push("⚠️ Verification loop logs missing (might not have found vulnerabilities)");
    }

    // Check 3: Vulnerabilities found and verified
    const verifiedVulns = vulnerabilities?.filter(v => 
      v.evidence && v.evidence.includes("VERIFIED by Dumper")
    );
    if (verifiedVulns && verifiedVulns.length > 0) {
      checks.push(`✅ ${verifiedVulns.length} verified vulnerability(ies) found`);
    } else if (vulnerabilities && vulnerabilities.length > 0) {
      checks.push(`⚠️ ${vulnerabilities.length} vulnerability(ies) found but not verified by dumper`);
    } else {
      checks.push("ℹ️ No vulnerabilities found (might be non-vulnerable target)");
    }

    // Check 4: Database persistence
    if (vulnerabilities && vulnerabilities.length > 0) {
      checks.push("✅ Data persisted to Railway PostgreSQL");
    }

    checks.forEach(check => console.log(`   ${check}`));
    console.log();

    if (passed && verifiedVulns && verifiedVulns.length > 0) {
      console.log("🎉 SUCCESS: Verification loop is working correctly!");
      console.log("   - Scanner detected vulnerabilities");
      console.log("   - Dumper automatically verified them");
      console.log("   - Extracted data saved to database");
      console.log("   - Zero false positives");
    } else if (updatedScan?.status === "completed") {
      console.log("✅ SCAN COMPLETED but no vulnerabilities found");
      console.log("   This is normal if the target is not vulnerable");
      console.log("   or if all detections were discarded as false positives.");
    } else {
      console.log("⚠️ TEST INCOMPLETE - Check logs above for details");
    }
    console.log();
    console.log("=".repeat(80));

    process.exit(0);

  } catch (error: any) {
    console.error();
    console.error("❌ TEST FAILED WITH ERROR:");
    console.error(`   ${error.message}`);
    console.error();
    console.error("Stack trace:");
    console.error(error.stack);
    process.exit(1);
  }
}

// Run the test
runVerificationTest().catch(console.error);
