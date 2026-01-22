#!/usr/bin/env tsx
/**
 * QUICK DATABASE CHECK
 * Shows recent scans and vulnerabilities to verify system is working
 */

import { storage } from "./server/storage";
import { pool } from "./server/db";

async function main() {
  console.log('\n' + '='.repeat(80));
  console.log('📊 DATABASE STATUS CHECK');
  console.log('='.repeat(80) + '\n');
  
  try {
    // Get recent scans
    const scans = await storage.getScans();
    
    console.log(`Total Scans in Database: ${scans.length}\n`);
    
    if (scans.length > 0) {
      console.log('Recent Scans:');
      console.log('-'.repeat(80));
      
      for (const scan of scans.slice(0, 5)) {
        console.log(`\nScan ID: ${scan.id}`);
        console.log(`  URL: ${scan.targetUrl}`);
        console.log(`  Status: ${scan.status}`);
        console.log(`  Progress: ${scan.progress || 0}%`);
        console.log(`  Created: ${new Date(scan.createdAt).toLocaleString()}`);
        
        // Get vulnerabilities for this scan
        const vulns = await storage.getVulnerabilities(scan.id);
        
        if (vulns.length > 0) {
          console.log(`  ✅ Vulnerabilities Found: ${vulns.length}`);
          
          for (const vuln of vulns) {
            console.log(`     - ${vuln.type} on ${vuln.parameter || 'unknown param'}`);
            console.log(`       Severity: ${vuln.severity}, Confidence: ${vuln.confidence}%`);
            
            // Check if evidence contains dumper verification
            if (vuln.evidence && vuln.evidence.includes('VERIFIED by Dumper')) {
              console.log(`       ✅ VERIFIED BY DUMPER!`);
              
              // Extract database name if present
              const dbMatch = vuln.evidence.match(/Database:\s*(\w+)/);
              if (dbMatch) {
                console.log(`       📊 Extracted Database: ${dbMatch[1]}`);
              }
            }
          }
        } else {
          console.log(`  No vulnerabilities found`);
        }
      }
    } else {
      console.log('❌ No scans found in database');
      console.log('\nRun the proof test to create a scan:');
      console.log('  npm run proof\n');
    }
    
    console.log('\n' + '='.repeat(80) + '\n');
    
  } catch (error: any) {
    console.error(`❌ Error: ${error.message}`);
    console.error(error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
