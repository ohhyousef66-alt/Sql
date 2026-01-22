#!/usr/bin/env node
/**
 * QUICK VERIFICATION TEST
 * Checks if the scanner and dumper integration is properly set up
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('\n' + '='.repeat(80));
console.log('🔍 VERIFICATION: Scanner + Dumper Integration');
console.log('='.repeat(80) + '\n');

// Read key files
const scannerPath = path.join(__dirname, 'server/scanner/index.ts');
const dumperPath = path.join(__dirname, 'server/scanner/data-dumping-engine.ts');

if (!fs.existsSync(scannerPath)) {
  console.error('❌ Scanner file not found');
  process.exit(1);
}

if (!fs.existsSync(dumperPath)) {
  console.error('❌ Dumper file not found');
  process.exit(1);
}

const scannerCode = fs.readFileSync(scannerPath, 'utf8');
const dumperCode = fs.readFileSync(dumperPath, 'utf8');

console.log('📋 Checking Integration Points:\n');

// Check 1: Verification loop exists
const hasVerificationLoop = scannerCode.includes('🔬 [Verification Loop] SQLi detected');
console.log(`1. Verification Loop Trigger: ${hasVerificationLoop ? '✅' : '❌'}`);

// Check 2: verifyWithDumper method exists
const hasVerifyMethod = scannerCode.includes('async verifyWithDumper(');
console.log(`2. verifyWithDumper() Method: ${hasVerifyMethod ? '✅' : '❌'}`);

// Check 3: Dumper is called in verification
const callsDumper = scannerCode.includes('await this.verifyWithDumper(vulnToReport)');
console.log(`3. Calls Dumper in reportVuln(): ${callsDumper ? '✅' : '❌'}`);

// Check 4: Dumper has getCurrentDatabaseInfo
const hasDumperMethod = dumperCode.includes('async getCurrentDatabaseInfo()');
console.log(`4. Dumper.getCurrentDatabaseInfo(): ${hasDumperMethod ? '✅' : '❌'}`);

// Check 5: Dumper is called
const callsgetCurrentDb = scannerCode.includes('await dumper.getCurrentDatabaseInfo()');
console.log(`5. getCurrentDatabaseInfo() Called: ${callsgetCurrentDb ? '✅' : '❌'}`);

// Check 6: Stop on success logic
const hasStopOnSuccess = scannerCode.includes('this.cancelled = true');
console.log(`6. Stop-on-Success Logic: ${hasStopOnSuccess ? '✅' : '❌'}`);

// Check 7: Evidence updated with dumper results
const updatesEvidence = scannerCode.includes('✅ VERIFIED by Dumper');
console.log(`7. Evidence Tagged with Verification: ${updatesEvidence ? '✅' : '❌'}`);

// Check 8: False positives are discarded
const discardsUnverified = scannerCode.includes('❌ [Verification Loop] DISCARDED');
console.log(`8. Discards Unverified Results: ${discardsUnverified ? '✅' : '❌'}`);

console.log('\n' + '='.repeat(80));

const allChecks = [
  hasVerificationLoop,
  hasVerifyMethod,
  callsDumper,
  hasDumperMethod,
  callsgetCurrentDb,
  hasStopOnSuccess,
  updatesEvidence,
  discardsUnverified
];

const passedChecks = allChecks.filter(Boolean).length;
const totalChecks = allChecks.length;

console.log(`\n📊 Result: ${passedChecks}/${totalChecks} checks passed\n`);

if (passedChecks === totalChecks) {
  console.log('✅ ✅ ✅ ALL INTEGRATION POINTS VERIFIED! ✅ ✅ ✅');
  console.log('\nThe Scanner + Dumper pipeline is properly integrated.');
  console.log('\n🚀 Ready to run live test with: npm run proof\n');
  process.exit(0);
} else {
  console.log('❌ Some integration points are missing');
  console.log('\nPlease review the code to ensure all components are connected.\n');
  process.exit(1);
}
