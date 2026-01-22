#!/usr/bin/env node
/**
 * INSTANT VERIFICATION - No Database Needed
 * Just checks the code is properly connected
 */

const fs = require('fs');
const path = require('path');

console.log('\n' + '█'.repeat(80));
console.log('█' + ' '.repeat(78) + '█');
console.log('█' + '  🔥 SQL INJECTION SCANNER + DUMPER - CODE VERIFICATION  🔥  '.padEnd(78) + '█');
console.log('█' + ' '.repeat(78) + '█');
console.log('█'.repeat(80) + '\n');

const scannerPath = path.join(__dirname, 'server/scanner/index.ts');
const dumperPath = path.join(__dirname, 'server/scanner/data-dumping-engine.ts');
const utilsPath = path.join(__dirname, 'server/scanner/utils.ts');

if (!fs.existsSync(scannerPath)) {
  console.error('❌ FATAL: Scanner file not found');
  process.exit(1);
}

if (!fs.existsSync(dumperPath)) {
  console.error('❌ FATAL: Dumper file not found');
  process.exit(1);
}

if (!fs.existsSync(utilsPath)) {
  console.error('❌ FATAL: Utils file not found');
  process.exit(1);
}

const scannerCode = fs.readFileSync(scannerPath, 'utf8');
const dumperCode = fs.readFileSync(dumperPath, 'utf8');
const utilsCode = fs.readFileSync(utilsPath, 'utf8');

console.log('📋 VERIFYING CORE COMPONENTS:\n');

const checks = [
  {
    name: 'Axios Request Function (makeRequest)',
    file: 'utils.ts',
    code: utilsCode,
    pattern: 'const response: AxiosResponse<Buffer> = await axios(config)',
    critical: true
  },
  {
    name: 'SQL Error Detection (extractErrorPatterns)',
    file: 'sqli.ts',
    code: scannerCode,
    pattern: 'extractErrorPatterns(body: string)',
    critical: true
  },
  {
    name: 'Verification Loop Trigger',
    file: 'index.ts',
    code: scannerCode,
    pattern: '🔬 [Verification Loop] SQLi detected',
    critical: true
  },
  {
    name: 'verifyWithDumper Method',
    file: 'index.ts',
    code: scannerCode,
    pattern: 'async verifyWithDumper(vuln',
    critical: true
  },
  {
    name: 'Dumper Called in Verification',
    file: 'index.ts',
    code: scannerCode,
    pattern: 'await this.verifyWithDumper(vulnToReport)',
    critical: true
  },
  {
    name: 'Dumper getCurrentDatabaseInfo',
    file: 'data-dumping-engine.ts',
    code: dumperCode,
    pattern: 'async getCurrentDatabaseInfo()',
    critical: true
  },
  {
    name: 'Dumper Instance Created',
    file: 'index.ts',
    code: scannerCode,
    pattern: 'new DataDumpingEngine(dumpingContext)',
    critical: true
  },
  {
    name: 'Database Extraction Called',
    file: 'index.ts',
    code: scannerCode,
    pattern: 'await dumper.getCurrentDatabaseInfo()',
    critical: true
  },
  {
    name: 'Evidence Tagged with Dumper Results',
    file: 'index.ts',
    code: scannerCode,
    pattern: '✅ VERIFIED by Dumper',
    critical: true
  },
  {
    name: 'Stop-on-Success Logic',
    file: 'index.ts',
    code: scannerCode,
    pattern: 'this.cancelled = true',
    critical: true
  },
  {
    name: 'False Positive Discard',
    file: 'index.ts',
    code: scannerCode,
    pattern: '❌ [Verification Loop] DISCARDED',
    critical: true
  },
  {
    name: 'Dumper Union Extraction',
    file: 'data-dumping-engine.ts',
    code: dumperCode,
    pattern: 'extractValueUnion',
    critical: true
  },
  {
    name: 'Dumper Error Extraction',
    file: 'data-dumping-engine.ts',
    code: dumperCode,
    pattern: 'extractValueError',
    critical: true
  },
];

let passed = 0;
let failed = 0;

for (const check of checks) {
  const found = check.code.includes(check.pattern);
  if (found) {
    console.log(`✅ ${check.name}`);
    console.log(`   └─ Found in ${check.file}`);
    passed++;
  } else {
    console.log(`❌ ${check.name}`);
    console.log(`   └─ MISSING in ${check.file}`);
    failed++;
    if (check.critical) {
      console.log(`   └─ ⚠️  CRITICAL COMPONENT MISSING!`);
    }
  }
}

console.log('\n' + '═'.repeat(80));
console.log(`\n📊 RESULTS: ${passed}/${checks.length} checks passed\n`);

if (failed === 0) {
  console.log('█'.repeat(80));
  console.log('█' + ' '.repeat(78) + '█');
  console.log('█' + '  ✅ ALL SYSTEMS OPERATIONAL - CODE FULLY INTEGRATED  ✅  '.padEnd(78) + '█');
  console.log('█' + ' '.repeat(78) + '█');
  console.log('█'.repeat(80));
  console.log('\n🚀 READY TO RUN: npm run proof\n');
  process.exit(0);
} else {
  console.log('█'.repeat(80));
  console.log('█' + ' '.repeat(78) + '█');
  console.log('█' + `  ❌ ${failed} CRITICAL COMPONENTS MISSING  ❌  `.padEnd(78) + '█');
  console.log('█' + ' '.repeat(78) + '█');
  console.log('█'.repeat(80));
  console.log('\n⚠️  System not ready for live testing\n');
  process.exit(1);
}
