// Simple test runner using Node's child_process
const { spawn } = require('child_process');
const path = require('path');

console.log('\n' + '='.repeat(80));
console.log('🔥 RUNNING PROOF-OF-WORK TEST');
console.log('='.repeat(80) + '\n');

// Ensure we have environment
if (!process.env.DATABASE_URL) {
  require('dotenv').config();
}

console.log('📊 Environment Check:');
console.log(`   DATABASE_URL: ${process.env.DATABASE_URL ? '✅ Set' : '❌ Not set'}`);
console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
console.log('\n');

// Run tsx proof-test.ts
const tsx = spawn('npx', ['tsx', 'proof-test.ts'], {
  cwd: process.cwd(),
  env: process.env,
  stdio: 'inherit'
});

tsx.on('close', (code) => {
  console.log(`\nTest process exited with code ${code}`);
  process.exit(code);
});

tsx.on('error', (err) => {
  console.error(`Failed to start test: ${err.message}`);
  process.exit(1);
});
