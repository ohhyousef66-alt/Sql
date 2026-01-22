#!/usr/bin/env node
// Quick test runner
const { spawn } = require('child_process');

console.log('\n🔥 Starting Quick Test...\n');

// Check environment
if (!process.env.DATABASE_URL) {
  console.log('⚠️  DATABASE_URL not set, loading from .env');
  require('dotenv').config();
}

console.log('Database:', process.env.DATABASE_URL ? '✅ Configured' : '❌ Missing');
console.log('\n' + '='.repeat(80) + '\n');

// Run the verification test
const test = spawn('npx', ['tsx', 'test-verification-loop.ts'], {
  stdio: 'inherit',
  env: process.env
});

test.on('close', (code) => {
  console.log(`\nTest exited with code ${code}`);
  process.exit(code);
});

test.on('error', (err) => {
  console.error('Failed to start:', err.message);
  process.exit(1);
});
