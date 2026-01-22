const { execSync } = require('child_process');
const fs = require('fs');

console.log('\n🔥 Running Instant Verification...\n');

try {
  const result = execSync('node instant-verify.js', { 
    encoding: 'utf8',
    stdio: 'pipe',
    cwd: __dirname
  });
  console.log(result);
  process.exit(0);
} catch (error) {
  console.error('Exit code:', error.status);
  console.log(error.stdout);
  console.error(error.stderr);
  process.exit(error.status || 1);
}
