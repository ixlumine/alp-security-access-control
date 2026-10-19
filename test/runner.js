/**
 * Master Test Runner for E-Commerce Authorization System
 * Executes all 6 test suites and generates a comprehensive verification report.
 */

const { fork } = require('child_process');
const path = require('path');

const SUITES = [
  {
    name: 'Suite 1: Database Schema & Integrity',
    file: 'db.test.js',
    description: 'SQLite schema, foreign keys, CHECK constraints, and seeding verification'
  },
  {
    name: 'Suite 2: Authentication & Token Layer',
    file: 'auth.test.js',
    description: 'Bcrypt hashing, JWT issue/verify, authenticateToken middleware, Google OAuth'
  },
  {
    name: 'Suite 3: Role-Based Access Control (RBAC)',
    file: 'rbac.test.js',
    description: 'Role permissions matrix, requireRole & requirePermission middlewares, admin routes'
  },
  {
    name: 'Suite 4: Attribute-Based Access Control (ABAC)',
    file: 'abac.test.js',
    description: 'VIP tier gating, order ownership checks, order cancellation lifecycle guards'
  },
  {
    name: 'Suite 5: Combined Controls (RBAC + ABAC)',
    file: 'combined.test.js',
    description: 'Compound policies: product deletion & refund approval with threshold ceilings'
  },
  {
    name: 'Suite 6: End-to-End Application & Dashboard',
    file: 'e2e.test.js',
    description: 'Full stack assembly, static UI serving, all 5 personas + OAuth user journeys'
  }
];

function runSuite(suite) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const suitePath = path.join(__dirname, suite.file);

    const child = fork(suitePath, [], {
      cwd: path.join(__dirname, '..'),
      stdio: 'inherit'
    });

    child.on('close', (code) => {
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      resolve({
        suite,
        passed: code === 0,
        code,
        duration
      });
    });

    child.on('error', (err) => {
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      resolve({
        suite,
        passed: false,
        error: err.message,
        duration
      });
    });
  });
}

async function main() {
  console.log('================================================================================');
  console.log('       E-COMMERCE AUTHORIZATION & SECURITY SYSTEM - MASTER TEST RUNNER          ');
  console.log('================================================================================\n');

  const results = [];
  const globalStart = Date.now();

  for (let i = 0; i < SUITES.length; i++) {
    const suite = SUITES[i];
    console.log(`\n▶ [${i + 1}/${SUITES.length}] Executing: ${suite.name}`);
    console.log(`  File: test/${suite.file} | Focus: ${suite.description}`);
    console.log('--------------------------------------------------------------------------------');

    const result = await runSuite(suite);
    results.push(result);

    if (!result.passed) {
      console.error(`\n❌ FAILED: ${suite.name} (exited with code ${result.code || 'error'})`);
      break;
    }
  }

  const totalDuration = ((Date.now() - globalStart) / 1000).toFixed(2);
  const allPassed = results.length === SUITES.length && results.every((r) => r.passed);

  console.log('\n================================================================================');
  console.log('                               TEST SUITE SUMMARY                               ');
  console.log('================================================================================');

  results.forEach((r, idx) => {
    const statusIcon = r.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`  ${idx + 1}. [${statusIcon}]  ${r.suite.name.padEnd(46)} (${r.duration}s)`);
  });

  console.log('--------------------------------------------------------------------------------');
  console.log(`  Total Suites:   ${SUITES.length}`);
  console.log(`  Suites Passed:  ${results.filter((r) => r.passed).length}`);
  console.log(`  Suites Failed:  ${results.filter((r) => !r.passed).length}`);
  console.log(`  Total Duration: ${totalDuration}s`);
  console.log('================================================================================');

  if (allPassed) {
    console.log('\n🎉 ALL 6 TEST SUITES PASSED WITH 100% SUCCESS RATE!\n');
    process.exit(0);
  } else {
    console.error('\n❌ ONE OR MORE TEST SUITES FAILED.\n');
    process.exit(1);
  }
}

main();
