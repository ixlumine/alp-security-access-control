const assert = require('assert');
const express = require('express');
const { db } = require('../src/db/database');
const { seedDatabase } = require('../src/db/seed');
const { generateToken, authenticateToken } = require('../src/middleware/authenticate');
const { roles, rolePermissions, hasPermission, hasRole } = require('../src/policies/rbac');
const { requireRole, requirePermission } = require('../src/middleware/authorize');
const adminRouter = require('../src/routes/admin');
const authRouter = require('../src/routes/auth');

console.log('--- Running RBAC Policy & Authorization Tests (Task 3) ---');

// Helper to start an ephemeral Express test server
async function startTestServer() {
  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.use('/api/admin', adminRouter);

  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const baseUrl = `http://127.0.0.1:${port}`;
      resolve({
        server,
        baseUrl,
        close: () => new Promise((res) => server.close(res))
      });
    });
  });
}

// Helper mock req/res for middleware unit testing
function createMockReqRes(user = null, headers = {}) {
  const req = { headers, user };
  let statusCode = 200;
  let jsonBody = null;
  let nextCalled = false;

  const res = {
    status(code) {
      statusCode = code;
      return this;
    },
    json(data) {
      jsonBody = data;
      return this;
    }
  };

  const next = () => {
    nextCalled = true;
  };

  return {
    req,
    res,
    next,
    getStatusCode: () => statusCode,
    getJsonBody: () => jsonBody,
    isNextCalled: () => nextCalled
  };
}

async function runTests() {
  // Re-seed DB to a known baseline
  seedDatabase();

  let testCount = 0;

  // ============================================================
  // Test 1: Unit Test - RBAC policy matrix definitions and hasPermission
  // ============================================================
  {
    testCount++;
    // Admin permissions
    assert.strictEqual(hasPermission('admin', 'admin:dashboard'), true, 'admin must have admin:dashboard');
    assert.strictEqual(hasPermission('admin', 'users:manage'), true, 'admin must have users:manage');
    assert.strictEqual(hasPermission('admin', 'products:read'), true, 'admin must have products:read');
    assert.strictEqual(hasPermission('admin', 'products:create'), true, 'admin must have products:create');
    assert.strictEqual(hasPermission('admin', 'products:delete_any'), true, 'admin must have products:delete_any');
    assert.strictEqual(hasPermission('admin', 'orders:read_all'), true, 'admin must have orders:read_all');
    assert.strictEqual(hasPermission('admin', 'orders:refund_any'), true, 'admin must have orders:refund_any');

    // Seller permissions
    assert.strictEqual(hasPermission('seller', 'seller:dashboard'), true, 'seller must have seller:dashboard');
    assert.strictEqual(hasPermission('seller', 'products:read'), true, 'seller must have products:read');
    assert.strictEqual(hasPermission('seller', 'products:create'), true, 'seller must have products:create');
    assert.strictEqual(hasPermission('seller', 'orders:read_store'), true, 'seller must have orders:read_store');
    assert.strictEqual(hasPermission('seller', 'orders:refund_store'), true, 'seller must have orders:refund_store');

    // Seller negative checks
    assert.strictEqual(hasPermission('seller', 'admin:dashboard'), false, 'seller must NOT have admin:dashboard');
    assert.strictEqual(hasPermission('seller', 'users:manage'), false, 'seller must NOT have users:manage');
    assert.strictEqual(hasPermission('seller', 'products:delete_any'), false, 'seller must NOT have products:delete_any');
    assert.strictEqual(hasPermission('seller', 'orders:read_all'), false, 'seller must NOT have orders:read_all');

    // Customer permissions
    assert.strictEqual(hasPermission('customer', 'customer:dashboard'), true, 'customer must have customer:dashboard');
    assert.strictEqual(hasPermission('customer', 'products:read'), true, 'customer must have products:read');
    assert.strictEqual(hasPermission('customer', 'orders:create'), true, 'customer must have orders:create');
    assert.strictEqual(hasPermission('customer', 'orders:read_own'), true, 'customer must have orders:read_own');
    assert.strictEqual(hasPermission('customer', 'orders:cancel_own'), true, 'customer must have orders:cancel_own');

    // Customer negative checks
    assert.strictEqual(hasPermission('customer', 'admin:dashboard'), false, 'customer must NOT have admin:dashboard');
    assert.strictEqual(hasPermission('customer', 'seller:dashboard'), false, 'customer must NOT have seller:dashboard');
    assert.strictEqual(hasPermission('customer', 'products:create'), false, 'customer must NOT have products:create');
    assert.strictEqual(hasPermission('customer', 'users:manage'), false, 'customer must NOT have users:manage');

    // Edge cases
    assert.strictEqual(hasPermission('guest', 'products:read'), false, 'unknown role must return false');
    assert.strictEqual(hasPermission(null, 'products:read'), false, 'null role must return false');
    assert.strictEqual(hasPermission(undefined, 'products:read'), false, 'undefined role must return false');
    assert.strictEqual(hasPermission('admin', null), false, 'null permission must return false');
    assert.strictEqual(hasPermission('admin', 'non_existent_perm'), false, 'non-existent permission must return false');

    console.log(`✓ Test ${testCount} Passed: RBAC policy matrix and hasPermission accurately enforce permissions`);
  }

  // ============================================================
  // Test 2: Unit Test - hasRole helper function
  // ============================================================
  {
    testCount++;
    assert.strictEqual(hasRole('admin', ['admin']), true, 'admin has role admin in [admin]');
    assert.strictEqual(hasRole('admin', ['admin', 'seller']), true, 'admin has role admin in [admin, seller]');
    assert.strictEqual(hasRole('seller', ['admin', 'seller']), true, 'seller has role seller in [admin, seller]');
    assert.strictEqual(hasRole('customer', ['admin']), false, 'customer does not have role admin');
    assert.strictEqual(hasRole('customer', 'customer'), true, 'customer matches single string customer');
    assert.strictEqual(hasRole(null, ['admin']), false, 'null role returns false');
    assert.strictEqual(hasRole('admin', null), false, 'null allowedRoles returns false');
    assert.strictEqual(hasRole(undefined, ['admin']), false, 'undefined role returns false');

    console.log(`✓ Test ${testCount} Passed: hasRole helper handles array, string, and edge cases`);
  }

  // ============================================================
  // Test 3: Unit Test - requireRole middleware
  // ============================================================
  {
    testCount++;
    const adminMiddleware = requireRole(['admin']);

    // Case 3a: Missing req.user -> 401
    {
      const { req, res, next, getStatusCode, getJsonBody, isNextCalled } = createMockReqRes(null);
      adminMiddleware(req, res, next);
      assert.strictEqual(getStatusCode(), 401, 'Unauthenticated user must receive 401');
      assert.strictEqual(isNextCalled(), false, 'next() must NOT be called on 401');
    }

    // Case 3b: Unauthorized role -> 403 with exact formatted error
    {
      const { req, res, next, getStatusCode, getJsonBody, isNextCalled } = createMockReqRes({ role: 'seller' });
      adminMiddleware(req, res, next);
      assert.strictEqual(getStatusCode(), 403, 'Unauthorized role must receive 403');
      assert.strictEqual(isNextCalled(), false, 'next() must NOT be called on 403');
      assert.deepStrictEqual(getJsonBody(), {
        error: "Forbidden: Access requires one of roles: [admin]. Current role: 'seller'"
      }, 'Must match exact RBAC error message specification');
    }

    // Case 3c: Authorized role -> next()
    {
      const { req, res, next, getStatusCode, isNextCalled } = createMockReqRes({ role: 'admin' });
      adminMiddleware(req, res, next);
      assert.strictEqual(isNextCalled(), true, 'next() must be called for authorized role');
      assert.strictEqual(getStatusCode(), 200, 'Status code should remain default 200');
    }

    console.log(`✓ Test ${testCount} Passed: requireRole middleware enforces authentication, authorization, and error formatting`);
  }

  // ============================================================
  // Test 4: Unit Test - requirePermission middleware
  // ============================================================
  {
    testCount++;
    const manageUsersMiddleware = requirePermission('users:manage');

    // Case 4a: Missing req.user -> 401
    {
      const { req, res, next, getStatusCode, isNextCalled } = createMockReqRes(null);
      manageUsersMiddleware(req, res, next);
      assert.strictEqual(getStatusCode(), 401, 'Unauthenticated user must receive 401');
      assert.strictEqual(isNextCalled(), false, 'next() must NOT be called on 401');
    }

    // Case 4b: Role lacking permission -> 403 with exact formatted error
    {
      const { req, res, next, getStatusCode, getJsonBody, isNextCalled } = createMockReqRes({ role: 'seller' });
      manageUsersMiddleware(req, res, next);
      assert.strictEqual(getStatusCode(), 403, 'Role lacking permission must receive 403');
      assert.strictEqual(isNextCalled(), false, 'next() must NOT be called on 403');
      assert.deepStrictEqual(getJsonBody(), {
        error: "Forbidden: Role 'seller' lacks required permission 'users:manage'"
      }, 'Must match exact RBAC error message specification');
    }

    // Case 4c: Role possessing permission -> next()
    {
      const { req, res, next, isNextCalled } = createMockReqRes({ role: 'admin' });
      manageUsersMiddleware(req, res, next);
      assert.strictEqual(isNextCalled(), true, 'next() must be called for authorized role');
    }

    console.log(`✓ Test ${testCount} Passed: requirePermission middleware enforces granular permission requirements`);
  }

  // ============================================================
  // Test 5: HTTP Integration - Ephemeral server setup & tokens
  // ============================================================
  const { server, baseUrl, close } = await startTestServer();

  try {
    // Generate valid tokens for test roles
    const adminUser = db.prepare("SELECT * FROM users WHERE username = 'admin'").get();
    const sellerUser = db.prepare("SELECT * FROM users WHERE username = 'seller_tech'").get();
    const customerUser = db.prepare("SELECT * FROM users WHERE username = 'customer_regular'").get();

    const adminToken = generateToken(adminUser);
    const sellerToken = generateToken(sellerUser);
    const customerToken = generateToken(customerUser);

    // ============================================================
    // Test 6: HTTP Integration - Unauthenticated requests blocked (401)
    // ============================================================
    {
      testCount++;
      const metricsRes = await fetch(`${baseUrl}/api/admin/metrics`);
      assert.strictEqual(metricsRes.status, 401, 'GET /api/admin/metrics without token must return 401');

      const usersRes = await fetch(`${baseUrl}/api/admin/users`);
      assert.strictEqual(usersRes.status, 401, 'GET /api/admin/users without token must return 401');

      console.log(`✓ Test ${testCount} Passed: Unauthenticated requests to /api/admin/* return 401 Unauthorized`);
    }

    // ============================================================
    // Test 7: HTTP Integration - Seller blocked from /api/admin/metrics with exact RBAC message (403)
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/admin/metrics`, {
        headers: { Authorization: `Bearer ${sellerToken}` }
      });

      assert.strictEqual(res.status, 403, 'Seller must receive 403 Forbidden on /api/admin/metrics');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "Forbidden: Access requires one of roles: [admin]. Current role: 'seller'",
        'Seller must receive exact requireRole error message'
      );

      console.log(`✓ Test ${testCount} Passed: Seller is forbidden (403) from accessing admin metrics`);
    }

    // ============================================================
    // Test 8: HTTP Integration - Customer blocked from /api/admin/metrics (403)
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/admin/metrics`, {
        headers: { Authorization: `Bearer ${customerToken}` }
      });

      assert.strictEqual(res.status, 403, 'Customer must receive 403 Forbidden on /api/admin/metrics');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "Forbidden: Access requires one of roles: [admin]. Current role: 'customer'",
        'Customer must receive exact requireRole error message'
      );

      console.log(`✓ Test ${testCount} Passed: Customer is forbidden (403) from accessing admin metrics`);
    }

    // ============================================================
    // Test 9: HTTP Integration - Seller blocked from /api/admin/users (403 with permission error)
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/admin/users`, {
        headers: { Authorization: `Bearer ${sellerToken}` }
      });

      assert.strictEqual(res.status, 403, 'Seller must receive 403 Forbidden on /api/admin/users');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "Forbidden: Role 'seller' lacks required permission 'users:manage'",
        'Seller must receive exact requirePermission error message'
      );

      console.log(`✓ Test ${testCount} Passed: Seller lacking users:manage is forbidden (403) from /api/admin/users`);
    }

    // ============================================================
    // Test 10: HTTP Integration - Admin access to /api/admin/metrics (200 OK with metrics)
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/admin/metrics`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });

      assert.strictEqual(res.status, 200, 'Admin must receive 200 OK on /api/admin/metrics');
      const body = await res.json();
      assert(typeof body.totalUsers === 'number' && body.totalUsers >= 5, 'Metrics must report total users >= 5');
      assert(typeof body.totalProducts === 'number' && body.totalProducts >= 4, 'Metrics must report total products >= 4');
      assert(typeof body.totalRevenue === 'number', 'Metrics must report total revenue');

      console.log(`✓ Test ${testCount} Passed: Admin accesses /api/admin/metrics successfully (200 OK) with DB metrics`);
    }

    // ============================================================
    // Test 11: HTTP Integration - Admin access to /api/admin/users (200 OK with users list)
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/admin/users`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });

      assert.strictEqual(res.status, 200, 'Admin must receive 200 OK on /api/admin/users');
      const body = await res.json();
      assert(Array.isArray(body.users), 'Response must contain users array');
      assert(body.users.length >= 5, 'Users array must contain seeded users');

      const adminFound = body.users.find((u) => u.username === 'admin');
      assert(adminFound, 'Admin user must be in user list');
      assert.strictEqual(adminFound.role, 'admin', 'Admin user must have admin role');
      assert.strictEqual(adminFound.password_hash, undefined, 'Password hash must NOT be leaked in users list');

      console.log(`✓ Test ${testCount} Passed: Admin accesses /api/admin/users successfully (200 OK) without password leakage`);
    }

  } finally {
    await close();
  }

  console.log('\n========================================');
  console.log(`ALL RBAC TESTS PASSED (${testCount}/${testCount} tests)`);
  console.log('========================================\n');
}

runTests().catch((err) => {
  console.error('RBAC Test Suite Failed:', err);
  process.exit(1);
});
