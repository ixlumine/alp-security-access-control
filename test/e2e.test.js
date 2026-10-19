const assert = require('assert');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { db } = require('../src/db/database');
const { seedDatabase } = require('../src/db/seed');
const { JWT_SECRET } = require('../src/config/env');

console.log('--- Running End-to-End (E2E) Application Integration Tests (Task 6) ---');

// Helper to launch ephemeral HTTP server using the assembled app
function startAppServer() {
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

async function runE2ETests() {
  // Reset database to initial seed baseline
  seedDatabase();

  const { baseUrl, close } = await startAppServer();
  let testCount = 0;

  try {
    // ============================================================
    // Test 1: Static Web Dashboard & Health Endpoint
    // ============================================================
    {
      testCount++;
      // Health check endpoint
      const healthRes = await fetch(`${baseUrl}/api/health`);
      assert.strictEqual(healthRes.status, 200, 'GET /api/health must return 200 OK');
      const healthData = await healthRes.json();
      assert.strictEqual(healthData.status, 'ok');
      assert.strictEqual(healthData.name, 'E-Commerce Security & Authorization API');

      // Static index.html root
      const indexRes = await fetch(`${baseUrl}/`);
      assert.strictEqual(indexRes.status, 200, 'GET / must serve static index.html with 200 OK');
      const indexHtml = await indexRes.text();
      assert(indexHtml.includes('E-Commerce Authorization & Security'), 'HTML must include project title');
      assert(indexHtml.includes('One-Click Persona Switcher'), 'HTML must include persona switcher');

      // Static style.css
      const cssRes = await fetch(`${baseUrl}/style.css`);
      assert.strictEqual(cssRes.status, 200, 'GET /style.css must return 200 OK');
      const cssText = await cssRes.text();
      assert(cssText.includes('badge-200'), 'CSS must include badge styles');

      // Static app.js
      const jsRes = await fetch(`${baseUrl}/app.js`);
      assert.strictEqual(jsRes.status, 200, 'GET /app.js must return 200 OK');
      const jsText = await jsRes.text();
      assert(jsText.includes('loginAsPersona'), 'app.js must include controller logic');

      console.log(`✓ Test ${testCount} Passed: Server boots cleanly and serves API health & static dashboard assets`);
    }

    // ============================================================
    // Test 2: Persona Authentication & JWT Issue for all 5 Personas + Mock Google
    // ============================================================
    const tokens = {};
    const personas = [
      { key: 'admin', username: 'admin', password: 'admin123', expectedRole: 'admin', expectedTier: 'regular' },
      { key: 'seller_tech', username: 'seller_tech', password: 'seller123', expectedRole: 'seller', expectedTier: 'regular' },
      { key: 'seller_fashion', username: 'seller_fashion', password: 'seller123', expectedRole: 'seller', expectedTier: 'regular' },
      { key: 'customer_vip', username: 'customer_vip', password: 'user123', expectedRole: 'customer', expectedTier: 'vip' },
      { key: 'customer_regular', username: 'customer_regular', password: 'user123', expectedRole: 'customer', expectedTier: 'regular' }
    ];

    {
      testCount++;
      for (const p of personas) {
        const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: p.username, password: p.password })
        });
        assert.strictEqual(loginRes.status, 200, `Login for ${p.username} must succeed with 200`);
        const data = await loginRes.json();
        assert(data.token, `Token must be returned for ${p.username}`);
        assert.strictEqual(data.user.role, p.expectedRole);
        assert.strictEqual(data.user.tier, p.expectedTier);

        // Verify cryptographic validity of JWT
        const decoded = jwt.verify(data.token, JWT_SECRET);
        assert.strictEqual(decoded.username, p.username);
        assert.strictEqual(decoded.role, p.expectedRole);
        assert.strictEqual(decoded.tier, p.expectedTier);

        tokens[p.key] = data.token;
      }

      // Mock Google OAuth Login
      const googleRes = await fetch(`${baseUrl}/api/auth/mock-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'e2e.oauth.user@gmail.com',
          name: 'E2E Google User',
          tier: 'regular'
        })
      });
      assert.strictEqual(googleRes.status, 200);
      const googleData = await googleRes.json();
      assert(googleData.token);
      assert.strictEqual(googleData.user.role, 'customer');
      tokens['mock_google'] = googleData.token;

      console.log(`✓ Test ${testCount} Passed: Successfully authenticated and issued signed JWTs for all 5 personas + Google OAuth`);
    }

    // ============================================================
    // Test 3: JWT Verification via GET /api/auth/me & Tampering Protection
    // ============================================================
    {
      testCount++;
      // Valid token
      const meRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${tokens.customer_vip}` }
      });
      assert.strictEqual(meRes.status, 200);
      const meData = await meRes.json();
      assert.strictEqual(meData.user.username, 'customer_vip');
      assert.strictEqual(meData.user.tier, 'vip');

      // Tampered token signature -> 403 Forbidden
      const parts = tokens.customer_vip.split('.');
      const tamperedToken = `${parts[0]}.${parts[1]}.TAMPERED_INVALID_SIG`;
      const tamperedRes = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${tamperedToken}` }
      });
      assert.strictEqual(tamperedRes.status, 403, 'Tampered token must be rejected with 403 Forbidden');

      // Missing token -> 401 Unauthorized
      const unauthRes = await fetch(`${baseUrl}/api/auth/me`);
      assert.strictEqual(unauthRes.status, 401, 'Missing token must be rejected with 401 Unauthorized');

      console.log(`✓ Test ${testCount} Passed: Protected /api/auth/me validates Bearer JWT and repels tampered tokens`);
    }

    // ============================================================
    // Test 4: RBAC Role Barriers (Admin Metrics, Users Directory, Product Creation)
    // ============================================================
    {
      testCount++;
      // 4a: Admin accesses metrics -> 200 OK
      const adminMetricsRes = await fetch(`${baseUrl}/api/admin/metrics`, {
        headers: { Authorization: `Bearer ${tokens.admin}` }
      });
      assert.strictEqual(adminMetricsRes.status, 200);
      const metrics = await adminMetricsRes.json();
      assert(metrics.totalUsers >= 5);

      // 4b: Seller blocked from metrics -> 403 Forbidden
      const sellerMetricsRes = await fetch(`${baseUrl}/api/admin/metrics`, {
        headers: { Authorization: `Bearer ${tokens.seller_tech}` }
      });
      assert.strictEqual(sellerMetricsRes.status, 403);

      // 4c: Customer blocked from metrics -> 403 Forbidden
      const custMetricsRes = await fetch(`${baseUrl}/api/admin/metrics`, {
        headers: { Authorization: `Bearer ${tokens.customer_vip}` }
      });
      assert.strictEqual(custMetricsRes.status, 403);

      // 4d: Admin accesses user directory -> 200 OK
      const adminUsersRes = await fetch(`${baseUrl}/api/admin/users`, {
        headers: { Authorization: `Bearer ${tokens.admin}` }
      });
      assert.strictEqual(adminUsersRes.status, 200);

      // 4e: Customer blocked from user directory -> 403 Forbidden
      const custUsersRes = await fetch(`${baseUrl}/api/admin/users`, {
        headers: { Authorization: `Bearer ${tokens.customer_regular}` }
      });
      assert.strictEqual(custUsersRes.status, 403);

      // 4f: Seller creates product -> 201 Created
      const sellerProdRes = await fetch(`${baseUrl}/api/products`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokens.seller_tech}`
        },
        body: JSON.stringify({
          name: 'E2E Wireless Mouse',
          price: 350000,
          category: 'Electronics',
          is_vip_exclusive: 0
        })
      });
      assert.strictEqual(sellerProdRes.status, 201);

      // 4g: Customer creates product -> 403 Forbidden
      const custProdRes = await fetch(`${baseUrl}/api/products`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${tokens.customer_regular}`
        },
        body: JSON.stringify({
          name: 'Illicit Product',
          price: 100000,
          category: 'Electronics'
        })
      });
      assert.strictEqual(custProdRes.status, 403);

      console.log(`✓ Test ${testCount} Passed: RBAC role boundaries strictly enforced across admin, seller, and customer roles`);
    }

    // ============================================================
    // Test 5: ABAC Attribute Gates (VIP Deals, Order Ownership, Order Lifecycle)
    // ============================================================
    {
      testCount++;
      // 5a: VIP deals: customer_regular blocked (403 Forbidden)
      const regVipRes = await fetch(`${baseUrl}/api/products/vip-deals`, {
        headers: { Authorization: `Bearer ${tokens.customer_regular}` }
      });
      assert.strictEqual(regVipRes.status, 403);
      const regVipData = await regVipRes.json();
      assert(regVipData.error.includes('exclusive to VIP members'));

      // 5b: VIP deals: customer_vip allowed (200 OK)
      const vipDealsRes = await fetch(`${baseUrl}/api/products/vip-deals`, {
        headers: { Authorization: `Bearer ${tokens.customer_vip}` }
      });
      assert.strictEqual(vipDealsRes.status, 200);
      const deals = await vipDealsRes.json();
      assert(deals.products.length >= 2);

      // 5c: Order ownership: customer_vip cannot view customer_regular's order (Order #1)
      const otherOrderRes = await fetch(`${baseUrl}/api/orders/1`, {
        headers: { Authorization: `Bearer ${tokens.customer_vip}` }
      });
      assert.strictEqual(otherOrderRes.status, 403);

      // 5d: Order ownership: customer_regular can view their own order (Order #1)
      const ownOrderRes = await fetch(`${baseUrl}/api/orders/1`, {
        headers: { Authorization: `Bearer ${tokens.customer_regular}` }
      });
      assert.strictEqual(ownOrderRes.status, 200);

      // 5e: Order cancellation lifecycle: cannot cancel 'shipped' order (Order #2)
      const cancelShippedRes = await fetch(`${baseUrl}/api/orders/2/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.customer_regular}` }
      });
      assert.strictEqual(cancelShippedRes.status, 403);
      const cancelShippedData = await cancelShippedRes.json();
      assert(cancelShippedData.error.includes("cannot be cancelled (Only 'pending' allowed)"));

      // 5f: Order cancellation: customer_regular cancels 'pending' order (Order #1)
      const cancelPendingRes = await fetch(`${baseUrl}/api/orders/1/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.customer_regular}` }
      });
      assert.strictEqual(cancelPendingRes.status, 200);
      const cancelPendingData = await cancelPendingRes.json();
      assert.strictEqual(cancelPendingData.order.status, 'cancelled');

      console.log(`✓ Test ${testCount} Passed: ABAC gates correctly evaluate user tier, resource ownership, and order status`);
    }

    // ============================================================
    // Test 6: Combined RBAC + ABAC Compound Authorization Workflows
    // ============================================================
    {
      testCount++;
      // Re-seed DB to have clean products and orders
      seedDatabase();

      // 6a: Product Deletion - Customer attempting delete -> 403 Forbidden
      const custDelRes = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokens.customer_regular}` }
      });
      assert.strictEqual(custDelRes.status, 403);

      // 6b: Product Deletion - Other seller attempting delete -> 403 Forbidden
      const otherSellerDelRes = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokens.seller_fashion}` }
      });
      assert.strictEqual(otherSellerDelRes.status, 403);

      // 6c: Product Deletion - Owner seller with active orders attempting delete -> 403 Forbidden
      const activeOrderDelRes = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokens.seller_tech}` }
      });
      assert.strictEqual(activeOrderDelRes.status, 403);
      const activeOrderData = await activeOrderDelRes.json();
      assert(activeOrderData.error.includes('Product has 2 active order(s)'));

      // 6d: Product Deletion - Owner seller with 0 orders deletes successfully -> 200 OK
      const zeroOrderDelRes = await fetch(`${baseUrl}/api/products/2`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokens.seller_tech}` }
      });
      assert.strictEqual(zeroOrderDelRes.status, 200);

      // 6e: Product Deletion - Admin deletes any product regardless of orders -> 200 OK
      const adminDelRes = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${tokens.admin}` }
      });
      assert.strictEqual(adminDelRes.status, 200);

      // Re-seed DB for refund testing
      seedDatabase();

      // 6f: Refund Approval - Customer cannot approve refunds -> 403 Forbidden
      const custRefundRes = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.customer_vip}` }
      });
      assert.strictEqual(custRefundRes.status, 403);

      // 6g: Refund Approval - Seller from other store cannot approve -> 403 Forbidden
      const otherStoreRefundRes = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.seller_tech}` }
      });
      assert.strictEqual(otherStoreRefundRes.status, 403);

      // 6h: Refund Approval - Seller approving > 500k ceiling rejected -> 403 Forbidden
      const overCeilingRes = await fetch(`${baseUrl}/api/orders/4/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.seller_tech}` }
      });
      assert.strictEqual(overCeilingRes.status, 403);
      const overCeilingData = await overCeilingRes.json();
      assert(overCeilingData.error.includes('exceeds seller approval ceiling of Rp 500,000'));

      // 6i: Refund Approval - Seller approving <= 500k for own store -> 200 OK
      const underCeilingRes = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.seller_fashion}` }
      });
      assert.strictEqual(underCeilingRes.status, 200);

      // 6j: Refund Approval - Admin approving > 500k -> 200 OK
      const adminRefundRes = await fetch(`${baseUrl}/api/orders/4/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokens.admin}` }
      });
      assert.strictEqual(adminRefundRes.status, 200);

      console.log(`✓ Test ${testCount} Passed: Combined RBAC+ABAC compound decisions (product deletion & refund approval) verified end-to-end`);
    }

    // ============================================================
    // Test 7: Reseed Endpoint Verification
    // ============================================================
    {
      testCount++;
      const reseedRes = await fetch(`${baseUrl}/api/seed`, { method: 'POST' });
      assert.strictEqual(reseedRes.status, 200, 'POST /api/seed must succeed');
      const reseedData = await reseedRes.json();
      assert.strictEqual(reseedData.usersCount, 5);
      assert.strictEqual(reseedData.productsCount, 4);
      assert.strictEqual(reseedData.ordersCount, 4);

      console.log(`✓ Test ${testCount} Passed: Database reseed endpoint resets data back to known baseline`);
    }

    console.log('\n========================================');
    console.log(`ALL E2E INTEGRATION TESTS PASSED (${testCount}/${testCount} tests)`);
    console.log('========================================\n');
  } finally {
    await close();
  }
}

runE2ETests().catch((err) => {
  console.error('\n❌ E2E Test execution failed:', err);
  process.exit(1);
});
