const assert = require('assert');
const express = require('express');
const { db } = require('../src/db/database');
const { seedDatabase } = require('../src/db/seed');
const { generateToken } = require('../src/middleware/authenticate');
const { canDeleteProduct, canApproveRefund } = require('../src/policies/combined');
const productsRouter = require('../src/routes/products');
const ordersRouter = require('../src/routes/orders');
const authRouter = require('../src/routes/auth');

console.log('--- Running Combined RBAC + ABAC Authorization Tests (Task 5) ---');

// Helper to start an ephemeral Express test server
async function startTestServer() {
  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.use('/api/products', productsRouter);
  app.use('/api/orders', ordersRouter);

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

async function runTests() {
  // Re-seed DB to a known baseline
  seedDatabase();

  let testCount = 0;

  // ============================================================
  // Test 1: Unit Test - canDeleteProduct Policy Matrix
  // ============================================================
  {
    testCount++;
    const adminUser = { id: 1, role: 'admin' };
    const sellerOwner = { id: 2, role: 'seller' };
    const sellerOther = { id: 3, role: 'seller' };
    const customerUser = { id: 4, role: 'customer' };

    const sampleProduct = { id: 10, seller_id: 2, name: 'Sample Item' };

    // 1a: Admin can delete product regardless of ownership or active orders
    const adminRes = canDeleteProduct(adminUser, sampleProduct, 5);
    assert.strictEqual(adminRes.allowed, true);
    assert.strictEqual(adminRes.reason, 'RBAC: Admin granted global deletion rights');

    // 1b: Customer rejected by role check
    const custRes = canDeleteProduct(customerUser, sampleProduct, 0);
    assert.strictEqual(custRes.allowed, false);
    assert.strictEqual(
      custRes.reason,
      "RBAC: Only 'admin' or 'seller' can delete products. Role 'customer' lacks delete authority."
    );

    // 1c: Seller owning product with active orders rejected
    const activeOrdersRes = canDeleteProduct(sellerOwner, sampleProduct, 3);
    assert.strictEqual(activeOrdersRes.allowed, false);
    assert.strictEqual(
      activeOrdersRes.reason,
      'ABAC: Integrity constraint. Product has 3 active order(s) and cannot be deleted.'
    );

    // 1d: Seller not owning product rejected
    const nonOwnerRes = canDeleteProduct(sellerOther, sampleProduct, 0);
    assert.strictEqual(nonOwnerRes.allowed, false);
    assert.strictEqual(
      nonOwnerRes.reason,
      'ABAC: Ownership mismatch. You (ID: 3) are not the seller of product ID 10 (Seller ID: 2)'
    );

    // 1e: Seller owning product with 0 active orders allowed
    const ownerAllowedRes = canDeleteProduct(sellerOwner, sampleProduct, 0);
    assert.strictEqual(ownerAllowedRes.allowed, true);
    assert.strictEqual(
      ownerAllowedRes.reason,
      'RBAC+ABAC: Seller owns product and no active orders exist'
    );

    console.log(`✓ Test ${testCount} Passed: canDeleteProduct unit policy evaluates RBAC role, ABAC ownership, and active order constraints`);
  }

  // ============================================================
  // Test 2: Unit Test - canApproveRefund Policy Matrix
  // ============================================================
  {
    testCount++;
    const adminUser = { id: 1, role: 'admin' };
    const sellerOwner = { id: 2, role: 'seller' };
    const sellerOther = { id: 3, role: 'seller' };
    const customerUser = { id: 4, role: 'customer' };

    const smallRefundReq = { id: 100, seller_id: 2, amount: 250000, status: 'refund_requested' };
    const largeRefundReq = { id: 101, seller_id: 2, amount: 1500000, status: 'refund_requested' };
    const pendingOrder = { id: 102, seller_id: 2, amount: 250000, status: 'pending' };

    // 2a: Admin can approve refund of any amount
    const adminRes = canApproveRefund(adminUser, largeRefundReq);
    assert.strictEqual(adminRes.allowed, true);
    assert.strictEqual(adminRes.reason, 'RBAC: Admin can approve refunds of any amount');

    // 2b: Customer rejected by role check
    const custRes = canApproveRefund(customerUser, smallRefundReq);
    assert.strictEqual(custRes.allowed, false);
    assert.strictEqual(
      custRes.reason,
      "RBAC: Only 'admin' or 'seller' can approve refunds. Role 'customer' cannot approve refunds."
    );

    // 2c: Seller not owning order store rejected
    const storeMismatchRes = canApproveRefund(sellerOther, smallRefundReq);
    assert.strictEqual(storeMismatchRes.allowed, false);
    assert.strictEqual(
      storeMismatchRes.reason,
      'ABAC: Order store mismatch. Order belongs to store ID 2, not your store ID 3.'
    );

    // 2d: Seller approving amount exceeding 500,000 ceiling rejected
    const amountCeilingRes = canApproveRefund(sellerOwner, largeRefundReq);
    assert.strictEqual(amountCeilingRes.allowed, false);
    assert(amountCeilingRes.reason.includes('ABAC: Amount threshold exceeded'));
    assert(amountCeilingRes.reason.includes('exceeds seller approval ceiling of Rp 500,000. Admin approval required.'));

    // 2e: Order not in refund_requested state rejected
    const invalidStateRes = canApproveRefund(sellerOwner, pendingOrder);
    assert.strictEqual(invalidStateRes.allowed, false);
    assert.strictEqual(
      invalidStateRes.reason,
      "ABAC: Invalid state. Order status is 'pending', must be 'refund_requested' to approve refund."
    );

    // 2f: Seller owning store, amount <= 500,000, status refund_requested allowed
    const validRefundRes = canApproveRefund(sellerOwner, smallRefundReq);
    assert.strictEqual(validRefundRes.allowed, true);
    assert.strictEqual(
      validRefundRes.reason,
      'RBAC+ABAC: Seller owns order and amount is within Rp 500,000 threshold'
    );

    console.log(`✓ Test ${testCount} Passed: canApproveRefund unit policy evaluates RBAC role, store ownership, amount limit, and lifecycle state`);
  }

  // ============================================================
  // Launch HTTP Test Server for Integration Testing
  // ============================================================
  const { baseUrl, close } = await startTestServer();

  try {
    const adminUser = db.prepare("SELECT * FROM users WHERE username = 'admin'").get();
    const sellerTech = db.prepare("SELECT * FROM users WHERE username = 'seller_tech'").get();
    const sellerFashion = db.prepare("SELECT * FROM users WHERE username = 'seller_fashion'").get();
    const customerVip = db.prepare("SELECT * FROM users WHERE username = 'customer_vip'").get();
    const customerRegular = db.prepare("SELECT * FROM users WHERE username = 'customer_regular'").get();

    const adminToken = generateToken(adminUser);
    const sellerTechToken = generateToken(sellerTech);
    const sellerFashionToken = generateToken(sellerFashion);
    const vipToken = generateToken(customerVip);
    const regularToken = generateToken(customerRegular);

    // ============================================================
    // Test 3: HTTP Product Deletion - Customer trying to delete product is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${regularToken}` }
      });

      assert.strictEqual(res.status, 403, 'Customer role must be forbidden (403) from deleting products');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "RBAC: Only 'admin' or 'seller' can delete products. Role 'customer' lacks delete authority."
      );

      // Verify product 1 still exists
      const p = db.prepare('SELECT id FROM products WHERE id = 1').get();
      assert(p, 'Product 1 must not be deleted');

      console.log(`✓ Test ${testCount} Passed: Customer trying to delete product is rejected (403 Forbidden)`);
    }

    // ============================================================
    // Test 4: HTTP Product Deletion - Seller trying to delete another seller's product is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      // Product 1 belongs to seller_tech (id 2). seller_fashion (id 3) tries to delete it.
      const res = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${sellerFashionToken}` }
      });

      assert.strictEqual(res.status, 403, 'Non-owner seller must receive 403 Forbidden');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        `ABAC: Ownership mismatch. You (ID: ${sellerFashion.id}) are not the seller of product ID 1 (Seller ID: ${sellerTech.id})`
      );

      console.log(`✓ Test ${testCount} Passed: Seller trying to delete another seller's product is rejected (403 Forbidden)`);
    }

    // ============================================================
    // Test 5: HTTP Product Deletion - Seller owning product with active orders is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      // Product 1 has active orders (Order 1: pending, Order 2: shipped). seller_tech is the owner.
      const res = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${sellerTechToken}` }
      });

      assert.strictEqual(res.status, 403, 'Owner seller cannot delete product with active orders (403)');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        'ABAC: Integrity constraint. Product has 2 active order(s) and cannot be deleted.'
      );

      console.log(`✓ Test ${testCount} Passed: Seller owning product with active orders is rejected (403 Forbidden)`);
    }

    // ============================================================
    // Test 6: HTTP Product Deletion - Seller owning product with 0 active orders can delete (200 OK)
    // ============================================================
    {
      testCount++;
      // Product 2 ('VIP Exclusive Gold Watch') is owned by seller_tech and has 0 active orders.
      const res = await fetch(`${baseUrl}/api/products/2`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${sellerTechToken}` }
      });

      assert.strictEqual(res.status, 200, 'Owner seller can delete product with 0 active orders');
      const body = await res.json();
      assert.strictEqual(body.message, 'Product deleted successfully');
      assert.strictEqual(body.reason, 'RBAC+ABAC: Seller owns product and no active orders exist');

      // Verify product 2 is removed from DB
      const p2 = db.prepare('SELECT id FROM products WHERE id = 2').get();
      assert.strictEqual(p2, undefined, 'Product 2 must be deleted from DB');

      console.log(`✓ Test ${testCount} Passed: Seller owning product with 0 active orders can delete (200 OK)`);
    }

    // ============================================================
    // Test 7: HTTP Product Deletion - Admin can delete any product regardless of seller or active orders (200 OK)
    // ============================================================
    {
      testCount++;
      // Product 1 is owned by seller_tech and has active orders. Admin deletes it.
      const res = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` }
      });

      assert.strictEqual(res.status, 200, 'Admin must be permitted to delete any product');
      const body = await res.json();
      assert.strictEqual(body.message, 'Product deleted successfully');
      assert.strictEqual(body.reason, 'RBAC: Admin granted global deletion rights');

      // Verify product 1 is removed from DB
      const p1 = db.prepare('SELECT id FROM products WHERE id = 1').get();
      assert.strictEqual(p1, undefined, 'Product 1 must be deleted from DB by Admin');

      console.log(`✓ Test ${testCount} Passed: Admin can delete any product regardless of seller or active orders (200 OK)`);
    }

    // Reset database to ensure clean baseline for refund approval tests
    seedDatabase();

    // ============================================================
    // Test 8: HTTP Refund Approval - Customer trying to approve refund is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      // Order 3 is refund_requested, owned by seller_fashion (id 3). customer_vip attempts approval.
      const res = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${vipToken}` }
      });

      assert.strictEqual(res.status, 403, 'Customer role must be forbidden (403) from approving refunds');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "RBAC: Only 'admin' or 'seller' can approve refunds. Role 'customer' cannot approve refunds."
      );

      // Verify status in DB remains refund_requested
      const o3 = db.prepare('SELECT status FROM orders WHERE id = 3').get();
      assert.strictEqual(o3.status, 'refund_requested');

      console.log(`✓ Test ${testCount} Passed: Customer trying to approve refund is rejected (403 Forbidden)`);
    }

    // ============================================================
    // Test 9: HTTP Refund Approval - Seller trying to approve refund for another store's order is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      // Order 3 belongs to seller_fashion (id 3). seller_tech (id 2) attempts approval.
      const res = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${sellerTechToken}` }
      });

      assert.strictEqual(res.status, 403, 'Seller from different store must be rejected (403)');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        `ABAC: Order store mismatch. Order belongs to store ID ${sellerFashion.id}, not your store ID ${sellerTech.id}.`
      );

      console.log(`✓ Test ${testCount} Passed: Seller trying to approve refund for another store is rejected (403 Forbidden)`);
    }

    // ============================================================
    // Test 10: HTTP Refund Approval - Seller trying to approve refund > 500,000 is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      // Order 4 belongs to seller_tech (seller_id 2), amount is 12,000,000, status is 'refund_requested'
      const res = await fetch(`${baseUrl}/api/orders/4/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${sellerTechToken}` }
      });

      assert.strictEqual(res.status, 403, 'Seller cannot approve refund exceeding Rp 500,000 ceiling');
      const body = await res.json();
      assert(body.error.includes('ABAC: Amount threshold exceeded'));
      assert(body.error.includes('exceeds seller approval ceiling of Rp 500,000. Admin approval required.'));

      // Verify status remains refund_requested
      const o4 = db.prepare('SELECT status FROM orders WHERE id = 4').get();
      assert.strictEqual(o4.status, 'refund_requested');

      console.log(`✓ Test ${testCount} Passed: Seller trying to approve refund > 500,000 is rejected (403 Forbidden with ceiling reason)`);
    }

    // ============================================================
    // Test 11: HTTP Refund Approval - Approving refund on non-refund_requested status is rejected (403 Forbidden)
    // ============================================================
    {
      testCount++;
      // Create a pending order with amount <= 500k for seller_fashion
      const newPendingOrder = db.prepare(`
        INSERT INTO orders (customer_id, seller_id, product_id, amount, status, refund_reason)
        VALUES (?, ?, ?, ?, 'pending', NULL)
      `).run(customerRegular.id, sellerFashion.id, 3, 200000);

      const pendingOrderId = newPendingOrder.lastInsertRowid;

      // seller_fashion attempts to approve refund on 'pending' order
      const res = await fetch(`${baseUrl}/api/orders/${pendingOrderId}/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${sellerFashionToken}` }
      });

      assert.strictEqual(res.status, 403, 'Cannot approve refund on non-refund_requested order');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "ABAC: Invalid state. Order status is 'pending', must be 'refund_requested' to approve refund."
      );

      // Verify status in DB remains pending
      const checkPending = db.prepare('SELECT status FROM orders WHERE id = ?').get(pendingOrderId);
      assert.strictEqual(checkPending.status, 'pending');

      console.log(`✓ Test ${testCount} Passed: Approving refund on non-refund_requested status is rejected (403 Forbidden)`);
    }

    // ============================================================
    // Test 12: HTTP Refund Approval - Seller can approve refund for their own store when amount <= 500,000 (200 OK)
    // ============================================================
    {
      testCount++;
      // Order 3 belongs to seller_fashion (seller_id 3), amount is 350,000, status is 'refund_requested'
      const res = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${sellerFashionToken}` }
      });

      assert.strictEqual(res.status, 200, 'Seller can approve refund for own store <= 500k');
      const body = await res.json();
      assert.strictEqual(body.message, 'Refund approved successfully');
      assert.strictEqual(
        body.reason,
        'RBAC+ABAC: Seller owns order and amount is within Rp 500,000 threshold'
      );

      // Verify DB status updated to refunded
      const updatedOrder3 = db.prepare('SELECT status FROM orders WHERE id = 3').get();
      assert.strictEqual(updatedOrder3.status, 'refunded');

      console.log(`✓ Test ${testCount} Passed: Seller can approve refund for their own store when amount <= 500,000 (200 OK)`);
    }

    // ============================================================
    // Test 13: HTTP Refund Approval - Admin can approve refund of any amount (> 500,000) (200 OK)
    // ============================================================
    {
      testCount++;
      // Order 4 has amount 12,000,000 (> 500,000), status is 'refund_requested'
      const res = await fetch(`${baseUrl}/api/orders/4/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` }
      });

      assert.strictEqual(res.status, 200, 'Admin can approve refund of any amount');
      const body = await res.json();
      assert.strictEqual(body.message, 'Refund approved successfully');
      assert.strictEqual(body.reason, 'RBAC: Admin can approve refunds of any amount');

      // Verify DB status updated to refunded
      const updatedOrder4 = db.prepare('SELECT status FROM orders WHERE id = 4').get();
      assert.strictEqual(updatedOrder4.status, 'refunded');

      console.log(`✓ Test ${testCount} Passed: Admin can approve refund of any amount (> 500,000) (200 OK)`);
    }

    // ============================================================
    // Test 14: HTTP Error Handling - 404 Not Found & 401 Unauthorized
    // ============================================================
    {
      testCount++;
      // 14a: Non-existent product deletion
      const notFoundProd = await fetch(`${baseUrl}/api/products/9999`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      assert.strictEqual(notFoundProd.status, 404);

      // 14b: Non-existent order refund approval
      const notFoundOrder = await fetch(`${baseUrl}/api/orders/9999/approve-refund`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      assert.strictEqual(notFoundOrder.status, 404);

      // 14c: Unauthenticated product deletion
      const unauthProd = await fetch(`${baseUrl}/api/products/1`, {
        method: 'DELETE'
      });
      assert.strictEqual(unauthProd.status, 401);

      // 14d: Unauthenticated order refund approval
      const unauthOrder = await fetch(`${baseUrl}/api/orders/3/approve-refund`, {
        method: 'POST'
      });
      assert.strictEqual(unauthOrder.status, 401);

      console.log(`✓ Test ${testCount} Passed: Route edge cases (404 Not Found, 401 Unauthorized) verified`);
    }

  } finally {
    await close();
  }

  console.log('\n========================================');
  console.log(`ALL COMBINED RBAC+ABAC TESTS PASSED (${testCount}/${testCount} tests)`);
  console.log('========================================\n');
}

runTests().catch((err) => {
  console.error('Combined RBAC+ABAC Test Suite Failed:', err);
  process.exit(1);
});
