const assert = require('assert');
const express = require('express');
const { db } = require('../src/db/database');
const { seedDatabase } = require('../src/db/seed');
const { generateToken } = require('../src/middleware/authenticate');
const { canAccessProduct, canViewOrder, canCancelOrder } = require('../src/policies/abac');
const productsRouter = require('../src/routes/products');
const ordersRouter = require('../src/routes/orders');
const authRouter = require('../src/routes/auth');

console.log('--- Running ABAC Policy & Attribute-Based Authorization Tests (Task 4) ---');

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
  // Test 1: Unit Test - canAccessProduct ABAC Policy
  // ============================================================
  {
    testCount++;
    const regularProduct = { id: 1, name: 'Normal Phone', is_vip_exclusive: 0 };
    const vipProduct = { id: 2, name: 'VIP Gold Watch', is_vip_exclusive: 1 };

    const regularUser = { id: 5, username: 'customer_regular', role: 'customer', tier: 'regular' };
    const vipUser = { id: 4, username: 'customer_vip', role: 'customer', tier: 'vip' };

    // Regular products accessible to anyone
    assert.deepStrictEqual(canAccessProduct(regularUser, regularProduct), { allowed: true });
    assert.deepStrictEqual(canAccessProduct(vipUser, regularProduct), { allowed: true });
    assert.deepStrictEqual(canAccessProduct(null, regularProduct), { allowed: true });

    // VIP products accessible to VIP tier
    assert.deepStrictEqual(canAccessProduct(vipUser, vipProduct), { allowed: true });

    // VIP products denied to regular tier with exact reason string
    const regularResult = canAccessProduct(regularUser, vipProduct);
    assert.strictEqual(regularResult.allowed, false);
    assert.strictEqual(
      regularResult.reason,
      "ABAC: Access denied. This product is exclusive to VIP members (Current tier: 'regular')"
    );

    // VIP products denied to unauthenticated user
    const unauthResult = canAccessProduct(null, vipProduct);
    assert.strictEqual(unauthResult.allowed, false);
    assert.strictEqual(
      unauthResult.reason,
      "ABAC: Access denied. This product is exclusive to VIP members (Current tier: 'none')"
    );

    console.log(`✓ Test ${testCount} Passed: canAccessProduct ABAC policy accurately validates tier attributes`);
  }

  // ============================================================
  // Test 2: Unit Test - canViewOrder ABAC Policy
  // ============================================================
  {
    testCount++;
    const testOrder = { id: 10, customer_id: 101, seller_id: 202, amount: 50000, status: 'pending' };

    const customerOwner = { id: 101, role: 'customer' };
    const sellerOwner = { id: 202, role: 'seller' };
    const adminUser = { id: 999, role: 'admin' };
    const unrelatedCustomer = { id: 102, role: 'customer' };
    const unrelatedSeller = { id: 203, role: 'seller' };

    // Admin override
    assert.deepStrictEqual(canViewOrder(adminUser, testOrder), { allowed: true });

    // Customer owner
    assert.deepStrictEqual(canViewOrder(customerOwner, testOrder), { allowed: true });

    // Seller owner
    assert.deepStrictEqual(canViewOrder(sellerOwner, testOrder), { allowed: true });

    // Unrelated customer denied
    const unrelatedCustResult = canViewOrder(unrelatedCustomer, testOrder);
    assert.strictEqual(unrelatedCustResult.allowed, false);
    assert.strictEqual(
      unrelatedCustResult.reason,
      'ABAC: Access denied. You are neither the customer nor the seller of this order.'
    );

    // Unrelated seller denied
    const unrelatedSellResult = canViewOrder(unrelatedSeller, testOrder);
    assert.strictEqual(unrelatedSellResult.allowed, false);
    assert.strictEqual(
      unrelatedSellResult.reason,
      'ABAC: Access denied. You are neither the customer nor the seller of this order.'
    );

    // Null user denied
    const nullUserResult = canViewOrder(null, testOrder);
    assert.strictEqual(nullUserResult.allowed, false);

    console.log(`✓ Test ${testCount} Passed: canViewOrder ABAC policy accurately validates role & ownership attributes`);
  }

  // ============================================================
  // Test 3: Unit Test - canCancelOrder ABAC Policy
  // ============================================================
  {
    testCount++;
    const pendingOrder = { id: 20, customer_id: 101, status: 'pending' };
    const shippedOrder = { id: 21, customer_id: 101, status: 'shipped' };
    const deliveredOrder = { id: 22, customer_id: 101, status: 'delivered' };

    const ownerUser = { id: 101, role: 'customer' };
    const otherUser = { id: 102, role: 'customer' };

    // Owner can cancel pending order
    assert.deepStrictEqual(canCancelOrder(ownerUser, pendingOrder), { allowed: true });

    // Non-owner cannot cancel pending order
    const nonOwnerResult = canCancelOrder(otherUser, pendingOrder);
    assert.strictEqual(nonOwnerResult.allowed, false);
    assert.strictEqual(
      nonOwnerResult.reason,
      'ABAC: Access denied. You can only cancel your own orders.'
    );

    // Owner cannot cancel shipped order
    const shippedResult = canCancelOrder(ownerUser, shippedOrder);
    assert.strictEqual(shippedResult.allowed, false);
    assert.strictEqual(
      shippedResult.reason,
      "ABAC: Access denied. Orders with status 'shipped' cannot be cancelled (Only 'pending' allowed)."
    );

    // Owner cannot cancel delivered order
    const deliveredResult = canCancelOrder(ownerUser, deliveredOrder);
    assert.strictEqual(deliveredResult.allowed, false);
    assert.strictEqual(
      deliveredResult.reason,
      "ABAC: Access denied. Orders with status 'delivered' cannot be cancelled (Only 'pending' allowed)."
    );

    console.log(`✓ Test ${testCount} Passed: canCancelOrder ABAC policy enforces ownership & order lifecycle state`);
  }

  // ============================================================
  // Launch HTTP Test Server for Integration Testing
  // ============================================================
  const { baseUrl, close } = await startTestServer();

  try {
    // Retrieve seeded users for token generation
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

    // Retrieve seeded products
    const regularPhone = db.prepare("SELECT * FROM products WHERE name = 'Flagship Smartphone'").get();
    const vipGoldWatch = db.prepare("SELECT * FROM products WHERE name = 'VIP Exclusive Gold Watch'").get();

    // ============================================================
    // Test 4: HTTP - VIP Deals: customer_regular blocked with 403 Forbidden
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/products/vip-deals`, {
        headers: { Authorization: `Bearer ${regularToken}` }
      });

      assert.strictEqual(res.status, 403, 'Regular customer must be forbidden (403) from VIP deals');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "ABAC: Access denied. This product is exclusive to VIP members (Current tier: 'regular')",
        'Must return exact ABAC VIP denial message'
      );

      console.log(`✓ Test ${testCount} Passed: customer_regular receives 403 Forbidden on /api/products/vip-deals`);
    }

    // ============================================================
    // Test 5: HTTP - VIP Deals: customer_vip gets 200 OK with VIP products
    // ============================================================
    {
      testCount++;
      const res = await fetch(`${baseUrl}/api/products/vip-deals`, {
        headers: { Authorization: `Bearer ${vipToken}` }
      });

      assert.strictEqual(res.status, 200, 'VIP customer must be permitted (200) to access VIP deals');
      const body = await res.json();
      assert(Array.isArray(body.products), 'Response must contain products array');
      assert(body.products.length >= 2, 'Must contain seeded VIP exclusive products');
      for (const prod of body.products) {
        assert.strictEqual(prod.is_vip_exclusive, 1, 'All returned products must be VIP-exclusive');
      }

      console.log(`✓ Test ${testCount} Passed: customer_vip receives 200 OK with VIP exclusive items on /api/products/vip-deals`);
    }

    // ============================================================
    // Test 6: HTTP - Product Detail: ABAC tier check on individual product
    // ============================================================
    {
      testCount++;
      // 6a: Regular customer accessing VIP product -> 403 Forbidden
      const vipDeniedRes = await fetch(`${baseUrl}/api/products/${vipGoldWatch.id}`, {
        headers: { Authorization: `Bearer ${regularToken}` }
      });
      assert.strictEqual(vipDeniedRes.status, 403, 'Regular customer accessing VIP product by ID must get 403');
      const deniedBody = await vipDeniedRes.json();
      assert.strictEqual(
        deniedBody.error,
        "ABAC: Access denied. This product is exclusive to VIP members (Current tier: 'regular')"
      );

      // 6b: VIP customer accessing VIP product -> 200 OK
      const vipAllowedRes = await fetch(`${baseUrl}/api/products/${vipGoldWatch.id}`, {
        headers: { Authorization: `Bearer ${vipToken}` }
      });
      assert.strictEqual(vipAllowedRes.status, 200, 'VIP customer accessing VIP product by ID must get 200');
      const allowedBody = await vipAllowedRes.json();
      assert.strictEqual(allowedBody.product.id, vipGoldWatch.id);

      // 6c: Regular customer accessing regular product -> 200 OK
      const regRes = await fetch(`${baseUrl}/api/products/${regularPhone.id}`, {
        headers: { Authorization: `Bearer ${regularToken}` }
      });
      assert.strictEqual(regRes.status, 200, 'Regular customer accessing regular product by ID must get 200');

      console.log(`✓ Test ${testCount} Passed: Individual product retrieval enforces ABAC tier attributes`);
    }

    // ============================================================
    // Test 7: HTTP - Order Viewing: Customer CANNOT view another customer's order (403)
    // ============================================================
    {
      testCount++;
      // Order 1 belongs to customer_regular
      const order1 = db.prepare('SELECT * FROM orders WHERE id = 1').get();
      assert.strictEqual(order1.customer_id, customerRegular.id);

      // customer_vip attempts to view order 1
      const res = await fetch(`${baseUrl}/api/orders/${order1.id}`, {
        headers: { Authorization: `Bearer ${vipToken}` }
      });

      assert.strictEqual(res.status, 403, 'Customer must receive 403 Forbidden viewing another customer order');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        'ABAC: Access denied. You are neither the customer nor the seller of this order.',
        'Must return exact ABAC order view denial reason'
      );

      console.log(`✓ Test ${testCount} Passed: Customer viewing another customer's order returns 403 Forbidden`);
    }

    // ============================================================
    // Test 8: HTTP - Order Viewing: Customer CAN view their own order (200 OK)
    // ============================================================
    {
      testCount++;
      const order1 = db.prepare('SELECT * FROM orders WHERE id = 1').get();

      // customer_regular views their own order
      const res = await fetch(`${baseUrl}/api/orders/${order1.id}`, {
        headers: { Authorization: `Bearer ${regularToken}` }
      });

      assert.strictEqual(res.status, 200, 'Customer must receive 200 OK viewing their own order');
      const body = await res.json();
      assert.strictEqual(body.order.id, order1.id);
      assert.strictEqual(body.order.customer_id, customerRegular.id);

      // Admin views customer_regular's order (Admin override)
      const adminRes = await fetch(`${baseUrl}/api/orders/${order1.id}`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      assert.strictEqual(adminRes.status, 200, 'Admin can view any order');

      // Seller of order 1 (seller_tech) views order 1
      const sellerRes = await fetch(`${baseUrl}/api/orders/${order1.id}`, {
        headers: { Authorization: `Bearer ${sellerTechToken}` }
      });
      assert.strictEqual(sellerRes.status, 200, 'Order seller can view their store order');

      // Unrelated seller (seller_fashion) blocked from viewing order 1
      const unrelatedSellerRes = await fetch(`${baseUrl}/api/orders/${order1.id}`, {
        headers: { Authorization: `Bearer ${sellerFashionToken}` }
      });
      assert.strictEqual(unrelatedSellerRes.status, 403, 'Unrelated seller is forbidden from viewing order');

      console.log(`✓ Test ${testCount} Passed: Customer views own order (200 OK); Admin & Seller permissions verified`);
    }

    // ============================================================
    // Test 9: HTTP - Order Cancellation: Attempting to cancel another customer's order fails (403)
    // ============================================================
    {
      testCount++;
      // Order 1 is pending, owned by customer_regular
      const order1 = db.prepare('SELECT * FROM orders WHERE id = 1').get();
      assert.strictEqual(order1.status, 'pending');

      // customer_vip attempts to cancel order 1
      const res = await fetch(`${baseUrl}/api/orders/${order1.id}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${vipToken}` }
      });

      assert.strictEqual(res.status, 403, 'Non-owner cancellation must return 403 Forbidden');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        'ABAC: Access denied. You can only cancel your own orders.',
        'Must return exact ownership denial reason'
      );

      // Verify order status in DB remains pending
      const checkOrder = db.prepare('SELECT status FROM orders WHERE id = 1').get();
      assert.strictEqual(checkOrder.status, 'pending');

      console.log(`✓ Test ${testCount} Passed: Attempting to cancel another customer's order fails (403 Forbidden)`);
    }

    // ============================================================
    // Test 10: HTTP - Order Cancellation: Customer cancelling 'pending' order succeeds (200 OK)
    // ============================================================
    {
      testCount++;
      // customer_regular cancels their pending order 1
      const res = await fetch(`${baseUrl}/api/orders/1/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${regularToken}` }
      });

      assert.strictEqual(res.status, 200, 'Owner cancelling pending order must return 200 OK');
      const body = await res.json();
      assert.strictEqual(body.message, 'Order cancelled successfully');
      assert.strictEqual(body.order.status, 'cancelled');

      // Verify DB persistence
      const updatedInDb = db.prepare('SELECT status FROM orders WHERE id = 1').get();
      assert.strictEqual(updatedInDb.status, 'cancelled');

      console.log(`✓ Test ${testCount} Passed: Customer cancels pending order successfully (200 OK, status -> cancelled)`);
    }

    // ============================================================
    // Test 11: HTTP - Order Cancellation: Cancelling 'shipped' order fails with exact reason (403)
    // ============================================================
    {
      testCount++;
      // Order 2 is owned by customer_regular, status is 'shipped'
      const order2 = db.prepare('SELECT * FROM orders WHERE id = 2').get();
      assert.strictEqual(order2.customer_id, customerRegular.id);
      assert.strictEqual(order2.status, 'shipped');

      // customer_regular attempts to cancel order 2
      const res = await fetch(`${baseUrl}/api/orders/${order2.id}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${regularToken}` }
      });

      assert.strictEqual(res.status, 403, 'Cancelling shipped order must return 403 Forbidden');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "ABAC: Access denied. Orders with status 'shipped' cannot be cancelled (Only 'pending' allowed).",
        'Must return exact status lifecycle denial reason'
      );

      // Verify DB status unchanged
      const checkOrder2 = db.prepare('SELECT status FROM orders WHERE id = 2').get();
      assert.strictEqual(checkOrder2.status, 'shipped');

      console.log(`✓ Test ${testCount} Passed: Cancelling shipped order fails with 403 and exact lifecycle message`);
    }

    // ============================================================
    // Test 12: HTTP - Order Cancellation: Cancelling already 'cancelled' order fails (403)
    // ============================================================
    {
      testCount++;
      // Order 1 was cancelled in Test 10
      const res = await fetch(`${baseUrl}/api/orders/1/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${regularToken}` }
      });

      assert.strictEqual(res.status, 403, 'Cancelling already cancelled order must return 403');
      const body = await res.json();
      assert.strictEqual(
        body.error,
        "ABAC: Access denied. Orders with status 'cancelled' cannot be cancelled (Only 'pending' allowed)."
      );

      console.log(`✓ Test ${testCount} Passed: Cancelling non-pending ('cancelled') order fails with 403 Forbidden`);
    }

    // ============================================================
    // Test 13: HTTP - Product & Order Creation Workflows
    // ============================================================
    {
      testCount++;
      // 13a: Seller creates a product
      const newProdRes = await fetch(`${baseUrl}/api/products`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sellerTechToken}`
        },
        body: JSON.stringify({
          name: 'Wireless Noise-Cancelling Headphones',
          price: 2500000,
          category: 'Electronics',
          is_vip_exclusive: 0
        })
      });

      assert.strictEqual(newProdRes.status, 201, 'Seller creating product must return 201');
      const prodBody = await newProdRes.json();
      const createdProd = prodBody.product;
      assert.strictEqual(createdProd.seller_id, sellerTech.id);

      // 13b: Customer creates order for the new product
      const newOrderRes = await fetch(`${baseUrl}/api/orders`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${regularToken}`
        },
        body: JSON.stringify({
          product_id: createdProd.id
        })
      });

      assert.strictEqual(newOrderRes.status, 201, 'Customer ordering product must return 201');
      const orderBody = await newOrderRes.json();
      assert.strictEqual(orderBody.order.customer_id, customerRegular.id);
      assert.strictEqual(orderBody.order.seller_id, sellerTech.id);
      assert.strictEqual(orderBody.order.status, 'pending');

      console.log(`✓ Test ${testCount} Passed: End-to-end product creation and order placement workflows verified`);
    }

    // ============================================================
    // Test 14: HTTP - Role-based Order List Filtering
    // ============================================================
    {
      testCount++;
      // Customer orders listing: only returns customer_regular's orders
      const custOrdersRes = await fetch(`${baseUrl}/api/orders`, {
        headers: { Authorization: `Bearer ${regularToken}` }
      });
      assert.strictEqual(custOrdersRes.status, 200);
      const custOrders = (await custOrdersRes.json()).orders;
      for (const ord of custOrders) {
        assert.strictEqual(ord.customer_id, customerRegular.id);
      }

      // Admin orders listing: returns all orders
      const adminOrdersRes = await fetch(`${baseUrl}/api/orders`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      assert.strictEqual(adminOrdersRes.status, 200);
      const adminOrders = (await adminOrdersRes.json()).orders;
      assert(adminOrders.length >= 4);

      console.log(`✓ Test ${testCount} Passed: GET /api/orders accurately filters by role and subject identity`);
    }

  } finally {
    await close();
  }

  console.log('\n========================================');
  console.log(`ALL ABAC TESTS PASSED (${testCount}/${testCount} tests)`);
  console.log('========================================\n');
}

runTests().catch((err) => {
  console.error('ABAC Test Suite Failed:', err);
  process.exit(1);
});
