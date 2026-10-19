const assert = require('assert');
const bcrypt = require('bcryptjs');
const { db, initSchema } = require('../src/db/database');
const { seedDatabase } = require('../src/db/seed');

console.log('--- Running Database & Schema Verification Tests ---');

// Test 1: Verify Schema Tables
function testSchemaCreation() {
  initSchema();
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);
  
  assert(tables.includes('users'), 'Table "users" must exist');
  assert(tables.includes('products'), 'Table "products" must exist');
  assert(tables.includes('orders'), 'Table "orders" must exist');
  console.log('✓ Test 1 Passed: Tables (users, products, orders) exist in database');
}

// Test 2: Verify Seed Data Execution
function testSeedExecution() {
  const seedResult = seedDatabase();
  assert.strictEqual(seedResult.usersCount, 5, 'Seed should insert 5 users');
  assert.strictEqual(seedResult.productsCount, 4, 'Seed should insert 4 products');
  assert.strictEqual(seedResult.ordersCount, 4, 'Seed should insert 4 orders');
  console.log('✓ Test 2 Passed: Seed execution populated expected record counts');
}

// Test 3: Verify Users Seed Data and Password Hashes
function testUsersData() {
  const users = db.prepare('SELECT * FROM users').all();
  assert.strictEqual(users.length, 5, 'Must have 5 users in database');

  const admin = users.find(u => u.username === 'admin');
  assert(admin, 'Admin user must exist');
  assert.strictEqual(admin.role, 'admin');
  assert.strictEqual(admin.tier, 'regular');
  assert.strictEqual(admin.is_verified, 1);
  assert(bcrypt.compareSync('admin123', admin.password_hash), 'Admin password must match "admin123"');

  const sellerTech = users.find(u => u.username === 'seller_tech');
  assert(sellerTech, 'seller_tech must exist');
  assert.strictEqual(sellerTech.role, 'seller');
  assert.strictEqual(sellerTech.is_verified, 1);
  assert(bcrypt.compareSync('seller123', sellerTech.password_hash), 'seller_tech password must match "seller123"');

  const sellerFashion = users.find(u => u.username === 'seller_fashion');
  assert(sellerFashion, 'seller_fashion must exist');
  assert.strictEqual(sellerFashion.role, 'seller');
  assert.strictEqual(sellerFashion.is_verified, 0); // Not verified for ABAC/testing
  assert(bcrypt.compareSync('seller123', sellerFashion.password_hash), 'seller_fashion password must match "seller123"');

  const customerVip = users.find(u => u.username === 'customer_vip');
  assert(customerVip, 'customer_vip must exist');
  assert.strictEqual(customerVip.role, 'customer');
  assert.strictEqual(customerVip.tier, 'vip');
  assert(bcrypt.compareSync('user123', customerVip.password_hash), 'customer_vip password must match "user123"');

  const customerRegular = users.find(u => u.username === 'customer_regular');
  assert(customerRegular, 'customer_regular must exist');
  assert.strictEqual(customerRegular.role, 'customer');
  assert.strictEqual(customerRegular.tier, 'regular');
  assert(bcrypt.compareSync('user123', customerRegular.password_hash), 'customer_regular password must match "user123"');

  console.log('✓ Test 3 Passed: User accounts, roles, tiers, verification flags, and bcrypt hashes verified');
}

// Test 4: Verify Products Seed Data
function testProductsData() {
  const products = db.prepare('SELECT * FROM products').all();
  assert.strictEqual(products.length, 4, 'Must have 4 products');

  const regularProducts = products.filter(p => p.is_vip_exclusive === 0);
  const vipProducts = products.filter(p => p.is_vip_exclusive === 1);
  assert.strictEqual(regularProducts.length, 2, 'Must have 2 regular products');
  assert.strictEqual(vipProducts.length, 2, 'Must have 2 VIP-exclusive products');

  const goldWatch = products.find(p => p.name === 'VIP Exclusive Gold Watch');
  assert(goldWatch, 'Gold watch must exist');
  assert.strictEqual(goldWatch.is_vip_exclusive, 1);
  assert.strictEqual(goldWatch.price, 25000000);

  console.log('✓ Test 4 Passed: Products seeded with correct categories and VIP flags');
}

// Test 5: Verify Orders Seed Data
function testOrdersData() {
  const orders = db.prepare('SELECT * FROM orders').all();
  assert.strictEqual(orders.length, 4, 'Must have 4 orders');

  const pending = orders.filter(o => o.status === 'pending');
  const shipped = orders.filter(o => o.status === 'shipped');
  const refundReq = orders.filter(o => o.status === 'refund_requested');

  assert.strictEqual(pending.length, 1, 'Must have 1 pending order');
  assert.strictEqual(shipped.length, 1, 'Must have 1 shipped order');
  assert.strictEqual(refundReq.length, 2, 'Must have 2 refund_requested orders');

  // Verify refund amount boundaries (< 500k and > 500k)
  const underLimitRefund = refundReq.find(o => o.amount <= 500000);
  const overLimitRefund = refundReq.find(o => o.amount > 500000);
  assert(underLimitRefund, 'Must have order with refund request <= 500k');
  assert(overLimitRefund, 'Must have order with refund request > 500k');

  console.log('✓ Test 5 Passed: Orders seeded with pending, shipped, and threshold-tested refund states');
}

// Test 6: Verify Foreign Key Constraints Enforcement
function testForeignKeyConstraints() {
  let threwFkError = false;
  try {
    db.prepare(`
      INSERT INTO products (name, price, seller_id, category, is_vip_exclusive)
      VALUES ('Invalid Product', 10000, 999999, 'Test', 0)
    `).run();
  } catch (err) {
    threwFkError = true;
    assert(err.message.includes('FOREIGN KEY') || err.code === 'SQLITE_CONSTRAINT_FOREIGNKEY', 
      `Expected FOREIGN KEY constraint error, got: ${err.message}`);
  }
  assert(threwFkError, 'Inserting product with invalid seller_id must trigger FOREIGN KEY constraint error');

  console.log('✓ Test 6 Passed: Foreign key constraints actively prevent orphaned records');
}

// Test 7: Verify Check Constraints Enforcement
function testCheckConstraints() {
  let threwRoleCheck = false;
  try {
    db.prepare(`
      INSERT INTO users (username, email, password_hash, role)
      VALUES ('hacker', 'hacker@test.com', 'hash', 'superadmin')
    `).run();
  } catch (err) {
    threwRoleCheck = true;
    assert(err.message.includes('CHECK constraint failed') || err.code === 'SQLITE_CONSTRAINT_CHECK',
      `Expected CHECK constraint error, got: ${err.message}`);
  }
  assert(threwRoleCheck, 'Invalid role must fail CHECK constraint');

  let threwTierCheck = false;
  try {
    db.prepare(`
      INSERT INTO users (username, email, password_hash, role, tier)
      VALUES ('user_invalid_tier', 'tier@test.com', 'hash', 'customer', 'diamond')
    `).run();
  } catch (err) {
    threwTierCheck = true;
  }
  assert(threwTierCheck, 'Invalid tier must fail CHECK constraint');

  let threwOrderStatusCheck = false;
  try {
    const customer = db.prepare("SELECT id FROM users WHERE role = 'customer' LIMIT 1").get();
    const seller = db.prepare("SELECT id FROM users WHERE role = 'seller' LIMIT 1").get();
    const product = db.prepare("SELECT id FROM products LIMIT 1").get();

    db.prepare(`
      INSERT INTO orders (customer_id, seller_id, product_id, amount, status)
      VALUES (?, ?, ?, 50000, 'in_transit')
    `).run(customer.id, seller.id, product.id);
  } catch (err) {
    threwOrderStatusCheck = true;
  }
  assert(threwOrderStatusCheck, 'Invalid order status must fail CHECK constraint');

  console.log('✓ Test 7 Passed: CHECK constraints enforce domain integrity on role, tier, and status');
}

function runAll() {
  testSchemaCreation();
  testSeedExecution();
  testUsersData();
  testProductsData();
  testOrdersData();
  testForeignKeyConstraints();
  testCheckConstraints();
  console.log('\n========================================');
  console.log('ALL DATABASE TESTS PASSED (7/7 tests)');
  console.log('========================================\n');
}

runAll();
